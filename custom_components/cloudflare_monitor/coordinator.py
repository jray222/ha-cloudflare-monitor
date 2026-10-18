"""Polls Cloudflare, spots new IPs and raises alerts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import ipaddress
import logging
from typing import Any

from homeassistant.components import persistent_notification
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .api import CloudflareAuthError, CloudflareClient, CloudflareError
from .const import (
    BLOCK_NOTE_PREFIX,
    CONF_ACCOUNT_ID,
    CONF_IPINFO_TOKEN,
    CONF_NEW_IP_SCOPE,
    CONF_NOTIFY,
    CONF_SCAN_INTERVAL,
    CONF_TRUSTED_IPS,
    CONF_WATCHED_SITES,
    CONF_WATCH_ACCESS,
    CONF_WATCH_CONNECTORS,
    CONF_WATCH_TUNNELS,
    DEFAULT_NEW_IP_SCOPE,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    EVENT_NEW_IP,
    LOCK_POLICY_NAME,
    RECENT_ALERTS_KEPT,
    SCOPE_SOURCE,
    SITE_VISITORS_SHOWN,
    SOURCE_ACCESS,
    SOURCE_CONNECTOR,
    SOURCE_LABELS,
    SOURCE_TUNNEL,
)
from .geo import is_public_ip, lookup_ip

_LOGGER = logging.getLogger(__name__)

STORAGE_VERSION = 1
SLOW_REFRESH = timedelta(hours=1)  # hostnames, zones and lock state
GRAPHQL_OVERLAP = timedelta(minutes=5)
FIRST_ACCESS_LOOKBACK = timedelta(days=7)
FIRST_GRAPHQL_LOOKBACK = timedelta(hours=24)
GEO_CACHE_SIZE = 2000


@dataclass
class Sighting:
    """One IP seen in one place during this poll."""

    ip: str
    source_type: str
    source_id: str
    name: str
    hostname: str = ""
    when: str = ""
    user_email: str = ""
    login_allowed: bool | None = None
    idp: str = ""
    country: str = ""
    asn: str = ""
    requests: int = 0
    http_statuses: set[int] = field(default_factory=set)
    user_agents: set[str] = field(default_factory=set)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class MonitorData:
    """What the entities read after each poll."""

    tunnels: dict[str, dict[str, Any]] = field(default_factory=dict)
    apps: dict[str, dict[str, Any]] = field(default_factory=dict)
    sites: dict[str, dict[str, Any]] = field(default_factory=dict)
    blocked_ips: list[dict[str, Any]] = field(default_factory=list)
    recent_alerts: list[dict[str, Any]] = field(default_factory=list)
    new_ips_24h: int = 0
    failed_logins_24h: int = 0
    known_ip_count: int = 0
    problems: list[str] = field(default_factory=list)


class CloudflareMonitorCoordinator(DataUpdateCoordinator[MonitorData]):
    """Single poller for one Cloudflare account."""

    config_entry: ConfigEntry

    def __init__(
        self, hass: HomeAssistant, entry: ConfigEntry, client: CloudflareClient
    ) -> None:
        minutes = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=timedelta(minutes=minutes),
        )
        self.client = client
        self.account_id: str = entry.data[CONF_ACCOUNT_ID]
        self._store: Store[dict[str, Any]] = Store(
            hass, STORAGE_VERSION, f"{DOMAIN}.{entry.entry_id}"
        )
        self.state: dict[str, Any] = {}
        self._last_slow_refresh: datetime | None = None
        self._hostnames: dict[str, dict[str, str]] = {}  # host -> tunnel_id, zone_id
        self._zones: list[dict[str, Any]] = []
        self._locked_apps: set[str] = set()
        self._tunnel_remote: dict[str, bool] = {}

    # ----------------------------------------------------------------- options

    def _opt(self, key: str, default: Any) -> Any:
        return self.config_entry.options.get(key, default)

    def _trusted(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        nets = []
        raw = self._opt(CONF_TRUSTED_IPS, "") or ""
        for part in raw.replace("\n", ",").split(","):
            part = part.strip()
            if not part:
                continue
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                _LOGGER.warning("Ignoring trusted IP entry that is not an IP: %s", part)
        return nets

    def _watched_sites(self) -> list[str]:
        raw = self._opt(CONF_WATCHED_SITES, "") or ""
        sites = []
        for part in raw.replace("\n", ",").split(","):
            host = part.strip().lower().removeprefix("https://").removeprefix("http://")
            host = host.split("/")[0]
            if host and host not in sites:
                sites.append(host)
        return sites

    # ------------------------------------------------------------------- store

    async def async_load(self) -> None:
        self.state = await self._store.async_load() or {}
        self.state.setdefault("known", {})
        self.state.setdefault("geo", {})
        self.state.setdefault("recent_alerts", [])
        self.state.setdefault("alert_times", [])
        self.state.setdefault("failed_login_times", [])
        self.state.setdefault("tunnel_backups", {})
        self.state.setdefault("app_last_login", {})
        self.state.setdefault("baseline_done", False)
        self.state.setdefault("site_visitors", {})
        self.state.setdefault("site_alert_times", {})

    def _save(self) -> None:
        self._store.async_delay_save(lambda: self.state, 5)

    # -------------------------------------------------------------------- poll

    async def _async_update_data(self) -> MonitorData:
        now = dt_util.utcnow()
        data = MonitorData()
        sightings: list[Sighting] = []

        try:
            await self._poll_tunnels(data, sightings)
            if now - (self._last_slow_refresh or datetime.min.replace(tzinfo=now.tzinfo)) > SLOW_REFRESH:
                await self._slow_refresh(data)
                self._last_slow_refresh = now
            await self._poll_apps(data)
            if self._opt(CONF_WATCH_ACCESS, True):
                await self._poll_access_logins(now, data, sightings)
            if self._opt(CONF_WATCH_TUNNELS, True):
                await self._poll_tunnel_visitors(now, data, sightings)
            await self._poll_blocked(data)
        except CloudflareAuthError as err:
            # Only fatal if nothing at all works; partial permissions are fine
            if not data.tunnels and not data.apps:
                raise ConfigEntryAuthFailed(str(err)) from err
            data.problems.append(str(err))
        except CloudflareError as err:
            raise UpdateFailed(str(err)) from err

        await self._handle_sightings(sightings, data)

        cutoff = (now - timedelta(hours=24)).isoformat()
        self.state["alert_times"] = [t for t in self.state["alert_times"] if t >= cutoff]
        self.state["failed_login_times"] = [
            t for t in self.state["failed_login_times"] if t >= cutoff
        ]
        data.new_ips_24h = len(self.state["alert_times"])
        data.failed_logins_24h = len(self.state["failed_login_times"])
        data.recent_alerts = list(self.state["recent_alerts"])
        data.known_ip_count = len({k.split("|")[-1] for k in self.state["known"]})
        self._build_sites(data, cutoff)
        for problem in data.problems:
            _LOGGER.warning("Cloudflare Monitor: %s", problem)
        self._save()
        return data

    async def _poll_tunnels(self, data: MonitorData, sightings: list[Sighting]) -> None:
        try:
            tunnels = await self.client.list_tunnels()
        except CloudflareAuthError as err:
            data.problems.append(f"Tunnels not readable (needs 'Cloudflare Tunnel: Read'): {err}")
            return
        if not tunnels:
            # Cloudflare can answer an empty list rather than an error when the token
            # lacks the permission, so say so instead of going quiet
            data.problems.append(
                "Cloudflare returned no tunnels. If you have tunnels, the token "
                "probably lacks 'Cloudflare Tunnel: Read'"
            )
        for tunnel in tunnels:
            tid = tunnel["id"]
            remote = tunnel.get("remote_config")
            if remote is None:
                remote = tunnel.get("config_src") == "cloudflare"
            self._tunnel_remote[tid] = bool(remote)
            connections = tunnel.get("connections") or []
            data.tunnels[tid] = {
                "id": tid,
                "name": tunnel.get("name") or tid,
                "status": tunnel.get("status") or "unknown",
                "remote_config": bool(remote),
                "connections": connections,
                "connector_ips": sorted(
                    {c.get("origin_ip") for c in connections if c.get("origin_ip")}
                ),
                "hostnames": sorted(
                    h for h, v in self._hostnames.items() if v.get("tunnel_id") == tid
                ),
                "disabled_by_ha": tid in self.state["tunnel_backups"],
            }
            if self._opt(CONF_WATCH_CONNECTORS, True):
                for conn in connections:
                    ip = conn.get("origin_ip")
                    if not ip:
                        continue
                    sightings.append(
                        Sighting(
                            ip=ip,
                            source_type=SOURCE_CONNECTOR,
                            source_id=tid,
                            name=data.tunnels[tid]["name"],
                            when=conn.get("opened_at") or "",
                            extra={
                                "colo": conn.get("colo_name"),
                                "cloudflared_version": conn.get("client_version"),
                            },
                        )
                    )

    async def _slow_refresh(self, data: MonitorData) -> None:
        """Hourly: which hostnames point at which tunnel, and which apps are locked."""
        hostnames: dict[str, dict[str, str]] = {}
        for tid, remote in self._tunnel_remote.items():
            if not remote:
                continue
            try:
                config = await self.client.get_tunnel_config(tid) or {}
            except CloudflareError as err:
                data.problems.append(f"Could not read config of tunnel {tid}: {err}")
                continue
            if tid in self.state["tunnel_backups"]:
                config = self.state["tunnel_backups"][tid]
            for rule in config.get("ingress") or []:
                if rule.get("hostname"):
                    hostnames[rule["hostname"]] = {"tunnel_id": tid}
        try:
            self._zones = await self.client.list_zones()
            for zone in self._zones:
                for record in await self.client.list_tunnel_cnames(zone["id"]):
                    tid = record["content"].split(".")[0]
                    hostnames.setdefault(record["name"], {"tunnel_id": tid})
        except CloudflareAuthError as err:
            data.problems.append(
                f"Zones/DNS not readable (needs 'Zone: Read' and 'DNS: Read'): {err}"
            )
        for host, info in hostnames.items():
            zone = self._zone_for(host)
            if zone:
                info["zone_id"] = zone
        self._hostnames = hostnames
        for tunnel in data.tunnels.values():
            tunnel["hostnames"] = sorted(
                h for h, v in hostnames.items() if v["tunnel_id"] == tunnel["id"]
            )

        locked: set[str] = set()
        try:
            for app in await self.client.list_access_apps():
                policies = await self.client.list_app_policies(app["id"])
                if any(p.get("name") == LOCK_POLICY_NAME for p in policies):
                    locked.add(app["id"])
            self._locked_apps = locked
        except CloudflareAuthError:
            pass  # reported by _poll_apps

    def _zone_for(self, host: str) -> str | None:
        best = None
        for zone in self._zones:
            name = zone.get("name", "")
            if (host == name or host.endswith("." + name)) and (
                best is None or len(name) > len(best[1])
            ):
                best = (zone["id"], name)
        return best[0] if best else None

    async def _poll_apps(self, data: MonitorData) -> None:
        try:
            apps = await self.client.list_access_apps()
        except CloudflareAuthError as err:
            data.problems.append(
                f"Access apps not readable (needs 'Access: Apps and Policies: Read'): {err}"
            )
            return
        if not apps:
            data.problems.append(
                "Cloudflare returned no Access apps. If you have apps, the token "
                "probably lacks 'Access: Apps and Policies: Read'"
            )
        for app in apps:
            if app.get("type") in ("warp", "app_launcher", "biso"):
                continue
            aid = app["id"]
            data.apps[aid] = {
                "id": aid,
                "name": app.get("name") or app.get("domain") or aid,
                "domain": app.get("domain") or "",
                "type": app.get("type") or "",
                "locked": aid in self._locked_apps,
                "last_login": self.state["app_last_login"].get(aid),
            }

    async def _poll_access_logins(
        self, now: datetime, data: MonitorData, sightings: list[Sighting]
    ) -> None:
        since_raw = self.state.get("access_since")
        since = dt_util.parse_datetime(since_raw) if since_raw else None
        since = since or now - FIRST_ACCESS_LOOKBACK
        try:
            entries = await self.client.access_logins_since(since)
        except CloudflareAuthError as err:
            data.problems.append(
                f"Access logs not readable (needs 'Access: Audit Logs: Read'): {err}"
            )
            return
        by_domain = {a["domain"]: a for a in data.apps.values() if a["domain"]}
        newest = since_raw
        for entry in entries:
            created = entry.get("created_at") or ""
            if since_raw and created <= since_raw:
                continue  # already handled in an earlier poll
            if not newest or created > newest:
                newest = created
            ip = entry.get("ip_address")
            if not ip:
                continue
            app = data.apps.get(entry.get("app_uid") or "") or by_domain.get(
                entry.get("app_domain") or ""
            )
            aid = app["id"] if app else (entry.get("app_uid") or "unknown")
            allowed = entry.get("allowed")
            login = {
                "ip": ip,
                "user_email": entry.get("user_email") or "",
                "allowed": allowed,
                "time": created,
                "country": entry.get("country") or "",
            }
            self.state["app_last_login"][aid] = login
            if aid in data.apps:
                data.apps[aid]["last_login"] = login
            if allowed is False:
                self.state["failed_login_times"].append(
                    dt_util.parse_datetime(created).isoformat()
                    if dt_util.parse_datetime(created)
                    else now.isoformat()
                )
            sightings.append(
                Sighting(
                    ip=ip,
                    source_type=SOURCE_ACCESS,
                    source_id=aid,
                    name=app["name"] if app else (entry.get("app_domain") or aid),
                    hostname=entry.get("app_domain") or "",
                    when=created,
                    user_email=entry.get("user_email") or "",
                    login_allowed=allowed,
                    idp=entry.get("connection") or "",
                    country=entry.get("country") or "",
                    requests=1,
                )
            )
        if newest:
            self.state["access_since"] = newest

    async def _poll_tunnel_visitors(
        self, now: datetime, data: MonitorData, sightings: list[Sighting]
    ) -> None:
        by_zone: dict[str, list[str]] = {}
        for host, info in self._hostnames.items():
            if info.get("zone_id") and not host.startswith("*"):
                by_zone.setdefault(info["zone_id"], []).append(host)
        for host in self._watched_sites():
            # A watched site may not be on a tunnel (or the config was unreadable)
            zone = self._zone_for(host)
            if zone and host not in by_zone.get(zone, []):
                by_zone.setdefault(zone, []).append(host)
        if not by_zone:
            return
        since_raw = self.state.get("graphql_since")
        start = dt_util.parse_datetime(since_raw) if since_raw else None
        start = (start - GRAPHQL_OVERLAP) if start else now - FIRST_GRAPHQL_LOOKBACK
        start = max(start, now - FIRST_GRAPHQL_LOOKBACK)
        for zone_id, hosts in by_zone.items():
            try:
                rows = await self.client.visitors_by_ip(zone_id, hosts, start, now)
            except CloudflareError as err:
                if since_raw is None:
                    # Some plans only allow short windows; retry with one hour
                    try:
                        rows = await self.client.visitors_by_ip(
                            zone_id, hosts, now - timedelta(hours=1), now
                        )
                    except CloudflareError as err2:
                        data.problems.append(
                            f"Tunnel visitor analytics not available (needs 'Analytics: Read'): {err2}"
                        )
                        continue
                else:
                    data.problems.append(f"Tunnel visitor analytics failed: {err}")
                    continue
            merged: dict[tuple[str, str], Sighting] = {}
            for row in rows:
                dims = row.get("dimensions") or {}
                ip = dims.get("clientIP")
                host = dims.get("clientRequestHTTPHost") or ""
                if not ip:
                    continue
                tid = self._hostnames.get(host, {}).get("tunnel_id", "")
                sighting = merged.get((ip, host))
                if sighting is None:
                    sighting = merged[(ip, host)] = Sighting(
                        ip=ip,
                        source_type=SOURCE_TUNNEL,
                        source_id=host,
                        name=data.tunnels.get(tid, {}).get("name", host),
                        hostname=host,
                        when=now.isoformat(),
                        country=dims.get("clientCountryName") or "",
                        asn=(
                            f"AS{dims['clientAsn']} {dims.get('clientASNDescription') or ''}".strip()
                            if dims.get("clientAsn")
                            else ""
                        ),
                        extra={"tunnel_id": tid},
                    )
                sighting.requests += int(row.get("count") or 0)
                if dims.get("edgeResponseStatus"):
                    sighting.http_statuses.add(int(dims["edgeResponseStatus"]))
                if dims.get("userAgent") and len(sighting.user_agents) < 3:
                    sighting.user_agents.add(dims["userAgent"][:200])
            sightings.extend(merged.values())
        self.state["graphql_since"] = now.isoformat()

    async def _poll_blocked(self, data: MonitorData) -> None:
        try:
            rules = await self.client.list_blocked_ips()
        except CloudflareAuthError as err:
            data.problems.append(
                f"IP Access rules not readable (needs 'Account Firewall Access Rules'): {err}"
            )
            return
        data.blocked_ips = [
            {
                "ip": (r.get("configuration") or {}).get("value"),
                "note": r.get("notes") or "",
                "since": r.get("created_on") or "",
            }
            for r in rules
        ]

    # ------------------------------------------------------------- new IPs

    async def _handle_sightings(self, sightings: list[Sighting], data: MonitorData) -> None:
        known: dict[str, Any] = self.state["known"]
        per_source = self._opt(CONF_NEW_IP_SCOPE, DEFAULT_NEW_IP_SCOPE) == SCOPE_SOURCE
        trusted = self._trusted()
        baseline = not self.state["baseline_done"]
        blocked = {b["ip"] for b in data.blocked_ips}
        now_iso = dt_util.utcnow().isoformat()
        watched = set(self._watched_sites())

        for s in sightings:
            try:
                ipaddress.ip_address(s.ip)
            except ValueError:
                continue  # never put something that is not an IP into links or rules
            site = s.hostname.lower()
            if s.source_type == SOURCE_TUNNEL and site in watched and not self._is_trusted(s.ip, trusted):
                visitors = self.state["site_visitors"].setdefault(site, {})
                seen = visitors.get(s.ip) or {"requests": 0}
                visitors[s.ip] = {
                    "last_seen": now_iso,
                    "country": s.country or seen.get("country", ""),
                    "requests": seen["requests"] + s.requests,
                    "user_agent": next(iter(sorted(s.user_agents)), seen.get("user_agent", "")),
                }
            key = f"{s.source_type}:{s.source_id}|{s.ip}" if per_source else s.ip
            # Connector IPs are always tracked per tunnel: a new one is notable
            if s.source_type == SOURCE_CONNECTOR:
                key = f"{SOURCE_CONNECTOR}:{s.source_id}|{s.ip}"
            entry = known.get(key)
            if entry is not None:
                entry["last_seen"] = now_iso
                continue
            known[key] = {"first_seen": now_iso, "last_seen": now_iso, "where": s.name}
            if baseline or self._is_trusted(s.ip, trusted):
                continue
            if s.source_type == SOURCE_TUNNEL and site in watched:
                self.state["site_alert_times"].setdefault(site, []).append(now_iso)
            await self._alert(s, s.ip in blocked)

        if baseline:
            self.state["baseline_done"] = True
            _LOGGER.info(
                "Cloudflare Monitor learned %s existing IPs; alerts start from the next poll",
                len(known),
            )

    def _build_sites(self, data: MonitorData, cutoff: str) -> None:
        """Visitors of each watched site over the last 24 hours."""
        watched = self._watched_sites()
        for site in list(self.state["site_visitors"]):
            if site not in watched:
                self.state["site_visitors"].pop(site)
                self.state["site_alert_times"].pop(site, None)
        for site in watched:
            visitors = {
                ip: v
                for ip, v in self.state["site_visitors"].get(site, {}).items()
                if v["last_seen"] >= cutoff
            }
            self.state["site_visitors"][site] = visitors
            alerts = [t for t in self.state["site_alert_times"].get(site, []) if t >= cutoff]
            self.state["site_alert_times"][site] = alerts
            ordered = sorted(visitors.items(), key=lambda kv: kv[1]["last_seen"], reverse=True)
            tunnel = self._hostnames.get(site, {}).get("tunnel_id", "")
            data.sites[site] = {
                "id": site,
                "name": site,
                "tunnel": data.tunnels.get(tunnel, {}).get("name", ""),
                "visitors": [{"ip": ip, **v} for ip, v in ordered[:SITE_VISITORS_SHOWN]],
                "visitor_count": len(visitors),
                "new_ips_24h": len(alerts),
            }

    @staticmethod
    def _is_trusted(ip: str, trusted: list) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in trusted)

    async def _alert(self, s: Sighting, already_blocked: bool) -> None:
        geo = self.state["geo"].get(s.ip)
        if geo is None:
            geo = await lookup_ip(
                async_get_clientsession(self.hass), s.ip, self._opt(CONF_IPINFO_TOKEN, "") or None
            )
            self.state["geo"][s.ip] = geo
            if len(self.state["geo"]) > GEO_CACHE_SIZE:
                for old in list(self.state["geo"])[: len(self.state["geo"]) - GEO_CACHE_SIZE]:
                    self.state["geo"].pop(old, None)

        event = {
            "ip": s.ip,
            "source": SOURCE_LABELS[s.source_type],
            "source_type": s.source_type,
            "name": s.name,
            "hostname": s.hostname,
            "user_email": s.user_email,
            "login_allowed": s.login_allowed,
            "identity_provider": s.idp,
            "city": geo.get("city", ""),
            "region": geo.get("region", ""),
            "country": s.country or geo.get("country", ""),
            "isp": geo.get("org") or s.asn,
            "reverse_dns": geo.get("hostname", ""),
            "map_location": geo.get("loc", ""),
            "timezone": geo.get("timezone", ""),
            "requests": s.requests,
            "http_statuses": sorted(s.http_statuses),
            "user_agents": sorted(s.user_agents),
            "seen_at": s.when or dt_util.utcnow().isoformat(),
            "already_blocked": already_blocked,
            "is_public_ip": is_public_ip(s.ip),
            "abuseipdb_url": f"https://www.abuseipdb.com/check/{s.ip}",
            "ipinfo_url": f"https://ipinfo.io/{s.ip}",
            "app_id": s.source_id if s.source_type == SOURCE_ACCESS else "",
            "tunnel_id": (
                s.source_id if s.source_type == SOURCE_CONNECTOR else s.extra.get("tunnel_id", "")
            ),
            **{k: v for k, v in s.extra.items() if k != "tunnel_id" and v},
        }
        self.hass.bus.async_fire(EVENT_NEW_IP, event)

        self.state["alert_times"].append(dt_util.utcnow().isoformat())
        self.state["recent_alerts"].insert(0, event)
        del self.state["recent_alerts"][RECENT_ALERTS_KEPT:]

        if self._opt(CONF_NOTIFY, True):
            persistent_notification.async_create(
                self.hass,
                _notification_text(event),
                title=f"New IP on Cloudflare: {s.ip}",
                notification_id=f"{DOMAIN}_{s.ip}",
            )

    # ------------------------------------------------------------- actions

    async def async_block_ip(self, ip: str, note: str | None) -> None:
        text = f"{BLOCK_NOTE_PREFIX} {dt_util.now().strftime('%Y-%m-%d %H:%M')}"
        if note:
            text += f": {note}"
        await self.client.block_ip(ip, text)
        await self.async_request_refresh()

    async def async_unblock_ip(self, ip: str) -> int:
        removed = await self.client.unblock_ip(ip)
        await self.async_request_refresh()
        return removed

    async def async_lock_app(self, app_id: str) -> None:
        await self.client.lock_app(app_id)
        self._locked_apps.add(app_id)
        self._set_now(self.data.apps, app_id, "locked", True)

    async def async_unlock_app(self, app_id: str) -> None:
        await self.client.unlock_app(app_id)
        self._locked_apps.discard(app_id)
        self._set_now(self.data.apps, app_id, "locked", False)

    async def async_disable_tunnel(self, tunnel_id: str) -> None:
        """Point every hostname of a dashboard-managed tunnel at a 503 page."""
        if tunnel_id in self.state["tunnel_backups"]:
            return  # already disabled
        if not self._tunnel_remote.get(tunnel_id, False):
            raise CloudflareError(
                "This tunnel is set up with a local config file, so Cloudflare can't "
                "switch it off remotely. Lock its Access app or block the IP instead."
            )
        config = await self.client.get_tunnel_config(tunnel_id)
        if not config:
            raise CloudflareError("Could not read this tunnel's current settings.")
        self.state["tunnel_backups"][tunnel_id] = config
        await self._store.async_save(self.state)  # keep the backup before changing anything
        await self.client.put_tunnel_config(
            tunnel_id, {"ingress": [{"service": "http_status:503"}]}
        )
        self._set_now(self.data.tunnels, tunnel_id, "disabled_by_ha", True)

    async def async_enable_tunnel(self, tunnel_id: str) -> None:
        config = self.state["tunnel_backups"].get(tunnel_id)
        if config is None:
            raise CloudflareError(
                "This tunnel was not disabled from Home Assistant, so there is nothing to restore."
            )
        await self.client.put_tunnel_config(tunnel_id, config)
        del self.state["tunnel_backups"][tunnel_id]
        await self._store.async_save(self.state)
        self._set_now(self.data.tunnels, tunnel_id, "disabled_by_ha", False)

    def _set_now(self, items: dict, object_id: str, key: str, value: Any) -> None:
        """Show the result of an action right away instead of at the next poll."""
        if object_id in items:
            items[object_id][key] = value
            self.async_update_listeners()

    def forget_ip(self, ip: str) -> int:
        keys = [k for k in self.state["known"] if k == ip or k.endswith(f"|{ip}")]
        for key in keys:
            del self.state["known"][key]
        self._save()
        return len(keys)


def _code(value: Any) -> str:
    """Show outside text (user agents, reverse DNS, emails) literally.

    These values come from visitors or third parties, so they are put in an
    inline code span: Markdown links, images and formatting in them never render.
    """
    text = " ".join(str(value).split()).replace("`", "'")[:200]
    return f"`{text}`"


def _notification_text(e: dict[str, Any]) -> str:
    place = ", ".join(p for p in (e["city"], e["region"], e["country"]) if p) or "unknown"
    title = f"**{e['source']}** on {_code(e['name'])}"
    if e["hostname"] and e["hostname"] != e["name"]:
        title += f" ({_code(e['hostname'])})"
    lines = [
        title,
        "",
        f"- IP: {_code(e['ip'])}" + (" (already blocked)" if e["already_blocked"] else ""),
        f"- Location: {_code(place)}",
    ]
    if e["isp"]:
        lines.append(f"- Network: {_code(e['isp'])}")
    if e["reverse_dns"]:
        lines.append(f"- Reverse DNS: {_code(e['reverse_dns'])}")
    if e["user_email"]:
        lines.append(f"- User: {_code(e['user_email'])}")
    if e["login_allowed"] is not None:
        lines.append(f"- Login: {'allowed' if e['login_allowed'] else 'DENIED'}")
    if e["source_type"] == SOURCE_TUNNEL:
        lines.append(f"- Requests: {e['requests']}, status codes {e['http_statuses']}")
        for agent in e["user_agents"]:
            lines.append(f"- Browser/app: {_code(agent)}")
    if e.get("colo"):
        lines.append(f"- Cloudflare data center: {_code(e['colo'])}")
    lines += [
        f"- Seen: {_code(e['seen_at'])}",
        "",
        f"[AbuseIPDB report]({e['abuseipdb_url']}) · [ipinfo]({e['ipinfo_url']})",
        "",
        "To block it, run the action *Cloudflare Monitor: Block IP*.",
    ]
    return "\n".join(lines)
