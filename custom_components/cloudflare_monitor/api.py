"""Small async client for the parts of the Cloudflare API this integration uses."""

from __future__ import annotations

from datetime import datetime
import json
import logging
from typing import Any

import aiohttp

from .const import LOCK_POLICY_NAME

VISITOR_FIELDS = [
    "clientIP",
    "clientRequestHTTPHost",
    "clientCountryName",
    "clientAsn",
    "clientASNDescription",
    "userAgent",
    "edgeResponseStatus",
]
REQUIRED_VISITOR_FIELDS = {"clientIP", "clientRequestHTTPHost"}

_LOGGER = logging.getLogger(__name__)

API_BASE = "https://api.cloudflare.com/client/v4"
TIMEOUT = aiohttp.ClientTimeout(total=30)


class CloudflareError(Exception):
    """Any error talking to Cloudflare."""


class CloudflareAuthError(CloudflareError):
    """The token is wrong, expired, or missing a permission."""


def _iso(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


class CloudflareClient:
    """Thin wrapper around the Cloudflare REST and GraphQL APIs."""

    def __init__(
        self, session: aiohttp.ClientSession, token: str, account_id: str | None = None
    ) -> None:
        self._session = session
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        self.account_id = account_id
        self._denied_fields: set[str] = set()

    # ------------------------------------------------------------------ basics

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"{API_BASE}{path}"
        try:
            async with self._session.request(
                method,
                url,
                headers=self._headers,
                params=params,
                json=body,
                timeout=TIMEOUT,
            ) as resp:
                try:
                    data = await resp.json(content_type=None)
                except (aiohttp.ContentTypeError, json.JSONDecodeError):
                    data = {}
                if resp.status in (401, 403):
                    raise CloudflareAuthError(
                        f"{method} {path}: permission denied ({_errors(data)})"
                    )
                if resp.status >= 400 or not data.get("success", True):
                    raise CloudflareError(
                        f"{method} {path}: HTTP {resp.status} ({_errors(data)})"
                    )
                return data
        except aiohttp.ClientError as err:
            raise CloudflareError(f"{method} {path}: {err}") from err
        except TimeoutError as err:
            raise CloudflareError(f"{method} {path}: timed out") from err

    async def _get_all(
        self, path: str, params: dict[str, Any] | None = None, per_page: int = 100
    ) -> list[dict[str, Any]]:
        """GET every page of a paginated list."""
        results: list[dict[str, Any]] = []
        page = 1
        while True:
            query = {**(params or {}), "page": page, "per_page": per_page}
            data = await self._request("GET", path, params=query)
            results.extend(data.get("result") or [])
            info = data.get("result_info") or {}
            if page >= int(info.get("total_pages") or 1) or page >= 50:
                return results
            page += 1

    def _acct(self, path: str) -> str:
        return f"/accounts/{self.account_id}{path}"

    # ---------------------------------------------------------------- accounts

    async def list_accounts(self) -> list[dict[str, Any]]:
        return await self._get_all("/accounts", per_page=50)

    # ----------------------------------------------------------------- tunnels

    async def list_tunnels(self) -> list[dict[str, Any]]:
        return await self._get_all(
            self._acct("/cfd_tunnel"), {"is_deleted": "false"}, per_page=50
        )

    async def get_tunnel_config(self, tunnel_id: str) -> dict[str, Any] | None:
        """Remote config of a dashboard-managed tunnel (None for local configs)."""
        data = await self._request(
            "GET", self._acct(f"/cfd_tunnel/{tunnel_id}/configurations")
        )
        result = data.get("result") or {}
        return result.get("config")

    async def put_tunnel_config(self, tunnel_id: str, config: dict[str, Any]) -> None:
        await self._request(
            "PUT",
            self._acct(f"/cfd_tunnel/{tunnel_id}/configurations"),
            body={"config": config},
        )

    # ------------------------------------------------------------------ access

    async def list_access_apps(self) -> list[dict[str, Any]]:
        return await self._get_all(self._acct("/access/apps"))

    async def list_app_policies(self, app_id: str) -> list[dict[str, Any]]:
        data = await self._request("GET", self._acct(f"/access/apps/{app_id}/policies"))
        return data.get("result") or []

    async def lock_app(self, app_id: str) -> str:
        """Add a 'Block everyone' policy to an Access app. Returns the policy id.

        Cloudflare evaluates Block policies before Allow policies, so this stops
        every login until the policy is removed again.
        """
        policies = await self.list_app_policies(app_id)
        for policy in policies:
            if policy.get("name") == LOCK_POLICY_NAME:
                return policy["id"]
        precedence = max((p.get("precedence") or 0 for p in policies), default=0) + 1
        data = await self._request(
            "POST",
            self._acct(f"/access/apps/{app_id}/policies"),
            body={
                "name": LOCK_POLICY_NAME,
                "decision": "deny",
                "include": [{"everyone": {}}],
                "precedence": precedence,
            },
        )
        return data["result"]["id"]

    async def unlock_app(self, app_id: str) -> int:
        """Remove every lock policy this integration added. Returns how many."""
        removed = 0
        for policy in await self.list_app_policies(app_id):
            if policy.get("name") == LOCK_POLICY_NAME:
                await self._request(
                    "DELETE",
                    self._acct(f"/access/apps/{app_id}/policies/{policy['id']}"),
                )
                removed += 1
        return removed

    async def access_logins_since(self, since: datetime) -> list[dict[str, Any]]:
        """Access authentication log entries newer than `since`, oldest first."""
        data = await self._request(
            "GET",
            self._acct("/access/logs/access_requests"),
            params={"since": _iso(since), "direction": "asc", "limit": 1000},
        )
        return data.get("result") or []

    # ------------------------------------------------------------- zones / dns

    async def list_zones(self) -> list[dict[str, Any]]:
        return await self._get_all("/zones", {"account.id": self.account_id}, per_page=50)

    async def list_tunnel_cnames(self, zone_id: str) -> list[dict[str, Any]]:
        records = await self._get_all(
            f"/zones/{zone_id}/dns_records", {"type": "CNAME"}
        )
        return [
            r
            for r in records
            if str(r.get("content", "")).endswith(".cfargotunnel.com")
        ]

    # ----------------------------------------------------------------- graphql

    async def visitors_by_ip(
        self, zone_id: str, hosts: list[str], start: datetime, end: datetime
    ) -> list[dict[str, Any]]:
        """Visitor IPs seen on the given hostnames between start and end."""
        flt = json.dumps(
            {
                "datetime_geq": _iso(start),
                "datetime_lt": _iso(end),
                "clientRequestHTTPHost_in": hosts,
            }
        )
        # GraphQL input objects use bare keys, not quoted JSON keys
        for key in ("datetime_geq", "datetime_lt", "clientRequestHTTPHost_in"):
            flt = flt.replace(f'"{key}"', key)
        # Cheaper plans reject some dimensions (Free has no clientAsn, for example).
        # Drop each field Cloudflare refuses and ask again; clientIP is all we need.
        fields = [f for f in VISITOR_FIELDS if f not in self._denied_fields]
        while True:
            query = (
                "{ viewer { zones(filter: {zoneTag: %s}) {"
                " httpRequestsAdaptiveGroups(limit: 2000, filter: %s, orderBy: [count_DESC]) {"
                " count dimensions { %s } } } } }"
            ) % (json.dumps(zone_id), flt, " ".join(fields))
            data = await self._request("POST", "/graphql", body={"query": query})
            if not data.get("errors"):
                break
            denied = _denied_field(_errors(data), fields)
            if denied is None or denied in REQUIRED_VISITOR_FIELDS:
                raise CloudflareError(f"GraphQL: {_errors(data)}")
            self._denied_fields.add(denied)
            fields.remove(denied)
        zones = ((data.get("data") or {}).get("viewer") or {}).get("zones") or []
        if not zones:
            return []
        return zones[0].get("httpRequestsAdaptiveGroups") or []

    # -------------------------------------------------------- ip access rules

    async def list_blocked_ips(self) -> list[dict[str, Any]]:
        return await self._get_all(
            self._acct("/firewall/access_rules/rules"), {"mode": "block"}
        )

    async def block_ip(self, ip: str, note: str) -> str:
        target = "ip6" if ":" in ip else "ip"
        if "/" in ip:
            target = "ip_range"
        data = await self._request(
            "POST",
            self._acct("/firewall/access_rules/rules"),
            body={
                "mode": "block",
                "configuration": {"target": target, "value": ip},
                "notes": note,
            },
        )
        return data["result"]["id"]

    async def unblock_ip(self, ip: str) -> int:
        rules = await self._get_all(
            self._acct("/firewall/access_rules/rules"),
            {"mode": "block", "configuration.value": ip},
        )
        for rule in rules:
            await self._request(
                "DELETE", self._acct(f"/firewall/access_rules/rules/{rule['id']}")
            )
        return len(rules)


def _denied_field(message: str, fields: list[str]) -> str | None:
    """The field named in a "does not have access to the field 'x'" error."""
    lowered = message.lower()
    if "does not have access to the field" not in lowered:
        return None
    for field in fields:
        if f"'{field.lower()}'" in lowered:
            return field
    return None


def _errors(data: dict[str, Any]) -> str:
    errors = data.get("errors") or []
    if not errors:
        return "no details"
    return "; ".join(
        f"{e.get('code', '')} {e.get('message', '')}".strip()
        if isinstance(e, dict)
        else str(e)
        for e in errors
    )
