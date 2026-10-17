"""Sensors for Cloudflare Monitor."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorStateClass
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import CloudflareMonitorConfigEntry
from .entity import CloudflareEntity, add_entities_as_they_appear

TUNNEL_STATES = ["healthy", "degraded", "down", "inactive", "unknown"]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: CloudflareMonitorConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    async_add_entities(
        [
            LastNewIpSensor(coordinator, "last_new_ip"),
            CountSensor(coordinator, "new_ips_24h", "new_ips_24h"),
            CountSensor(coordinator, "failed_logins_24h", "failed_logins_24h"),
            CountSensor(coordinator, "known_ips", "known_ip_count"),
            BlockedIpsSensor(coordinator, "blocked_ips"),
        ]
    )

    def build(kind: str, object_id: str) -> list:
        if kind == "tunnel":
            return [
                TunnelStatusSensor(coordinator, "tunnel_status", kind, object_id),
                TunnelConnectorsSensor(coordinator, "tunnel_connectors", kind, object_id),
            ]
        return [AppLastLoginSensor(coordinator, "app_last_login", kind, object_id)]

    entry.async_on_unload(add_entities_as_they_appear(coordinator, async_add_entities, build))


class LastNewIpSensor(CloudflareEntity, SensorEntity):
    """The most recent new IP, with everything known about it as attributes."""

    _attr_icon = "mdi:ip-network"

    @property
    def native_value(self) -> str | None:
        alerts = self.coordinator.data.recent_alerts
        return alerts[0]["ip"] if alerts else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        alerts = self.coordinator.data.recent_alerts
        if not alerts:
            return {}
        attrs = dict(alerts[0])
        attrs["recent"] = [
            f"{a['seen_at'][:16]} {a['ip']} ({a['country'] or '?'}) {a['source']} {a['name']}"
            for a in alerts[:10]
        ]
        return attrs


class CountSensor(CloudflareEntity, SensorEntity):
    """A plain number from the coordinator data."""

    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator, key: str, field: str) -> None:
        super().__init__(coordinator, key)
        self._field = field
        if key == "known_ips":
            self._attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> int:
        return getattr(self.coordinator.data, self._field)


class BlockedIpsSensor(CloudflareEntity, SensorEntity):
    """How many IPs are blocked by account IP Access rules."""

    _attr_icon = "mdi:shield-lock"

    @property
    def native_value(self) -> int:
        return len(self.coordinator.data.blocked_ips)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"ips": self.coordinator.data.blocked_ips[:50]}


class TunnelStatusSensor(CloudflareEntity, SensorEntity):
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = TUNNEL_STATES

    @property
    def native_value(self) -> str | None:
        status = self.item.get("status")
        return status if status in TUNNEL_STATES else "unknown"


class TunnelConnectorsSensor(CloudflareEntity, SensorEntity):
    """Number of cloudflared connections, with their public IPs and hostnames."""

    _attr_icon = "mdi:lan-connect"
    _attr_state_class = SensorStateClass.MEASUREMENT

    @property
    def native_value(self) -> int:
        return len(self.item.get("connections") or [])

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        item = self.item
        return {
            "connector_ips": item.get("connector_ips", []),
            "data_centers": sorted(
                {c.get("colo_name") for c in item.get("connections") or [] if c.get("colo_name")}
            ),
            "hostnames": item.get("hostnames", []),
            "managed_in_dashboard": item.get("remote_config"),
            "tunnel_id": item.get("id"),
        }


class AppLastLoginSensor(CloudflareEntity, SensorEntity):
    """IP of the latest login attempt on this Access app."""

    _attr_icon = "mdi:login"

    @property
    def native_value(self) -> str | None:
        login = self.item.get("last_login") or {}
        return login.get("ip")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        login = self.item.get("last_login") or {}
        return {
            "user_email": login.get("user_email"),
            "allowed": login.get("allowed"),
            "time": login.get("time"),
            "country": login.get("country"),
            "domain": self.item.get("domain"),
            "app_id": self.item.get("id"),
        }
