"""Binary sensors for Cloudflare Monitor."""

from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import CloudflareMonitorConfigEntry
from .entity import CloudflareEntity, add_entities_as_they_appear


async def async_setup_entry(
    hass: HomeAssistant,
    entry: CloudflareMonitorConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data

    def build(kind: str, object_id: str) -> list:
        if kind == "tunnel":
            return [
                TunnelConnected(coordinator, "tunnel_connected", kind, object_id),
                TunnelPaused(coordinator, "tunnel_paused", kind, object_id),
            ]
        if kind == "app":
            return [AppLocked(coordinator, "app_locked", kind, object_id)]
        return []

    entry.async_on_unload(add_entities_as_they_appear(coordinator, async_add_entities, build))


class TunnelConnected(CloudflareEntity, BinarySensorEntity):
    """On while at least one cloudflared connector is connected."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    @property
    def is_on(self) -> bool:
        return self.item.get("status") in ("healthy", "degraded")


class TunnelPaused(CloudflareEntity, BinarySensorEntity):
    """On while the tunnel is switched off by the 'Disable tunnel' action."""

    _attr_icon = "mdi:pause-octagon"

    @property
    def is_on(self) -> bool:
        return bool(self.item.get("disabled_by_ha"))


class AppLocked(CloudflareEntity, BinarySensorEntity):
    """On while the 'Lock Access app' block policy is in place."""

    _attr_device_class = BinarySensorDeviceClass.LOCK

    @property
    def is_on(self) -> bool:
        # The lock device class treats "on" as unlocked
        return not self.item.get("locked")
