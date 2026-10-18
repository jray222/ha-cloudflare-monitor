"""Shared entity base and device info."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    CONF_ACCOUNT_NAME,
    DOMAIN,
    MANUFACTURER,
    MODEL_ACCESS_APP,
    MODEL_ACCOUNT,
    MODEL_SITE,
    MODEL_TUNNEL,
)
from .coordinator import CloudflareMonitorCoordinator


class CloudflareEntity(CoordinatorEntity[CloudflareMonitorCoordinator]):
    """Base: one of the account, a tunnel, an Access app, or a watched site."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: CloudflareMonitorCoordinator,
        key: str,
        kind: str = "account",
        object_id: str = "",
    ) -> None:
        super().__init__(coordinator)
        self.kind = kind
        self.object_id = object_id
        account = coordinator.account_id
        self._attr_translation_key = key
        self._attr_unique_id = f"{account}_{kind}_{object_id}_{key}".replace("__", "_")
        account_ident = (DOMAIN, f"account_{account}")
        if kind == "account":
            self._attr_device_info = DeviceInfo(
                identifiers={account_ident},
                name=f"Cloudflare {coordinator.config_entry.data.get(CONF_ACCOUNT_NAME, '')}".strip(),
                manufacturer=MANUFACTURER,
                model=MODEL_ACCOUNT,
                entry_type=DeviceEntryType.SERVICE,
                configuration_url="https://dash.cloudflare.com/",
            )
        elif kind == "tunnel":
            self._attr_device_info = DeviceInfo(
                identifiers={(DOMAIN, f"tunnel_{object_id}")},
                name=f"Tunnel {coordinator.data.tunnels[object_id]['name']}",
                manufacturer=MANUFACTURER,
                model=MODEL_TUNNEL,
                entry_type=DeviceEntryType.SERVICE,
                via_device=account_ident,
                configuration_url="https://one.dash.cloudflare.com/",
            )
        elif kind == "site":
            self._attr_device_info = DeviceInfo(
                identifiers={(DOMAIN, f"site_{object_id}")},
                name=f"Site {object_id}",
                manufacturer=MANUFACTURER,
                model=MODEL_SITE,
                entry_type=DeviceEntryType.SERVICE,
                via_device=account_ident,
                configuration_url=f"https://{object_id}/",
            )
        else:
            self._attr_device_info = DeviceInfo(
                identifiers={(DOMAIN, f"app_{object_id}")},
                name=f"Access app {coordinator.data.apps[object_id]['name']}",
                manufacturer=MANUFACTURER,
                model=MODEL_ACCESS_APP,
                entry_type=DeviceEntryType.SERVICE,
                via_device=account_ident,
                configuration_url="https://one.dash.cloudflare.com/",
            )

    @property
    def item(self) -> dict:
        """The tunnel, app or site this entity belongs to (empty if it disappeared)."""
        data = self.coordinator.data
        source = {"tunnel": data.tunnels, "site": data.sites}.get(self.kind, data.apps)
        return source.get(self.object_id, {})

    @property
    def available(self) -> bool:
        if self.kind == "account":
            return super().available
        return super().available and bool(self.item)


def add_entities_as_they_appear(
    coordinator: CloudflareMonitorCoordinator,
    async_add_entities: Callable[[Iterable[Entity]], None],
    build: Callable[[str, str], list[Entity]],
) -> Callable[[], None]:
    """Add entities for tunnels / apps / watched sites now, and for any created later."""
    seen: set[tuple[str, str]] = set()

    def check() -> None:
        new: list[Entity] = []
        for kind, items in (
            ("tunnel", coordinator.data.tunnels),
            ("app", coordinator.data.apps),
            ("site", coordinator.data.sites),
        ):
            for object_id in items:
                if (kind, object_id) not in seen:
                    seen.add((kind, object_id))
                    new.extend(build(kind, object_id))
        if new:
            async_add_entities(new)

    check()
    return coordinator.async_add_listener(check)
