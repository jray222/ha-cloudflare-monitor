"""Cloudflare Monitor: alerts for new IPs on your tunnels and Access apps."""

from __future__ import annotations

import ipaddress
import logging

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv, device_registry as dr
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.storage import Store
from homeassistant.helpers.typing import ConfigType

from .api import CloudflareClient, CloudflareError
from .const import CONF_ACCOUNT_ID, CONF_API_TOKEN, DOMAIN
from .coordinator import CloudflareMonitorCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.BINARY_SENSOR, Platform.SENSOR]
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

type CloudflareMonitorConfigEntry = ConfigEntry[CloudflareMonitorCoordinator]


def _valid_ip(value: str) -> str:
    value = str(value).strip()
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError as err:
        raise vol.Invalid(f"'{value}' is not an IP address") from err
    return value


IP_SCHEMA = vol.Schema({vol.Required("ip"): _valid_ip})
BLOCK_SCHEMA = IP_SCHEMA.extend({vol.Optional("note"): cv.string})
DEVICE_SCHEMA = vol.Schema({vol.Required("device_id"): cv.string})


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register the actions once, for all accounts."""

    def coordinators() -> list[CloudflareMonitorCoordinator]:
        return [
            entry.runtime_data
            for entry in hass.config_entries.async_loaded_entries(DOMAIN)
        ]

    def from_device(call: ServiceCall, prefix: str) -> tuple[CloudflareMonitorCoordinator, str]:
        device = dr.async_get(hass).async_get(call.data["device_id"])
        if device is None:
            raise ServiceValidationError("That device no longer exists.")
        for domain, ident in device.identifiers:
            if domain == DOMAIN and ident.startswith(prefix):
                object_id = ident[len(prefix):]
                for coordinator in coordinators():
                    if coordinator.config_entry.entry_id in device.config_entries:
                        return coordinator, object_id
        kind = "tunnel" if prefix == "tunnel_" else "Access application"
        raise ServiceValidationError(f"Pick a Cloudflare {kind} device.")

    async def run(coro) -> None:
        try:
            await coro
        except CloudflareError as err:
            raise HomeAssistantError(f"Cloudflare said: {err}") from err

    async def block_ip(call: ServiceCall) -> None:
        if not coordinators():
            raise ServiceValidationError("Cloudflare Monitor is not set up.")
        for coordinator in coordinators():
            await run(coordinator.async_block_ip(call.data["ip"], call.data.get("note")))

    async def unblock_ip(call: ServiceCall) -> None:
        for coordinator in coordinators():
            await run(coordinator.async_unblock_ip(call.data["ip"]))

    async def lock_app(call: ServiceCall) -> None:
        coordinator, app_id = from_device(call, "app_")
        await run(coordinator.async_lock_app(app_id))

    async def unlock_app(call: ServiceCall) -> None:
        coordinator, app_id = from_device(call, "app_")
        await run(coordinator.async_unlock_app(app_id))

    async def disable_tunnel(call: ServiceCall) -> None:
        coordinator, tunnel_id = from_device(call, "tunnel_")
        await run(coordinator.async_disable_tunnel(tunnel_id))

    async def enable_tunnel(call: ServiceCall) -> None:
        coordinator, tunnel_id = from_device(call, "tunnel_")
        await run(coordinator.async_enable_tunnel(tunnel_id))

    async def forget_ip(call: ServiceCall) -> dict:
        removed = sum(c.forget_ip(call.data["ip"]) for c in coordinators())
        return {"forgotten": removed}

    hass.services.async_register(DOMAIN, "block_ip", block_ip, BLOCK_SCHEMA)
    hass.services.async_register(DOMAIN, "unblock_ip", unblock_ip, IP_SCHEMA)
    hass.services.async_register(DOMAIN, "lock_access_app", lock_app, DEVICE_SCHEMA)
    hass.services.async_register(DOMAIN, "unlock_access_app", unlock_app, DEVICE_SCHEMA)
    hass.services.async_register(DOMAIN, "disable_tunnel", disable_tunnel, DEVICE_SCHEMA)
    hass.services.async_register(DOMAIN, "enable_tunnel", enable_tunnel, DEVICE_SCHEMA)
    hass.services.async_register(
        DOMAIN, "forget_ip", forget_ip, IP_SCHEMA, supports_response=SupportsResponse.OPTIONAL
    )
    return True


async def async_setup_entry(hass: HomeAssistant, entry: CloudflareMonitorConfigEntry) -> bool:
    client = CloudflareClient(
        async_get_clientsession(hass), entry.data[CONF_API_TOKEN], entry.data[CONF_ACCOUNT_ID]
    )
    coordinator = CloudflareMonitorCoordinator(hass, entry, client)
    await coordinator.async_load()
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_options_updated))
    return True


async def _options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: CloudflareMonitorConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Delete the saved IP history and tunnel backups when the integration is removed."""
    await Store(hass, 1, f"{DOMAIN}.{entry.entry_id}").async_remove()
