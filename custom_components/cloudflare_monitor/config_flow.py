"""Setup screens for Cloudflare Monitor."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    BooleanSelector,
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .api import CloudflareAuthError, CloudflareClient, CloudflareError
from .const import (
    CONF_ACCOUNT_ID,
    CONF_ACCOUNT_NAME,
    CONF_API_TOKEN,
    CONF_IPINFO_TOKEN,
    CONF_NEW_IP_SCOPE,
    CONF_NOTIFY,
    CONF_SCAN_INTERVAL,
    CONF_TRUSTED_IPS,
    CONF_WATCH_ACCESS,
    CONF_WATCH_CONNECTORS,
    CONF_WATCH_TUNNELS,
    DEFAULT_NEW_IP_SCOPE,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    SCOPE_ACCOUNT,
    SCOPE_SOURCE,
)

TOKEN_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_API_TOKEN): TextSelector(
            TextSelectorConfig(type=TextSelectorType.PASSWORD)
        )
    }
)


class CloudflareMonitorConfigFlow(ConfigFlow, domain=DOMAIN):
    """Ask for an API token, then pick the account."""

    VERSION = 1

    def __init__(self) -> None:
        self._token = ""
        self._accounts: dict[str, str] = {}

    async def _check_token(self, token: str) -> dict[str, str]:
        client = CloudflareClient(async_get_clientsession(self.hass), token)
        accounts = await client.list_accounts()
        return {a["id"]: a.get("name") or a["id"] for a in accounts}

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            token = user_input[CONF_API_TOKEN].strip()
            try:
                self._accounts = await self._check_token(token)
            except CloudflareAuthError:
                errors["base"] = "invalid_auth"
            except CloudflareError:
                errors["base"] = "cannot_connect"
            else:
                if not self._accounts:
                    errors["base"] = "no_accounts"
                else:
                    self._token = token
                    if len(self._accounts) == 1:
                        return await self._create(next(iter(self._accounts)))
                    return await self.async_step_account()
        return self.async_show_form(
            step_id="user", data_schema=TOKEN_SCHEMA, errors=errors
        )

    async def async_step_account(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return await self._create(user_input[CONF_ACCOUNT_ID])
        options = [
            SelectOptionDict(value=aid, label=name) for aid, name in self._accounts.items()
        ]
        return self.async_show_form(
            step_id="account",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_ACCOUNT_ID): SelectSelector(
                        SelectSelectorConfig(options=options)
                    )
                }
            ),
        )

    async def _create(self, account_id: str) -> ConfigFlowResult:
        await self.async_set_unique_id(account_id)
        self._abort_if_unique_id_configured()
        name = self._accounts[account_id]
        return self.async_create_entry(
            title=name,
            data={
                CONF_API_TOKEN: self._token,
                CONF_ACCOUNT_ID: account_id,
                CONF_ACCOUNT_NAME: name,
            },
        )

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        entry = self._get_reauth_entry()
        if user_input is not None:
            token = user_input[CONF_API_TOKEN].strip()
            try:
                accounts = await self._check_token(token)
            except CloudflareAuthError:
                errors["base"] = "invalid_auth"
            except CloudflareError:
                errors["base"] = "cannot_connect"
            else:
                if entry.data[CONF_ACCOUNT_ID] not in accounts:
                    errors["base"] = "wrong_account"
                else:
                    return self.async_update_reload_and_abort(
                        entry, data_updates={CONF_API_TOKEN: token}
                    )
        return self.async_show_form(
            step_id="reauth_confirm", data_schema=TOKEN_SCHEMA, errors=errors
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        return CloudflareMonitorOptionsFlow()


class CloudflareMonitorOptionsFlow(OptionsFlow):
    """Everything adjustable after setup."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(data=user_input)
        opts = self.config_entry.options
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_SCAN_INTERVAL,
                    default=opts.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                ): NumberSelector(
                    NumberSelectorConfig(
                        min=1, max=60, step=1, unit_of_measurement="min",
                        mode=NumberSelectorMode.BOX,
                    )
                ),
                vol.Required(
                    CONF_WATCH_ACCESS, default=opts.get(CONF_WATCH_ACCESS, True)
                ): BooleanSelector(),
                vol.Required(
                    CONF_WATCH_TUNNELS, default=opts.get(CONF_WATCH_TUNNELS, True)
                ): BooleanSelector(),
                vol.Required(
                    CONF_WATCH_CONNECTORS, default=opts.get(CONF_WATCH_CONNECTORS, True)
                ): BooleanSelector(),
                vol.Required(
                    CONF_NEW_IP_SCOPE,
                    default=opts.get(CONF_NEW_IP_SCOPE, DEFAULT_NEW_IP_SCOPE),
                ): SelectSelector(
                    SelectSelectorConfig(
                        options=[SCOPE_ACCOUNT, SCOPE_SOURCE],
                        translation_key=CONF_NEW_IP_SCOPE,
                    )
                ),
                vol.Required(
                    CONF_NOTIFY, default=opts.get(CONF_NOTIFY, True)
                ): BooleanSelector(),
                vol.Optional(
                    CONF_TRUSTED_IPS,
                    description={"suggested_value": opts.get(CONF_TRUSTED_IPS, "")},
                ): TextSelector(TextSelectorConfig(multiline=True)),
                vol.Optional(
                    CONF_IPINFO_TOKEN,
                    description={"suggested_value": opts.get(CONF_IPINFO_TOKEN, "")},
                ): TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD)),
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
