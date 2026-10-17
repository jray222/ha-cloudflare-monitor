"""Constants for the Cloudflare Monitor integration."""

from __future__ import annotations

DOMAIN = "cloudflare_monitor"
MANUFACTURER = "Cloudflare"

CONF_API_TOKEN = "api_token"
CONF_ACCOUNT_ID = "account_id"
CONF_ACCOUNT_NAME = "account_name"

# Options (all editable later from Settings > Devices & services > Configure)
CONF_SCAN_INTERVAL = "scan_interval"
CONF_WATCH_ACCESS = "watch_access_logins"
CONF_WATCH_TUNNELS = "watch_tunnel_visitors"
CONF_WATCH_CONNECTORS = "watch_tunnel_connectors"
CONF_NEW_IP_SCOPE = "new_ip_scope"
CONF_NOTIFY = "persistent_notification"
CONF_IPINFO_TOKEN = "ipinfo_token"
CONF_TRUSTED_IPS = "trusted_ips"

SCOPE_ACCOUNT = "account"
SCOPE_SOURCE = "source"

DEFAULT_SCAN_INTERVAL = 5  # minutes
DEFAULT_NEW_IP_SCOPE = SCOPE_ACCOUNT

# Event fired once for every new IP. Use it as an automation trigger.
EVENT_NEW_IP = f"{DOMAIN}_new_ip"

# Kinds of places an IP can show up
SOURCE_ACCESS = "access_login"
SOURCE_TUNNEL = "tunnel_visitor"
SOURCE_CONNECTOR = "tunnel_connector"

SOURCE_LABELS = {
    SOURCE_ACCESS: "Access login",
    SOURCE_TUNNEL: "Tunnel visitor",
    SOURCE_CONNECTOR: "Tunnel connector (cloudflared)",
}

# Device models, also used to filter the device pickers in the actions
MODEL_ACCOUNT = "Account"
MODEL_TUNNEL = "Tunnel"
MODEL_ACCESS_APP = "Access application"

# Names of the things this integration creates in Cloudflare, so they are
# easy to recognise (and remove by hand) in the Cloudflare dashboard.
LOCK_POLICY_NAME = "Locked by Home Assistant"
BLOCK_NOTE_PREFIX = "Blocked from Home Assistant"

RECENT_ALERTS_KEPT = 25
