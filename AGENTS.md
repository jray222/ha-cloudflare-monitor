# AGENTS.md: handoff guide for coding agents

Read this file first. It is meant to let you work on this repo without exploring it.
Everything below was checked against the code at v0.1.3 (October 2026).

**Also read `AGENTS.local.md` if it exists.** It is git-ignored and holds the owner's
private context (the Home Assistant install, hostnames, people and house rules).
It is never committed because this repo is public.

## 1. What this is

A Home Assistant (HA) custom integration, installed through HACS, called
**Cloudflare Monitor** (domain `cloudflare_monitor`). It polls one Cloudflare account and:

- raises an alert (HA event + sidebar notification) when a **new IP** shows up in
  Access app logins, in visitors to tunnel hostnames, or as a tunnel connector origin;
- exposes sensors per account, tunnel, Access app and "watched site";
- offers actions (services) to block an IP, lock an Access app, or disable a tunnel,
  each with an undo. **Nothing destructive ever runs automatically.**

Owner: GitHub `jray222`. License MIT. No external Python requirements (`requirements: []`).

## 2. Hard rules

1. Never commit secrets: Cloudflare tokens, ipinfo tokens, MQTT logins, webhook URLs,
   the owner's home IP, email address or private hostnames. The repo is public.
2. Never make the integration block, lock or disable anything on its own. Those stay
   user-triggered actions.
3. Text that comes from visitors or third parties (user agents, reverse DNS, ISP, emails)
   must go through `_code()` in `coordinator.py` before it reaches a notification.
4. Validate anything used as an IP with `ipaddress` before it goes into a URL or a
   Cloudflare rule (see `_handle_sightings` and `_valid_ip`).
5. Keep partial permissions non-fatal: a missing token permission adds a line to
   `data.problems` (logged as a warning) instead of failing the whole poll.
6. Every change ships through a PR to `main` with CI green (section 9), and bumps
   `manifest.json` `version` (section 10).
7. Owner's style: plain, human-readable code and docs; user-facing text in simple
   English. Anything that ends up in HA (blueprints, dashboards, automations) must be
   easy to edit in the HA UI editor: native triggers/conditions, minimal Jinja.

## 3. File map

```
custom_components/cloudflare_monitor/
  __init__.py        setup, service registration (async_setup), entry setup/unload/remove
  api.py             CloudflareClient: REST + GraphQL calls, error classes
  coordinator.py     CloudflareMonitorCoordinator: the poll, new-IP logic, alerts, actions
  entity.py          CloudflareEntity base (device info per kind), add_entities_as_they_appear
  sensor.py          all sensors
  binary_sensor.py   all binary sensors
  geo.py             ipinfo.io lookup (is_public_ip, lookup_ip)
  config_flow.py     token step, account picker, reauth, options flow
  const.py           every CONF_* key, defaults, source names, device models
  services.yaml      service field schemas (selectors)
  strings.json       UI text. translations/en.json MUST stay byte-identical to it
  manifest.json      domain, version, iot_class cloud_polling
  brand/             icon/logo PNGs (HA 2026.3+ shows them)
blueprints/automation/cloudflare_monitor/new_ip_alert.yaml   phone alert with Block button
tests/test_integration.py   end-to-end tests with a mocked Cloudflare API
tests/conftest.py           enables custom integrations for every test
.github/workflows/validate.yml   CI: hassfest, HACS action, ruff + pytest
hacs.json           name, minimum HA 2025.6.0, render_readme
images/             banner.png (README), icon.svg / logo.svg sources
```

## 4. Runtime flow

`async_setup_entry` builds `CloudflareClient(session, token, account_id)`, then
`CloudflareMonitorCoordinator`, calls `async_load()` (reads the Store), does the first
refresh, and forwards to the `sensor` and `binary_sensor` platforms. An options change
reloads the entry (`_options_updated`). Removing the entry deletes the Store.

`_async_update_data()` runs every `scan_interval` minutes (default 5), in this order:

1. `_poll_tunnels`: `list_tunnels()`; fills `data.tunnels`; each connection's
   `origin_ip` becomes a `Sighting` (source `tunnel_connector`) if connectors are watched.
2. `_slow_refresh` (at most hourly, `SLOW_REFRESH`): reads remote ingress config per
   dashboard-managed tunnel and CNAMEs ending `.cfargotunnel.com` in every zone to build
   `self._hostnames` (`host -> {tunnel_id, zone_id}`); re-reads which apps carry the lock
   policy into `self._locked_apps`. A disabled tunnel's hostnames come from its backup.
3. `_poll_apps`: `list_access_apps()` (skips types `warp`, `app_launcher`, `biso`).
4. `_poll_access_logins`: Access auth logs since `state["access_since"]` (first run: 7 days).
   Each entry becomes a `Sighting` (source `access_login`); denied ones add to
   `failed_login_times`.
5. `_poll_tunnel_visitors`: GraphQL per zone for all tunnel hostnames plus watched sites,
   window from `state["graphql_since"]` minus 5 min overlap, capped at 24 h back
   (first run 24 h, retried with 1 h if the plan refuses). Rows merge per (ip, host)
   into `Sighting`s (source `tunnel_visitor`).
6. `_poll_blocked`: account IP Access rules in mode block.

Auth errors: if neither tunnels nor apps were read, raises `ConfigEntryAuthFailed`
(starts reauth); otherwise the error is just a problem line. Other `CloudflareError`
raises `UpdateFailed`.

Then `_handle_sightings`:
- Key in `state["known"]` is the bare IP (scope `account`, default) or
  `"{source_type}:{source_id}|{ip}"` (scope `source`). Connector IPs are always keyed per
  tunnel.
- Unknown key: recorded; if `baseline_done` is false (very first poll) or the IP is in
  Trusted IPs, no alert. Otherwise `_alert()`.
- Watched-site visitors are recorded in `state["site_visitors"]` regardless of newness
  (trusted IPs excluded).

`_alert()`: ipinfo lookup (cached in `state["geo"]`, max 2000), builds the event dict,
fires `cloudflare_monitor_new_ip`, prepends to `recent_alerts` (keeps 25), creates a
persistent notification (`notification_id = cloudflare_monitor_<ip>`) if enabled.

After that: trims 24 h counters, drops `recent_alerts` for IPs that are now trusted,
builds `data.sites` (`_build_sites`), logs problems, delay-saves the Store (5 s).

### Persistent state

`Store(hass, 1, "cloudflare_monitor.<entry_id>")` (in HA's `.storage/`). Keys:
`known`, `geo`, `recent_alerts`, `alert_times`, `failed_login_times`, `tunnel_backups`,
`app_last_login`, `baseline_done`, `site_visitors`, `site_alert_times`,
`access_since`, `graphql_since`. Add new keys with `setdefault` in `async_load()`;
there is no migration code, so never rename or repurpose an existing key.

### MonitorData (what entities read)

`tunnels{id: {id,name,status,remote_config,connections,connector_ips,hostnames,disabled_by_ha}}`,
`apps{id: {id,name,domain,type,locked,last_login}}`,
`sites{host: {id,name,tunnel,visitors[],visitor_count,new_ips_24h}}`,
`blocked_ips[{ip,note,since}]`, `recent_alerts[]`, `new_ips_24h`, `failed_logins_24h`,
`known_ip_count`, `problems[]`.

## 5. Cloudflare API calls (api.py)

Base `https://api.cloudflare.com/client/v4`, Bearer token, 30 s timeout. HTTP 401/403 ->
`CloudflareAuthError`; other >=400 or `success: false` -> `CloudflareError`.
`_get_all` pages until `result_info.total_pages` (max 50 pages).

| Method | Endpoint | Token permission |
|---|---|---|
| `list_accounts` | GET `/accounts` | Account Settings: Read |
| `list_tunnels` | GET `/accounts/{a}/cfd_tunnel?is_deleted=false` | Cloudflare Tunnel: Read |
| `get_tunnel_config` / `put_tunnel_config` | GET/PUT `/accounts/{a}/cfd_tunnel/{t}/configurations` | Tunnel Read / **Edit** |
| `list_access_apps` | GET `/accounts/{a}/access/apps` | Access: Apps and Policies: Read |
| `list_app_policies`, `lock_app`, `unlock_app` | GET/POST/DELETE `/accounts/{a}/access/apps/{app}/policies[/{p}]` | Apps and Policies Read / **Edit** |
| `access_logins_since` | GET `/accounts/{a}/access/logs/access_requests?since&direction=asc&limit=1000` | Access: Audit Logs: Read |
| `list_zones` | GET `/zones?account.id=` | Zone: Read |
| `list_tunnel_cnames` | GET `/zones/{z}/dns_records?type=CNAME` | DNS: Read |
| `visitors_by_ip` | POST `/graphql`, `httpRequestsAdaptiveGroups` (limit 2000) | Zone Analytics: Read |
| `list_blocked_ips`, `block_ip`, `unblock_ip` | `/accounts/{a}/firewall/access_rules/rules` | Account Firewall Access Rules Read / **Edit** |

Known quirks (learned the hard way):
- Cloudflare can return an **empty list instead of 403** when a permission is missing;
  the code logs "Cloudflare returned no tunnels / Access apps" for that.
- **Free plan rejects some GraphQL fields** (e.g. `clientAsn`). `visitors_by_ip` drops each
  field named in a "does not have access to the field" error and retries; `clientIP` and
  `clientRequestHTTPHost` are required.
- GraphQL filters use bare keys, hence the `replace` trick in `visitors_by_ip`.
- Tunnels with a local `config.yml` (`remote_config` false) cannot be disabled remotely.
- When creating the token in the Cloudflare UI, adding a "DNS View" permission makes the
  save fail; use "DNS: Read". Zone resources: "All zones from an account".

## 6. Entities

`_attr_has_entity_name = True`, names come from `strings.json` `entity.*` via
`translation_key`. Unique id: `{account_id}_{kind}_{object_id}_{key}`.
Device identifiers: `account_{id}`, `tunnel_{id}`, `app_{id}`, `site_{host}`; device
models (`const.py`) `Account`, `Tunnel`, `Access application`, `Watched site` are also
used by the service device selectors. Tunnel/app/site entities appear dynamically
(`add_entities_as_they_appear`) and go unavailable when the object disappears.

| Device | key | Platform | State / attributes |
|---|---|---|---|
| Account | `last_new_ip` | sensor | IP; all event fields + `recent` (10 lines) |
| Account | `new_ips_24h`, `failed_logins_24h`, `known_ips` (diagnostic) | sensor | counts |
| Account | `blocked_ips` | sensor | count; `ips` (first 50) |
| Tunnel | `tunnel_status` | sensor (enum) | healthy/degraded/down/inactive/unknown |
| Tunnel | `tunnel_connectors` | sensor | connection count; connector_ips, data_centers, hostnames, managed_in_dashboard, tunnel_id |
| Tunnel | `tunnel_connected` | binary_sensor connectivity | on if healthy/degraded |
| Tunnel | `tunnel_paused` ("Disabled from Home Assistant") | binary_sensor | on while disabled by HA |
| Access app | `app_last_login` | sensor | IP; user_email, allowed, time, country, domain, app_id |
| Access app | `app_locked` ("Logins") | binary_sensor lock | **on = unlocked** (HA lock device class) |
| Watched site | `site_last_visitor` | sensor | IP; country, requests, user_agent, seen_at, tunnel |
| Watched site | `site_visitors_24h` | sensor | distinct IPs; `recent` (25 lines) |
| Watched site | `site_new_ips_24h` | sensor | count |

Resulting entity_ids look like `sensor.tunnel_<name>_status`,
`binary_sensor.access_app_<name>_logins`, `sensor.site_<host_with_underscores>_last_visitor`,
`sensor.cloudflare_<account_name>_last_new_ip`.

## 7. Services (domain `cloudflare_monitor`)

Registered once in `async_setup`, act on every loaded entry. Cloudflare errors surface as
`HomeAssistantError("Cloudflare said: ...")`.

| Service | Fields | Effect | Undo |
|---|---|---|---|
| `block_ip` | `ip` (IP or CIDR), `note` | account IP Access rule mode block, note prefixed "Blocked from Home Assistant <time>" | `unblock_ip` |
| `unblock_ip` | `ip` | deletes block rules with that value | |
| `lock_access_app` | `device_id` (Access app device) | adds deny-everyone policy "Locked by Home Assistant" | `unlock_access_app` |
| `unlock_access_app` | `device_id` | deletes every policy with that name | |
| `disable_tunnel` | `device_id` (Tunnel device) | saves ingress to Store first, then PUTs `{"ingress":[{"service":"http_status:503"}]}` | `enable_tunnel` restores the backup |
| `forget_ip` | `ip` | removes it from `known` so it alerts again; returns `{forgotten: n}` | |

Event `cloudflare_monitor_new_ip` data: `ip, source, source_type, name, hostname,
user_email, login_allowed, identity_provider, city, region, country, isp, reverse_dns,
map_location, timezone, requests, http_statuses, user_agents, seen_at, already_blocked,
is_public_ip, abuseipdb_url, ipinfo_url, app_id, tunnel_id` plus connector extras
`colo, cloudflared_version`.

## 8. Options (config_flow.py, keys in const.py)

`scan_interval` (1-60 min, default 5), `watch_access_logins`, `watch_tunnel_visitors`,
`watch_tunnel_connectors` (all default true), `new_ip_scope` (`account` | `source`),
`persistent_notification` (default true), `watched_sites` (hostnames, newline/comma
separated), `trusted_ips` (IPs/CIDRs, newline/comma separated), `ipinfo_token`.
Entry data: `api_token`, `account_id`, `account_name`. Config entry unique id = account id.

To add an option: constant in `const.py`, field in `CloudflareMonitorOptionsFlow`, label
and description in `strings.json` **and** `translations/en.json`, read it with
`self._opt(KEY, default)` in the coordinator, document it in README "Options".

## 9. Tests and CI

CI (`.github/workflows/validate.yml`) runs on every PR: hassfest, HACS validation
(ignores brands/description/topics), and:

```bash
pip install pytest-homeassistant-custom-component ruff
ruff check custom_components tests --select E,F,W,B --ignore E501
pytest -q
```

Python 3.13. Tests mock every Cloudflare URL with `AiohttpClientMocker` via
`mock_cloudflare()`; helpers `login()` and `visitor()` build log rows and GraphQL rows.
**If you add an API call, add its mock in `mock_cloudflare()` or every test breaks.**
Existing tests: config flow; new-IP alert and actions; notification escaping; GraphQL
field fallback; watched-site visitors; trusting an IP clears its alerts.
A typical test: set up a `MockConfigEntry`, run a first refresh (baseline), change the
mocked logs/visitors, `await coordinator.async_refresh()`, assert on events/states.

## 10. Releasing

- There are no git tags or GitHub releases; HACS tracks the default branch, so a merge to
  `main` is the release. Bump `"version"` in `manifest.json` (semver, currently 0.1.3)
  in the same PR so HACS shows an update.
- Branch -> PR -> CI green -> owner merges (the owner may say "merge it"; then merge).
- After merge the owner updates in HACS and **restarts HA themselves**. New code only runs
  after that restart. Don't restart HA unless the owner asks.
- The blueprint is imported in HA from its GitHub URL; HA keeps its own copy, so a repo
  fix to the blueprint must also be applied to HA's copy (re-import) to take effect.

## 11. Blueprint gotcha

In `new_ip_alert.yaml`, notification action ids use `context.id`. `context` does not
exist in top-level blueprint `variables:`, only once actions run, so those variables
are defined in the first `variables` action step. Keep it that way (bug fixed in PR #6).

## 12. History (merged PRs)

#1 initial integration, CI, license. #2 GraphQL retry without fields the plan forbids.
#3 icon/logo/banner. #4 warn on empty tunnel/app lists. #5 watched sites + trusted IPs
drop old alerts (v0.1.3). #6 blueprint `context` fix.

## 13. Possible next steps (suggestions, not requested yet)

- Optional auto-response (e.g. lock an app after N denied logins), only as an opt-in
  blueprint, never in the integration itself.
- Diagnostics download (`diagnostics.py`) with the token redacted.
- Repairs issue instead of a log warning when a token permission is missing.
