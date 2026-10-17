# Cloudflare Monitor for Home Assistant

Tells you when a new IP address shows up on your Cloudflare Tunnels or Cloudflare Access apps, shows where it comes from, and lets you block it, lock an app, or switch a tunnel off from Home Assistant.

## What it watches

| Where | What you learn | Cloudflare source |
|---|---|---|
| **Access app logins** | IP, user email, allowed or denied, login provider, app | Access authentication logs |
| **Visitors to tunnel hostnames** | IP, country, network (ASN), number of requests, status codes, browser/app | Zone HTTP analytics (GraphQL) |
| **Tunnel connectors** | The public IP each `cloudflared` connects from, and the Cloudflare data center | Tunnel API |

A new connector IP is worth a look: it can mean your tunnel token is being used on another machine.

For every new IP it also looks up the city, region, ISP and reverse DNS (ipinfo.io) and adds links to AbuseIPDB and ipinfo so you can check its reputation.

The first check after setup only **learns** the IPs already in your logs (Access logs from the last 7 days, tunnel traffic from the last 24 hours). Alerts start from the second check.

## What you get in Home Assistant

**Cloudflare (account) device**
- `Last new IP`, with every detail as attributes and a `recent` list of the last 10
- `New IPs last 24 hours`
- `Denied logins last 24 hours`
- `Blocked IPs` (account IP Access rules), with the list as an attribute
- `Known IPs`

**One device per tunnel**: `Status`, `Connected`, `Connections` (connector IPs, data centers, hostnames as attributes), `Disabled from Home Assistant`

**One device per Access app**: `Last login IP` (email, allowed, time, country as attributes), `Logins` (shows Locked when the app is locked)

**Event** `cloudflare_monitor_new_ip` for every new IP, to use as an automation trigger. It carries: `ip`, `source`, `name`, `hostname`, `user_email`, `login_allowed`, `identity_provider`, `city`, `region`, `country`, `isp`, `reverse_dns`, `map_location`, `timezone`, `requests`, `http_statuses`, `user_agents`, `seen_at`, `already_blocked`, `abuseipdb_url`, `ipinfo_url`.

**A notification** in the Home Assistant sidebar for each new IP (can be turned off in the options).

## Actions

All of these only run when you (or an automation you build) call them. Nothing is blocked automatically.

| Action | What it does in Cloudflare | Undo |
|---|---|---|
| **Block IP** | Adds an account-wide IP Access rule (mode Block). Covers every proxied hostname, including tunnels and Access apps. | **Unblock IP** |
| **Lock Access app** | Adds a policy named "Locked by Home Assistant" that blocks everyone. Block policies win over Allow policies, so nobody can log in. | **Unlock Access app** removes that policy |
| **Disable tunnel** | Saves the tunnel's routes, then replaces them with a single "503 error" route. `cloudflared` stays connected, but nothing gets through. | **Enable tunnel** puts the saved routes back |
| **Forget IP** | Removes an IP from the known list so it alerts again next time | — |

Notes:
- **Disable tunnel** only works for tunnels managed in the Cloudflare dashboard. Tunnels that use a local `config.yml` can't be changed remotely; lock the Access app or block the IP instead.
- If you reach Home Assistant itself through the tunnel you disable, you lose remote access through it until you enable it again (Nabu Casa or your local network still work).
- Blocking whole countries with IP Access rules needs an Enterprise plan, so it is not offered.

## Creating the API token

Cloudflare dashboard > **My Profile > API Tokens > Create Token > Create Custom Token**.

| Type | Permission | Level | Needed for |
|---|---|---|---|
| Account | Account Settings | Read | Setup (find your account) |
| Account | Access: Audit Logs | Read | Access login alerts |
| Account | Access: Apps and Policies | Read (**Edit** to lock apps) | App devices, lock/unlock |
| Account | Cloudflare Tunnel | Read (**Edit** to disable tunnels) | Tunnel devices, disable/enable |
| Account | Account Firewall Access Rules | Read (**Edit** to block IPs) | Blocked IP list, block/unblock |
| Zone | Zone | Read | Finding which hostnames belong to tunnels |
| Zone | DNS | Read | Same, for tunnels with a local config |
| Zone | Analytics | Read | Tunnel visitor alerts |

Under **Account Resources** pick your account; under **Zone Resources** pick "All zones from an account". Read-only gives you all the alerts; the Edit permissions are only for the actions. Anything you leave out just switches that part off (a warning appears in the log).

## Install

### With HACS
1. HACS > the three dots > **Custom repositories**, add this repository's URL as type **Integration**.
2. Install **Cloudflare Monitor**, then restart Home Assistant.
3. **Settings > Devices & services > Add integration > Cloudflare Monitor**, paste the token.

### By hand
Copy `custom_components/cloudflare_monitor` into your Home Assistant `config/custom_components/` folder, restart, then add the integration as above.

## Options

**Settings > Devices & services > Cloudflare Monitor > Configure**
- How often to check (default every 5 minutes)
- Which sources to watch (Access logins, tunnel visitors, tunnel connectors)
- Whether an IP is "new" for the whole account (default) or separately for each app or hostname
- Show a Home Assistant notification for each new IP
- Trusted IPs that never alert (your home IP, office, ranges like `192.0.2.0/24`)
- Optional ipinfo.io token (free) if you see a lot of new IPs

## Phone alert with a Block button

`blueprints/automation/cloudflare_monitor/new_ip_alert.yaml` sends the alert to your phone with **Block IP** and **Looks fine** buttons. Import it from **Settings > Automations & scenes > Blueprints > Import blueprint** with the file's GitHub URL, then create an automation from it and pick your phone.

## Limits worth knowing
- Cloudflare's tunnel visitor analytics can lag a few minutes, and how far back you can query depends on your plan. On plans that only allow short windows the first check looks back 1 hour instead of 24.
- Very busy hostnames: each check reads up to 2,000 IP/hostname combinations.
- ipinfo.io without a token allows a modest number of lookups per day; only new IPs are looked up, and results are cached.
