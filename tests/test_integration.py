"""End-to-end tests with a mocked Cloudflare API."""

from __future__ import annotations

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import device_registry as dr
from pytest_homeassistant_custom_component.common import MockConfigEntry, async_capture_events
from pytest_homeassistant_custom_component.test_util.aiohttp import AiohttpClientMocker

from custom_components.cloudflare_monitor.const import DOMAIN, EVENT_NEW_IP

API = "https://api.cloudflare.com/client/v4"
ACCT = "acct123"
TUNNEL = "11111111-2222-3333-4444-555555555555"
APP = "app-1"


def ok(result, pages=1):
    return {"success": True, "errors": [], "result": result, "result_info": {"total_pages": pages}}


def mock_cloudflare(mock: AiohttpClientMocker, logins: list, visitors: list) -> None:
    mock.get(f"{API}/accounts", json=ok([{"id": ACCT, "name": "Home"}]))
    mock.get(
        f"{API}/accounts/{ACCT}/cfd_tunnel",
        json=ok(
            [
                {
                    "id": TUNNEL,
                    "name": "home",
                    "status": "healthy",
                    "remote_config": True,
                    "connections": [
                        {"origin_ip": "198.51.100.10", "colo_name": "atl01", "opened_at": "2026-10-17T10:00:00Z"}
                    ],
                }
            ]
        ),
    )
    mock.get(
        f"{API}/accounts/{ACCT}/cfd_tunnel/{TUNNEL}/configurations",
        json=ok({"config": {"ingress": [{"hostname": "ha.example.com", "service": "http://ha:8123"}, {"service": "http_status:404"}]}}),
    )
    mock.put(f"{API}/accounts/{ACCT}/cfd_tunnel/{TUNNEL}/configurations", json=ok({}))
    mock.get(f"{API}/zones", json=ok([{"id": "zone1", "name": "example.com"}]))
    mock.get(f"{API}/zones/zone1/dns_records", json=ok([]))
    mock.get(f"{API}/accounts/{ACCT}/access/apps/{APP}/policies", json=ok([]))
    mock.post(f"{API}/accounts/{ACCT}/access/apps/{APP}/policies", json=ok({"id": "pol1"}))
    mock.get(
        f"{API}/accounts/{ACCT}/access/apps",
        json=ok([{"id": APP, "name": "Home Assistant", "domain": "ha.example.com", "type": "self_hosted"}]),
    )
    mock.get(f"{API}/accounts/{ACCT}/access/logs/access_requests", json=ok(logins))
    mock.post(
        f"{API}/graphql",
        json={"data": {"viewer": {"zones": [{"httpRequestsAdaptiveGroups": visitors}]}}, "errors": None},
    )
    mock.get(f"{API}/accounts/{ACCT}/firewall/access_rules/rules", json=ok([]))
    mock.post(f"{API}/accounts/{ACCT}/firewall/access_rules/rules", json=ok({"id": "rule1"}))
    mock.get(
        "https://ipinfo.io/81.2.69.160/json",
        json={"ip": "81.2.69.160", "city": "Lisbon", "region": "Lisbon", "country": "PT", "org": "AS1234 Example ISP"},
    )


def login(ip: str, when: str, allowed: bool = True) -> dict:
    return {
        "ip_address": ip, "user_email": "user@example.com", "app_uid": APP,
        "app_domain": "ha.example.com", "allowed": allowed, "created_at": when,
        "connection": "google", "action": "login", "ray_id": "abc",
    }


def visitor(ip: str, count: int = 3) -> dict:
    return {
        "count": count,
        "dimensions": {
            "clientIP": ip, "clientRequestHTTPHost": "ha.example.com",
            "clientCountryName": "US", "clientAsn": 7922, "clientASNDescription": "COMCAST",
            "userAgent": "Home Assistant/2026.10 iOS", "edgeResponseStatus": 200,
        },
    }


async def test_config_flow(hass: HomeAssistant, aioclient_mock: AiohttpClientMocker) -> None:
    mock_cloudflare(aioclient_mock, [], [])
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})
    assert result["type"] is FlowResultType.FORM
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"api_token": "tok"})
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"]["account_id"] == ACCT
    assert result["title"] == "Home"


async def test_new_ip_alert_and_actions(hass: HomeAssistant, aioclient_mock: AiohttpClientMocker) -> None:
    mock_cloudflare(aioclient_mock, [login("192.0.2.1", "2026-10-17T09:00:00Z")], [visitor("192.0.2.2")])
    entry = MockConfigEntry(
        domain=DOMAIN, unique_id=ACCT,
        data={"api_token": "tok", "account_id": ACCT, "account_name": "Home"},
    )
    entry.add_to_hass(hass)
    events = async_capture_events(hass, EVENT_NEW_IP)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    # First poll only learns what is already there
    assert events == []
    assert hass.states.get("sensor.cloudflare_home_known_ips").state == "3"
    assert hass.states.get("binary_sensor.tunnel_home_connected").state == "on"
    assert hass.states.get("sensor.access_app_home_assistant_last_login_ip").state == "192.0.2.1"

    # A login from a new IP, plus a repeat visitor that is already known
    aioclient_mock.clear_requests()
    mock_cloudflare(
        aioclient_mock,
        [login("192.0.2.1", "2026-10-17T09:00:00Z"), login("81.2.69.160", "2026-10-17T11:00:00Z", allowed=False)],
        [visitor("192.0.2.2")],
    )
    await entry.runtime_data.async_refresh()
    await hass.async_block_till_done()

    assert len(events) == 1
    data = events[0].data
    assert data["ip"] == "81.2.69.160"
    assert data["city"] == "Lisbon"
    assert data["isp"] == "AS1234 Example ISP"
    assert data["login_allowed"] is False
    assert data["user_email"] == "user@example.com"
    assert hass.states.get("sensor.cloudflare_home_last_new_ip").state == "81.2.69.160"
    assert hass.states.get("sensor.cloudflare_home_denied_logins_last_24_hours").state == "1"
    assert len(hass.states.async_all("persistent_notification")) >= 0

    # Block the IP
    await hass.services.async_call(DOMAIN, "block_ip", {"ip": "81.2.69.160", "note": "test"}, blocking=True)
    posts = [c for c in aioclient_mock.mock_calls if c[0] == "POST" and "access_rules" in str(c[1])]
    assert posts and posts[-1][2]["configuration"] == {"target": "ip", "value": "81.2.69.160"}

    devices = dr.async_get(hass)
    app_device = devices.async_get_device({(DOMAIN, f"app_{APP}")})
    tunnel_device = devices.async_get_device({(DOMAIN, f"tunnel_{TUNNEL}")})

    # Lock the Access app
    await hass.services.async_call(DOMAIN, "lock_access_app", {"device_id": app_device.id}, blocking=True)
    posts = [c for c in aioclient_mock.mock_calls if c[0] == "POST" and "policies" in str(c[1])]
    assert posts[-1][2]["decision"] == "deny"
    assert hass.states.get("binary_sensor.access_app_home_assistant_logins").state == "off"

    # Disable, then re-enable the tunnel
    await hass.services.async_call(DOMAIN, "disable_tunnel", {"device_id": tunnel_device.id}, blocking=True)
    puts = [c for c in aioclient_mock.mock_calls if c[0] == "PUT"]
    assert puts[-1][2] == {"config": {"ingress": [{"service": "http_status:503"}]}}
    assert hass.states.get("binary_sensor.tunnel_home_disabled_from_home_assistant").state == "on"

    await hass.services.async_call(DOMAIN, "enable_tunnel", {"device_id": tunnel_device.id}, blocking=True)
    puts = [c for c in aioclient_mock.mock_calls if c[0] == "PUT"]
    assert puts[-1][2]["config"]["ingress"][0]["hostname"] == "ha.example.com"
    assert hass.states.get("binary_sensor.tunnel_home_disabled_from_home_assistant").state == "off"


def test_notification_shows_outside_text_literally() -> None:
    """A hostile user agent or reverse DNS name must not render as a link or image."""
    from custom_components.cloudflare_monitor.coordinator import _notification_text

    text = _notification_text(
        {
            "source": "Tunnel visitor", "source_type": "tunnel_visitor", "name": "home",
            "hostname": "ha.example.com", "ip": "81.2.69.160", "already_blocked": False,
            "city": "", "region": "", "country": "PT",
            "isp": "AS1 [click](https://evil.example)", "reverse_dns": "![x](https://evil.example/t.png)",
            "user_email": "", "login_allowed": None, "requests": 1, "http_statuses": [200],
            "user_agents": ["`code` breaker\n# heading"], "seen_at": "2026-10-17T11:00:00Z",
            "abuseipdb_url": "https://www.abuseipdb.com/check/81.2.69.160",
            "ipinfo_url": "https://ipinfo.io/81.2.69.160",
        }
    )
    assert "`AS1 [click](https://evil.example)`" in text
    assert "`![x](https://evil.example/t.png)`" in text
    assert "`'code' breaker # heading`" in text


async def test_visitor_query_drops_fields_the_plan_does_not_allow() -> None:
    """Free plan zones reject clientAsn; the query retries without it."""
    from datetime import UTC, datetime

    from custom_components.cloudflare_monitor.api import CloudflareClient

    client = CloudflareClient(None, "tok", ACCT)
    queries: list[str] = []

    async def fake_request(method, path, *, params=None, body=None):
        queries.append(body["query"])
        if "clientAsn " in body["query"]:
            return {"data": None, "errors": [{"message": "zone 'zone1' does not have access to the field 'clientasn' from the path"}]}
        return {"data": {"viewer": {"zones": [{"httpRequestsAdaptiveGroups": [visitor("192.0.2.9")]}]}}, "errors": None}

    client._request = fake_request
    now = datetime.now(UTC)
    rows = await client.visitors_by_ip("zone1", ["ha.example.com"], now, now)
    assert rows[0]["dimensions"]["clientIP"] == "192.0.2.9"
    assert len(queries) == 2
    assert "clientAsn " not in queries[1] and "clientIP" in queries[1]

    # The denied field is remembered, so the next poll asks once
    await client.visitors_by_ip("zone1", ["ha.example.com"], now, now)
    assert len(queries) == 3
