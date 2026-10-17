"""IP location lookups (ipinfo.io). Only called once per new IP."""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

import aiohttp

_LOGGER = logging.getLogger(__name__)

TIMEOUT = aiohttp.ClientTimeout(total=10)


def is_public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


async def lookup_ip(
    session: aiohttp.ClientSession, ip: str, token: str | None
) -> dict[str, Any]:
    """Return city, region, country, org (ISP / ASN), hostname, timezone.

    Works without a token for light use; a free ipinfo.io token raises the limit.
    Returns an empty dict if the lookup fails, so alerts still go out.
    """
    if not is_public_ip(ip):
        return {"note": "private or reserved address"}
    params = {"token": token} if token else None
    try:
        async with session.get(
            f"https://ipinfo.io/{ip}/json", params=params, timeout=TIMEOUT
        ) as resp:
            if resp.status != 200:
                _LOGGER.debug("ipinfo.io returned %s for %s", resp.status, ip)
                return {}
            data = await resp.json(content_type=None)
    except (aiohttp.ClientError, TimeoutError, ValueError) as err:
        _LOGGER.debug("ipinfo.io lookup for %s failed: %s", ip, err)
        return {}
    return {
        key: data[key]
        for key in ("hostname", "city", "region", "country", "loc", "org", "timezone")
        if data.get(key)
    }
