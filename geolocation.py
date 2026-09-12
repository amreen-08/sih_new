"""
geolocation.py
--------------
Step 4 of the pipeline.

Given a public IP, returns where it's physically located (country,
region, city, lat/lon). Used later to plot the hop-by-hop trace on a
map and to catch geographically implausible jumps (e.g. Germany to
Brazil in the same few seconds).

Uses ip-api.com's free JSON endpoint - no API key required, generous
enough free-tier rate limit (45 requests/min) for a hackathon demo.
For a production build, swap this out for MaxMind's GeoLite2 database
(offline, no rate limit, mention this upgrade path in your PPT).

Every call is wrapped so a network failure or rate-limit never crashes
the pipeline - it just returns a result with "status": "error" and the
rest of the pipeline treats that as "location unknown" instead of dying.
"""

import requests

IP_API_URL = "http://ip-api.com/json/{ip}"
FIELDS = "status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query"
TIMEOUT_SECONDS = 5

# Simple in-memory cache so the same IP (very common - e.g. a shared relay)
# isn't looked up twice in one run. Fine for a demo/single script run;
# swap for a real cache (redis, sqlite) if this becomes a long-running service.
_cache: dict[str, dict] = {}


def geolocate_ip(ip: str) -> dict:
    """
    Returns a dict like:
    {
        "ip": "203.0.113.5",
        "status": "success",
        "country": "United States",
        "country_code": "US",
        "region": "Virginia",
        "city": "Ashburn",
        "lat": 39.0438,
        "lon": -77.4874,
        "isp": "Amazon.com, Inc.",
        "org": "AWS EC2",
        "as": "AS14618 Amazon.com, Inc."
    }
    On failure: {"ip": ip, "status": "error", "error": "<reason>"}
    """
    if ip in _cache:
        return _cache[ip]

    try:
        response = requests.get(
            IP_API_URL.format(ip=ip),
            params={"fields": FIELDS},
            timeout=TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()

        if data.get("status") != "success":
            result = {"ip": ip, "status": "error", "error": data.get("message", "lookup failed")}
        else:
            result = {
                "ip": ip,
                "status": "success",
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as"),
            }
    except requests.exceptions.RequestException as e:
        result = {"ip": ip, "status": "error", "error": str(e)}

    _cache[ip] = result
    return result


def geolocate_many(ips: list[str]) -> dict[str, dict]:
    """Geolocate a list of unique IPs, returned as {ip: result_dict}."""
    return {ip: geolocate_ip(ip) for ip in ips}


if __name__ == "__main__":
    print(geolocate_ip("8.8.8.8"))
