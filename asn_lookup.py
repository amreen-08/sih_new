"""
asn_lookup.py
-------------
Step 5 of the pipeline.

Given a public IP, finds out WHO OWNS it - which ASN (Autonomous System
Number) it belongs to, and the organization registered against that ASN.
This is what lets you tell "residential home internet" apart from
"cloud VPS provider commonly abused for spam/phishing infrastructure".

Primary method: ipwhois (RDAP protocol - the modern replacement for
plain WHOIS, no API key needed, queried directly against the regional
internet registries - ARIN/RIPE/APNIC/etc.).

Fallback: if RDAP fails or ipwhois isn't installed, fall back to the
"as" / "isp" / "org" fields already returned by geolocation.py's ip-api
call, so the pipeline degrades gracefully instead of failing outright.
"""

try:
    from ipwhois import IPWhois
    IPWHOIS_AVAILABLE = True
except ImportError:
    IPWHOIS_AVAILABLE = False

# Keywords commonly seen in ASN/org names for cloud & hosting providers.
# Real infrastructure fingerprinting is more nuanced than this, but a
# keyword match is a fast, explainable heuristic that works well for a demo.
HOSTING_KEYWORDS = [
    "amazon", "aws", "google cloud", "gcp", "microsoft azure", "azure",
    "digitalocean", "linode", "vultr", "ovh", "hetzner", "contabo",
    "hostinger", "godaddy", "namecheap", "cloudflare", "leaseweb",
    "choopa", "psychz", "m247", "scaleway", "oracle cloud", "alibaba cloud",
]


def _classify_owner(org_text: str) -> str:
    org_lower = (org_text or "").lower()
    for keyword in HOSTING_KEYWORDS:
        if keyword in org_lower:
            return "hosting_provider"
    return "isp_or_other"


def asn_lookup(ip: str, fallback_geo_result: dict | None = None) -> dict:
    """
    Returns:
    {
        "ip": ip,
        "status": "success" | "error",
        "asn": "14618",
        "asn_description": "AMAZON-AES, US",
        "network_name": "AMAZON-2011L",
        "owner_type": "hosting_provider" | "isp_or_other",
        "source": "rdap" | "ip-api-fallback"
    }
    """
    if IPWHOIS_AVAILABLE:
        try:
            obj = IPWhois(ip)
            result = obj.lookup_rdap(depth=1)
            asn_description = result.get("asn_description") or ""
            network_name = (result.get("network") or {}).get("name") or ""
            return {
                "ip": ip,
                "status": "success",
                "asn": result.get("asn"),
                "asn_description": asn_description,
                "network_name": network_name,
                "owner_type": _classify_owner(asn_description + " " + network_name),
                "source": "rdap",
            }
        except Exception as e:
            # Fall through to the ip-api based fallback below
            rdap_error = str(e)
    else:
        rdap_error = "ipwhois not installed"

    # --- Fallback path using data geolocation.py already fetched ---
    if fallback_geo_result and fallback_geo_result.get("status") == "success":
        org_text = fallback_geo_result.get("org") or fallback_geo_result.get("isp") or ""
        as_text = fallback_geo_result.get("as") or ""
        return {
            "ip": ip,
            "status": "success",
            "asn": as_text.split(" ")[0].replace("AS", "") if as_text else None,
            "asn_description": as_text,
            "network_name": org_text,
            "owner_type": _classify_owner(org_text + " " + as_text),
            "source": "ip-api-fallback",
        }

    return {
        "ip": ip,
        "status": "error",
        "error": rdap_error,
        "asn": None,
        "asn_description": None,
        "network_name": None,
        "owner_type": "unknown",
        "source": "none",
    }


if __name__ == "__main__":
    print(asn_lookup("8.8.8.8"))
