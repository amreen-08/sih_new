"""
infrastructure.py
------------------
Step 7 of the pipeline.

NOTE ON THIS FILE: also imported by main.py/main_2.py but missing from the
upload, and rebuilt here from the contract the rest of the codebase already
depends on:

    - main.py:   build_hop_profile(hop, geo_result, asn_result, dns_result,
                 claimed_domain) is called once per traceable hop.
    - main.py:   analyze_infrastructure(hop_profiles, claimed_domain)
                 returns {"indicators": [...], "risk_level": "low"|"medium"|"high"}.
    - main_2.py: risk_level_from_indicators(all_indicators) is called a
                 SECOND time after infra indicators are combined with the
                 SPF/DKIM/DMARC indicators from auth_checker.py, so the
                 final risk_level reflects both signal types together.
    - report.py: reads hop.get("hostname_matches_claimed_domain"),
                 hop.get("asn_description") or hop.get("isp"),
                 hop.get("country"), hop.get("ip"), hop.get("hop").

Combines the per-hop geolocation + ASN + reverse-DNS results into one
flat hop profile, then looks across all hops for the infrastructure-level
red flags that matter for phishing/BEC triage: origin traffic riding on
throwaway cloud/VPS infrastructure instead of a real corporate mail
server, a sending IP whose reverse DNS doesn't match what the email
claims to be from, hops with no reverse DNS record at all, and lookups
that failed outright (treated as a weak signal, not a strong one - a
failed API call is not evidence of fraud by itself).
"""

from dns_lookup import domain_matches_claim


# ============================================================
# HOP PROFILE
# ============================================================

def build_hop_profile(
    hop: dict,
    geo_result: dict,
    asn_result: dict,
    dns_result: dict,
    claimed_domain: str,
) -> dict:
    """
    Flatten one hop's geolocation + ASN + reverse-DNS results into a
    single dict. Only called for hops ip_validator.py marked traceable
    (public IPs) - main.py handles untraceable hops separately.
    """

    hostname = dns_result.get("hostname")

    return {
        "hop": hop["hop"],
        "ip": hop["ip"],
        "classification": hop.get("classification"),

        # --- geolocation ---
        "geo_status": geo_result.get("status"),
        "country": geo_result.get("country"),
        "country_code": geo_result.get("country_code"),
        "region": geo_result.get("region"),
        "city": geo_result.get("city"),
        "lat": geo_result.get("lat"),
        "lon": geo_result.get("lon"),
        "isp": geo_result.get("isp"),
        "org": geo_result.get("org"),

        # --- ASN / ownership ---
        "asn_status": asn_result.get("status"),
        "asn": asn_result.get("asn"),
        "asn_description": asn_result.get("asn_description"),
        "network_name": asn_result.get("network_name"),
        "owner_type": asn_result.get("owner_type"),

        # --- reverse DNS ---
        "dns_status": dns_result.get("status"),
        "hostname": hostname,
        "hostname_matches_claimed_domain": domain_matches_claim(
            hostname, claimed_domain
        ),
    }


# ============================================================
# INFRASTRUCTURE-LEVEL ANALYSIS
# ============================================================

def analyze_infrastructure(hop_profiles: list[dict], claimed_domain: str) -> dict:
    """
    Look across every traceable hop for infrastructure red flags and
    produce the plain-English indicator strings the rest of the pipeline
    (report.py, fraud_score.py) surfaces to a human.
    """

    indicators = []

    traceable_profiles = [h for h in hop_profiles if "country" in h]

    if not traceable_profiles:
        indicators.append(
            "No public IP could be traced in the hop chain - the true "
            "origin of this message could not be located."
        )
        return {
            "indicators": indicators,
            "risk_level": risk_level_from_indicators(indicators),
        }

    # The true original sender is the LAST traceable hop (oldest, closest
    # to the real source) - see main.py's comment on the same convention.
    origin_hop = traceable_profiles[-1]

    # --------------------------------------------------------
    # 1. Origin IP belongs to a cloud/hosting provider
    # --------------------------------------------------------
    if origin_hop.get("owner_type") == "hosting_provider":
        owner = origin_hop.get("asn_description") or origin_hop.get("isp") or "an unknown provider"
        indicators.append(
            f"Original sending IP ({origin_hop.get('ip')}) belongs to a "
            f"cloud/hosting provider ({owner}) rather than typical "
            f"residential or corporate mail infrastructure - this is "
            f"common infrastructure for disposable phishing campaigns."
        )

    # --------------------------------------------------------
    # 2. Reverse DNS hostname doesn't match the claimed sender domain
    # --------------------------------------------------------
    if origin_hop.get("dns_status") == "success":
        if not origin_hop.get("hostname_matches_claimed_domain"):
            indicators.append(
                f"Reverse DNS for the originating IP resolves to "
                f"'{origin_hop.get('hostname')}', which does not match "
                f"the claimed sending domain '{claimed_domain}'."
            )
    elif origin_hop.get("dns_status") == "no_record":
        indicators.append(
            "Originating IP has no reverse DNS (PTR) record at all - "
            "most legitimate mail servers publish one."
        )

    # --------------------------------------------------------
    # 3. Multiple distinct countries across the hop chain
    # --------------------------------------------------------
    countries = {
        h["country"] for h in traceable_profiles if h.get("country")
    }
    if len(countries) >= 3:
        indicators.append(
            f"Message passed through {len(countries)} different "
            f"countries ({', '.join(sorted(countries))}) across its "
            f"relay chain - an unusually long geographic path."
        )

    # --------------------------------------------------------
    # 4. Lookup failures (weak signal - noted, not scored heavily)
    # --------------------------------------------------------
    failed_lookups = [
        h for h in traceable_profiles
        if h.get("geo_status") == "error" or h.get("asn_status") == "error"
    ]
    if failed_lookups and len(failed_lookups) == len(traceable_profiles):
        indicators.append(
            "All geolocation/ASN lookups failed for this message - "
            "infrastructure could not be independently verified "
            "(this is a tooling limitation, not evidence of fraud)."
        )

    return {
        "indicators": indicators,
        "risk_level": risk_level_from_indicators(indicators),
    }


# ============================================================
# SHARED RISK SCORING
# ============================================================

def risk_level_from_indicators(indicators: list[str]) -> str:
    """
    Turn a flat list of plain-English indicator strings into an overall
    "low" / "medium" / "high" risk level.

    Deliberately simple (count-based) rather than weighted-by-severity -
    main_2.py calls this a second time after combining infrastructure
    indicators with SPF/DKIM/DMARC indicators from auth_checker.py, so
    this function has to work sensibly for indicator lists coming from
    either or both sources.
    """

    count = len(indicators)

    if count == 0:
        return "low"
    if count <= 2:
        return "medium"
    return "high"


if __name__ == "__main__":
    sample_profiles = [
        {
            "hop": 1,
            "ip": "203.0.113.5",
            "country": "Germany",
            "dns_status": "no_record",
            "hostname": None,
            "hostname_matches_claimed_domain": False,
            "owner_type": "hosting_provider",
            "asn_description": "OVH SAS",
            "isp": None,
        }
    ]
    print(analyze_infrastructure(sample_profiles, "paypal.com"))
