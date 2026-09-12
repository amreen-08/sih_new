"""
ip_validator.py
----------------
Step 3 of the pipeline.

NOTE ON THIS FILE: like ip_extractor.py and infrastructure.py, this module
was imported by main.py but never actually arrived in the upload. Rebuilt
here from the contract main.py already relies on:

    validated_hops = validate_hops(hops)
    for hop in validated_hops:
        if not hop["traceable"]:
            ... uses hop["hop"], hop["ip"], hop["classification"] ...
        else:
            ... geolocates hop["ip"] ...

Takes the raw hop list from ip_extractor.py and decides which hops are
actually worth sending out to geolocation/ASN/reverse-DNS lookups. Private,
loopback, link-local, and other non-routable addresses (10.x.x.x,
192.168.x.x, 127.0.0.1, internal mail-relay hops like Google's 10.x.x.x
LAN IPs, etc.) can't be geolocated or WHOIS'd meaningfully - sending them
to those APIs would just waste calls and clutter the trace with noise, so
they're marked untraceable here and skipped downstream instead.
"""

import ipaddress


def classify_ip(ip: str | None) -> str:
    """
    Classify a single IP string into one of:
        "public"    - routable on the public internet, worth tracing
        "private"   - RFC1918 / private range (10.x, 172.16-31.x, 192.168.x)
        "loopback"  - 127.0.0.1 etc.
        "link_local" - 169.254.x.x / fe80::
        "reserved"  - other IANA-reserved / multicast / unspecified ranges
        "invalid"   - not a parseable IP at all
        "unresolved" - no IP could be extracted from that hop's header
    """

    if not ip:
        return "unresolved"

    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"

    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_private:
        return "private"
    if address.is_multicast or address.is_reserved or address.is_unspecified:
        return "reserved"

    return "public"


def validate_hops(hops: list[dict]) -> list[dict]:
    """
    Annotate each hop from ip_extractor.py with a classification and a
    "traceable" flag. Only "public" IPs are traceable - everything else
    (private LAN hops, unresolved headers, malformed addresses) is kept in
    the list for completeness/audit purposes but flagged as not worth
    sending to geolocation/ASN/DNS.

    Input hop shape (from ip_extractor.py):
        {"hop": 1, "ip": "203.0.113.5", "raw_header": "..."}

    Output adds two keys:
        {"hop": 1, "ip": "203.0.113.5", "raw_header": "...",
         "classification": "public", "traceable": True}
    """

    validated = []

    for hop in hops:
        ip = hop.get("ip")
        classification = classify_ip(ip)

        validated.append(
            {
                **hop,
                "classification": classification,
                "traceable": classification == "public",
            }
        )

    return validated


if __name__ == "__main__":
    # Note: 8.8.8.8 is a real, publicly routable IP (Google DNS) used here
    # purely as a demo value - NOT the 203.0.113.0/24 "TEST-NET-3" block,
    # which ipaddress.is_private() correctly treats as non-routable
    # documentation space and would misleadingly show up as "private" here.
    sample_hops = [
        {"hop": 1, "ip": "10.0.0.5", "raw_header": "internal relay"},
        {"hop": 2, "ip": "8.8.8.8", "raw_header": "external relay"},
        {"hop": 3, "ip": None, "raw_header": "no ip found"},
    ]
    for validated_hop in validate_hops(sample_hops):
        print(validated_hop)
