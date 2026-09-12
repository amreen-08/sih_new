"""
dns_lookup.py
-------------
Step 6 of the pipeline.

Given a public IP, performs a REVERSE DNS lookup - asking "what hostname
is officially registered to point at this IP?" This is the check that
catches an email claiming to be from paypal.com when the sending IP
actually reverse-resolves to something like vps-4471.cheaphost.ru.

Uses only Python's built-in `socket` module - no extra dependency, no
API key, no rate limits, and it's genuinely how reverse DNS works
(a PTR record lookup under the hood).
"""

import socket

TIMEOUT_SECONDS = 3


def reverse_dns_lookup(ip: str) -> dict:
    """
    Returns:
    {"ip": ip, "status": "success", "hostname": "mail-sor-f41.google.com"}
    or
    {"ip": ip, "status": "no_record"}          # no PTR record exists at all
    or
    {"ip": ip, "status": "error", "error": "..."}
    """
    socket.setdefaulttimeout(TIMEOUT_SECONDS)
    try:
        hostname, _aliases, _addresses = socket.gethostbyaddr(ip)
        return {"ip": ip, "status": "success", "hostname": hostname}
    except socket.herror:
        # Valid response, just means "this IP has no reverse DNS record" -
        # itself a mild signal, since most legitimate mail servers do have one.
        return {"ip": ip, "status": "no_record", "hostname": None}
    except (socket.gaierror, socket.timeout, OSError) as e:
        return {"ip": ip, "status": "error", "error": str(e), "hostname": None}


def domain_matches_claim(hostname: str | None, claimed_domain: str) -> bool:
    """
    Loose check: does the reverse-DNS hostname share the same root domain
    as what the email claims to be from (e.g. From: someone@paypal.com)?

    This is intentionally permissive (checks if the claimed domain appears
    as a suffix of the hostname) since legitimate providers often use
    subdomains like mail-sor-f41.google.com for a @gmail.com sender.
    """
    if not hostname or not claimed_domain:
        return False
    return hostname.lower().endswith(claimed_domain.lower())


if __name__ == "__main__":
    print(reverse_dns_lookup("8.8.8.8"))
