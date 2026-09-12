"""
attachment_ioc.py
-----------------

Extracts Indicators of Compromise (IOCs) from attachment bytes.

Currently extracts:

    - URLs
    - IPv4 addresses
    - domains

IMPORTANT:

    Extracted URLs/domains are NEVER visited.
"""


import re


# ============================================================
# URL
# ============================================================

URL_PATTERN = re.compile(
    rb"https?://[^\s\"'<>]+",
    re.IGNORECASE,
)


# ============================================================
# IPv4
# ============================================================

IP_PATTERN = re.compile(
    rb"\b"
    rb"(?:(?:25[0-5]|"
    rb"2[0-4][0-9]|"
    rb"1?[0-9]{1,2})\.){3}"
    rb"(?:25[0-5]|"
    rb"2[0-4][0-9]|"
    rb"1?[0-9]{1,2})"
    rb"\b"
)


# ============================================================
# DOMAIN
# ============================================================

DOMAIN_PATTERN = re.compile(
    rb"\b"
    rb"(?:[a-zA-Z0-9]"
    rb"(?:[a-zA-Z0-9-]{0,61}"
    rb"[a-zA-Z0-9])?\.)+"
    rb"[a-zA-Z]{2,63}"
    rb"\b"
)


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(
    data: bytes
) -> list[str]:
    """
    Extract HTTP/HTTPS URLs.

    URLs are returned as strings.

    They are NOT requested or opened.
    """

    matches = URL_PATTERN.findall(
        data
    )

    urls = []

    for match in matches:

        try:

            url = match.decode(
                "utf-8",
                errors="ignore"
            )

            url = url.rstrip(
                ".,;:!?)]}'\""
            )

            if (
                url
                and url not in urls
            ):
                urls.append(url)

        except Exception:
            continue

    return urls[:100]


# ============================================================
# IP EXTRACTION
# ============================================================

def extract_ipv4_addresses(
    data: bytes
) -> list[str]:
    """
    Extract IPv4 addresses from attachment bytes.
    """

    matches = IP_PATTERN.findall(
        data
    )

    ips = []

    for match in matches:

        try:

            ip = match.decode(
                "ascii"
            )

            if ip not in ips:
                ips.append(ip)

        except Exception:
            continue

    return ips[:100]


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def extract_domains(
    data: bytes
) -> list[str]:
    """
    Extract domain-like strings.

    This is pattern-based extraction only.

    It does not verify whether the domains actually exist.
    """

    matches = DOMAIN_PATTERN.findall(
        data
    )

    domains = []

    for match in matches:

        try:

            domain = match.decode(
                "ascii",
                errors="ignore"
            ).lower()

            if domain not in domains:
                domains.append(
                    domain
                )

        except Exception:
            continue

    return domains[:100]


# ============================================================
# COMPLETE IOC EXTRACTION
# ============================================================

def extract_iocs(
    data: bytes
) -> dict:
    """
    Extract all supported IOCs from an attachment.

    Text-oriented IOC extraction is skipped for ZIP/container
    files because raw binary ZIP data can create false-positive
    URLs, IP addresses, and domains.
    """

    # --------------------------------------------------------
    # ZIP CONTAINER CHECK
    # --------------------------------------------------------

    if data.startswith((
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"PK\x07\x08"
    )):

        return {
            "urls": [],
            "ipv4_addresses": [],
            "domains": [],
            "ioc_count": 0,
            "forensic_indicators": [],
        }


    # --------------------------------------------------------
    # NORMAL IOC EXTRACTION
    # --------------------------------------------------------

    urls = extract_urls(
        data
    )

    ips = extract_ipv4_addresses(
        data
    )

    domains = extract_domains(
        data
    )


    # --------------------------------------------------------
    # IOC INDICATORS
    # --------------------------------------------------------

    indicators = []


    if urls:

        indicators.append(
            f"{len(urls)} URL(s) found inside attachment."
        )


    if ips:

        indicators.append(
            f"{len(ips)} IPv4 address(es) found inside attachment."
        )


    if domains:

        indicators.append(
            f"{len(domains)} domain(s) found inside attachment."
        )


    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

    return {

        "urls": urls,

        "ipv4_addresses": ips,

        "domains": domains,

        "ioc_count": (
            len(urls)
            + len(ips)
            + len(domains)
        ),

        "forensic_indicators": indicators,
    }


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    test_data = (
        b"""
        Please visit https://example.com/login
        or contact 192.168.1.100.

        Another domain is suspicious-example.com.
        """
    )

    result = extract_iocs(
        test_data
    )

    print(
        result
    )