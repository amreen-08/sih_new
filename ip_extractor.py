"""
ip_extractor.py
----------------
Step 2 of the pipeline.

NOTE ON THIS FILE: this module was referenced by main.py's import list but
did not actually make it into the upload batch. It has been rebuilt here
from the exact contract the rest of the pipeline already assumes:

    - main.py calls extract_hops(parsed["received_headers"]) and feeds the
      result straight into ip_validator.validate_hops().
    - ip_validator/infrastructure/report.py all expect each hop dict to
      carry at least "hop" (1-indexed position, hop 1 = newest/closest to
      the recipient) and "ip" (may be None if no address could be found
      in that particular Received: header).

Given a raw string from a `Received:` header, pulls out the IP address of
the machine that connected to hand off the message. A typical header looks
like:

    Received: from mail.example.com (mail-relay.example.com [203.0.113.5])
        by mx.google.com with ESMTPS id abc123
        for <user@gmail.com>;
        Thu, 03 Sep 2026 08:15:10 -0700

The address that matters forensically is the one inside the square
brackets after "from ... (" - that's the IP the receiving server actually
saw the connection come from (the hostname next to it can be forged by
whoever controls that hostname's forward DNS, the bracketed IP can't be).
This module deliberately only extracts; it does not decide whether that
IP is public/private/valid - that's ip_validator.py's job.
"""

import re

# Preferred pattern: an IPv4 address inside square brackets, e.g. [203.0.113.5]
# or [203.0.113.5:25] (some MTAs append a port). This is the most reliable
# signal because it's what the receiving MTA itself recorded about the
# connecting socket, not something copy-pasted from a hostname.
_BRACKETED_IP_PATTERN = re.compile(
    r"\[(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?\]"
)

# Fallback: an IPv4 address in parentheses, e.g. (203.0.113.5), used by a
# handful of MTAs instead of square brackets.
_PARENTHESIZED_IP_PATTERN = re.compile(
    r"\((\d{1,3}(?:\.\d{1,3}){3})\)"
)

# Last-resort fallback: any bare IPv4-looking token anywhere in the header.
_BARE_IP_PATTERN = re.compile(
    r"\b(\d{1,3}(?:\.\d{1,3}){3})\b"
)

# IPv6 addresses in brackets, e.g. [2001:db8::1]. Kept separate from the
# IPv4 patterns above so we don't accidentally treat a mangled IPv4 match
# as IPv6 or vice versa.
_BRACKETED_IPV6_PATTERN = re.compile(
    r"\[([0-9a-fA-F:]{3,45})\]"
)


def _looks_like_ipv4(candidate: str) -> bool:
    """Cheap sanity check: each octet must be 0-255."""
    parts = candidate.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def extract_ip_from_header(received_header: str) -> str | None:
    """
    Pull the single most-likely connecting IP out of one Received: header.

    Tries, in order of trustworthiness:
        1. IPv4 in square brackets - [x.x.x.x]
        2. IPv4 in parentheses - (x.x.x.x)
        3. IPv6 in square brackets - [xxxx::xxxx]
        4. any bare IPv4-looking token in the header text

    Returns None if nothing IP-shaped was found at all (common for the
    innermost hop, which is often just "Received: by 10.x.x.x with SMTP id
    ..." from Google's internal, non-routable infrastructure).
    """

    if not received_header:
        return None

    bracketed = _BRACKETED_IP_PATTERN.search(received_header)
    if bracketed and _looks_like_ipv4(bracketed.group(1)):
        return bracketed.group(1)

    parenthesized = _PARENTHESIZED_IP_PATTERN.search(received_header)
    if parenthesized and _looks_like_ipv4(parenthesized.group(1)):
        return parenthesized.group(1)

    ipv6 = _BRACKETED_IPV6_PATTERN.search(received_header)
    if ipv6 and ":" in ipv6.group(1):
        return ipv6.group(1)

    bare = _BARE_IP_PATTERN.search(received_header)
    if bare and _looks_like_ipv4(bare.group(1)):
        return bare.group(1)

    return None


def extract_hops(received_headers: list[str]) -> list[dict]:
    """
    Turn the raw list of Received: header strings (already ordered
    newest-first by email_parser.py) into a hop-numbered list ready for
    ip_validator.py.

    Returns:
        [
            {"hop": 1, "ip": "203.0.113.5", "raw_header": "..."},
            {"hop": 2, "ip": None,          "raw_header": "..."},
            ...
        ]
    """

    hops = []

    for index, header in enumerate(received_headers, start=1):
        hops.append(
            {
                "hop": index,
                "ip": extract_ip_from_header(header),
                "raw_header": header,
            }
        )

    return hops


if __name__ == "__main__":
    sample_header = (
        "from mail-relay.example.com (mail-relay.example.com [8.8.8.8]) "
        "by mx.google.com with ESMTPS id abc123 for <user@gmail.com>; "
        "Thu, 03 Sep 2026 08:15:10 -0700"
    )
    print(extract_hops([sample_header]))
