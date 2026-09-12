"""
email_parser.py
----------------
Step 1 of the pipeline.

Takes a raw .eml file (or raw email text) and pulls out the structural
pieces we need for the rest of the trace-back pipeline:
    - every Received: header, in the order they appear in the file
      (top of file = most recent hop, bottom = oldest/original hop)
    - From / Return-Path / Message-ID / Subject
    - the domain claimed in the From address

This module does NOT touch IPs, geolocation, or anything network-related.
It only parses the email structure. That separation is what lets the
rest of the team build ip_extractor / geolocation / etc. against a
clean, predictable output instead of re-parsing raw email text everywhere.
"""

import re

from email import message_from_string, message_from_file
from email.utils import parseaddr
from email.policy import default as default_policy


# A malformed From/Return-Path header (real example seen in the wild:
# "Microsoft account team ,_<no-reply@access-accsecurity.com>" - the
# unquoted comma before "<...>" is invalid RFC 2822 syntax) makes Python's
# own email.utils.parseaddr() give up entirely and return ("", "") - not
# a partial result, a completely empty one. This isn't rare: some
# phishing kits emit broken headers like this, whether by carelessness or
# as a mild evasion trick against parsers that assume well-formed mail.
# Rather than silently losing the sender on those messages, fall back to
# pulling an address out with a plain regex when parseaddr comes up empty.
_ANGLE_ADDRESS_PATTERN = re.compile(r"<([^<>\s]+@[^<>\s]+)>")
_BARE_ADDRESS_PATTERN = re.compile(r"([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})")


def _parse_address_with_fallback(header_value: str) -> tuple[str, str]:
    """
    Returns (display_name, address), same shape as email.utils.parseaddr().

    Tries the standard library parser first (correctly handles quoted
    display names, comments, etc. on well-formed headers). Only falls
    back to regex extraction when parseaddr returns nothing usable but
    the raw header text clearly contains an email address anyway.
    """
    display_name, address = parseaddr(header_value or "")
    if address:
        return display_name, address

    if not header_value:
        return "", ""

    angle_match = _ANGLE_ADDRESS_PATTERN.search(header_value)
    if angle_match:
        # Whatever came before "<address>" is a best-effort display name -
        # strip common junk (stray commas/underscores) rather than keep it verbatim.
        prefix = header_value[: angle_match.start()].strip(" ,_\"")
        return prefix, angle_match.group(1)

    bare_match = _BARE_ADDRESS_PATTERN.search(header_value)
    if bare_match:
        return "", bare_match.group(1)

    return "", ""


def parse_email_file(file_path: str) -> dict:
    """Parse an .eml file from disk and return the structured header data."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        msg = message_from_file(f, policy=default_policy)
    return _extract(msg)


def parse_email_text(raw_text: str) -> dict:
    """Parse raw email text (already loaded as a string) and return the same structure."""
    msg = message_from_string(raw_text, policy=default_policy)
    return _extract(msg)


def _extract(msg) -> dict:
    # get_all() preserves the order headers appear in the file and
    # returns [] instead of None if the header is missing, which keeps
    # downstream code simple (no None-checking every call site).
    received_headers = msg.get_all("Received", [])

    from_header = msg.get("From", "")
    display_name, from_address = _parse_address_with_fallback(from_header)
    from_domain = from_address.split("@")[-1].lower() if "@" in from_address else ""

    return_path_header = msg.get("Return-Path", "")
    _, return_path_address = _parse_address_with_fallback(return_path_header)
    return_path_domain = return_path_address.split("@")[-1].lower() if "@" in return_path_address else ""

    return {
        "subject": msg.get("Subject", ""),
        "from_display_name": display_name,
        "from_address": from_address,
        "from_domain": from_domain,
        "return_path": return_path_header,
        "return_path_domain": return_path_domain,
        "message_id": msg.get("Message-ID", ""),
        "date": msg.get("Date", ""),
        # Keep this as a plain list of raw strings - ip_extractor.py
        # is responsible for pulling IPs out of each one.
        "received_headers": [str(h) for h in received_headers],
        # NEW: feeds auth_checker.py for the SPF/DKIM/DMARC check. Since
        # we're already parsing every header off this message for the
        # geolocation/IP-trace pipeline, grabbing these two extra ones
        # costs nothing extra.
        "authentication_results_headers": [str(h) for h in msg.get_all("Authentication-Results", [])],
        "dkim_signature_headers": [str(h) for h in msg.get_all("DKIM-Signature", [])],
    }


if __name__ == "__main__":
    # Quick manual test: python email_parser.py sample_email.eml
    import sys
    import json

    path = sys.argv[1] if len(sys.argv) > 1 else "sample_email.eml"
    result = parse_email_file(path)
    print(json.dumps(result, indent=2))
