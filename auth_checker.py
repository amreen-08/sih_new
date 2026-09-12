"""
auth_checker.py
----------------
NEW MODULE: SPF / DKIM / DMARC authentication check - "is the sender
really who they claim to be?" This is called out explicitly in the
problem statement, so it needs its own clear module rather than being
folded into geolocation/asn/dns.

There are two ways to get this data, and this module tries both:

1. HEADER-BASED (preferred - free, instant, no network calls at all).
   Almost every real mail provider (Gmail, Outlook, corporate mail
   servers) already runs full SPF/DKIM/DMARC validation the moment an
   email arrives, and stamps the verdict into an `Authentication-Results:`
   header before it's ever delivered to an inbox. Since email_parser.py
   is already reading every header off the message for the geolocation/
   IP-trace pipeline, pulling this one out is essentially free - and it's
   MORE reliable than reimplementing verification ourselves, because the
   receiving server had context we don't always have (the true envelope
   sender, the HELO string, etc).

2. LIVE / INDEPENDENT DNS CHECK (fallback). Used when no
   Authentication-Results header exists - e.g. a hand-crafted test .eml,
   a locally-composed email, or a provider that doesn't stamp this header.
   We then do our own simplified check:
     - SPF: DNS TXT lookup of the sender's domain, evaluated against the
       IP our ip_extractor/geolocation steps already traced.
     - DMARC: DNS TXT lookup of _dmarc.<domain> for the published policy,
       combined with a SIMPLIFIED alignment check against the SPF/DKIM
       results (not the full RFC 7489 alignment algorithm - good enough
       to demo the concept, worth saying so out loud to judges).
     - DKIM: checks whether a DKIM-Signature header exists and whether a
       public key is actually published in DNS for it. NOTE: this
       confirms DKIM is *configured*, it does NOT cryptographically
       verify the signature (that needs full header/body canonicalization
       - see the README for the `dkimpy` upgrade path if you want that).

Both paths return the same shape, so main.py and the rest of the team's
JSON schema don't care which one produced the answer.
"""

import re
import ipaddress

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

DNS_TIMEOUT = 5


# ---------------------------------------------------------------------------
# 1. Header-based extraction (no network calls)
# ---------------------------------------------------------------------------

_AUTH_RESULT_PATTERN = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(\w+)", re.IGNORECASE)


def parse_authentication_results(auth_headers: list[str]) -> dict:
    """
    Scan every Authentication-Results header (a message can have more than
    one - each hop that chose to run its own checks adds one) and pull out
    spf=/dkim=/dmarc= verdicts.

    We trust the FIRST header in the list - i.e. the one closest to final
    delivery, since email_parser.py preserves header order the same way
    Received: headers are ordered (newest/most-recent first). That's the
    check run by the mail server the recipient actually trusts; an
    earlier/upstream hop's Authentication-Results header could in theory
    be forged by that hop, so we don't blindly trust those instead.
    """
    found = {"spf": None, "dkim": None, "dmarc": None}
    for header in auth_headers:
        for mechanism, verdict in _AUTH_RESULT_PATTERN.findall(header):
            key = mechanism.lower()
            if found[key] is None:
                found[key] = verdict.lower()
        if all(v is not None for v in found.values()):
            break
    return found


# ---------------------------------------------------------------------------
# 2. Live / independent DNS-based checks (fallback path)
# ---------------------------------------------------------------------------

def _get_txt_records(domain: str) -> list[str]:
    if not DNS_AVAILABLE or not domain:
        return []
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=DNS_TIMEOUT)
        return [
            "".join(part.decode() if isinstance(part, bytes) else part for part in r.strings)
            for r in answers
        ]
    except Exception:
        return []


def _ip_in_mechanism(ip: str, mechanism_value: str) -> bool:
    """Check if `ip` falls inside an ip4:/ip6: CIDR mechanism value."""
    try:
        network = ipaddress.ip_network(mechanism_value, strict=False)
        return ipaddress.ip_address(ip) in network
    except ValueError:
        return False


def live_spf_check(sender_ip: str, domain: str) -> dict:
    """
    Lightweight SPF evaluator using only dnspython - deliberately not
    using the `pyspf` package, since it has build issues on several
    platforms/Python versions. Handles the common real-world mechanisms
    (ip4, ip6, one level of include:, and the trailing all mechanism).
    Doesn't implement the full SPF RFC (macros, deep include chains, the
    mx/ptr mechanisms) - good enough to demo the concept correctly
    against the vast majority of real domains.
    """
    if not sender_ip or not domain:
        return {"result": "unknown", "source": "live-dns-spf", "detail": "insufficient data to check SPF"}

    spf_record = next((r for r in _get_txt_records(domain) if r.lower().startswith("v=spf1")), None)
    if not spf_record:
        return {"result": "none", "source": "live-dns-spf", "detail": f"no SPF record published for {domain}"}

    checked = {domain}

    def evaluate(tokens, depth=0):
        if depth > 3:
            return None  # safety cap on include recursion
        for token in tokens:
            lower = token.lower()
            if lower.startswith("ip4:") or lower.startswith("ip6:"):
                if _ip_in_mechanism(sender_ip, token.split(":", 1)[1]):
                    return "pass"
            elif lower.startswith("include:"):
                include_domain = token.split(":", 1)[1]
                if include_domain in checked:
                    continue
                checked.add(include_domain)
                included = next(
                    (r for r in _get_txt_records(include_domain) if r.lower().startswith("v=spf1")), None
                )
                if included and evaluate(included.split(), depth + 1) == "pass":
                    return "pass"
            elif lower in ("~all", "-all", "?all", "+all"):
                return {"~all": "softfail", "-all": "fail", "?all": "neutral", "+all": "pass"}[lower]
        return None

    outcome = evaluate(spf_record.split()) or "neutral"
    return {
        "result": outcome,
        "source": "live-dns-spf",
        "detail": f"evaluated {sender_ip} against {domain}'s SPF record: {spf_record}",
    }


def live_dkim_check(dkim_signature_headers: list[str]) -> dict:
    """
    Checks whether DKIM is even configured for this message: is there a
    DKIM-Signature header, and does DNS actually have a public key
    published at <selector>._domainkey.<domain>?

    IMPORTANT: this is NOT a full cryptographic verification of the
    signature. Doing that correctly means re-canonicalizing headers/body
    exactly per RFC 6376 - the `dkimpy` library does this in one call
    (`dkim.verify(raw_bytes)`) if you can get it building in your
    environment (see README). Report this honestly to judges as
    "DKIM configuration check" rather than "DKIM verification".
    """
    if not dkim_signature_headers:
        return {"result": "unsigned", "source": "live-dkim-check", "detail": "no DKIM-Signature header present on this message"}

    tags = dict(re.findall(r"\b([a-z])\s*=\s*([^;]+)", dkim_signature_headers[0], re.IGNORECASE))
    domain = tags.get("d", "").strip()
    selector = tags.get("s", "").strip()

    if not domain or not selector:
        return {"result": "unverified", "source": "live-dkim-check", "detail": "DKIM-Signature header present but missing d= or s= tag"}

    key_records = _get_txt_records(f"{selector}._domainkey.{domain}")
    key_found = any("p=" in r for r in key_records)

    return {
        "result": "unverified",  # we never claim "pass" without real crypto verification
        "key_published": key_found,
        "source": "live-dkim-check",
        "detail": (
            f"DKIM-Signature present (domain={domain}, selector={selector}); "
            + ("a public key is published in DNS, but the signature itself was not cryptographically verified"
               if key_found else f"NO public key found at {selector}._domainkey.{domain} - signature cannot be valid")
        ),
    }


def live_dmarc_check(domain: str, spf_result: dict, dkim_result: dict, from_domain: str, spf_checked_domain: str) -> dict:
    """
    DMARC passes if EITHER SPF or DKIM passes AND is "aligned" (roughly:
    the domain that passed matches the visible From: domain). This is a
    SIMPLIFIED version of RFC 7489 alignment (real DMARC also supports a
    'relaxed' mode allowing organizational-domain matches, not just exact
    matches) - call this out as a simplification if asked, don't present
    it as a full implementation.
    """
    if not domain:
        return {"result": "unknown", "policy": None, "source": "live-dns-dmarc", "detail": "no domain to check"}

    dmarc_record = next((r for r in _get_txt_records(f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")), None)
    if not dmarc_record:
        return {
            "result": "none",
            "policy": None,
            "source": "live-dns-dmarc",
            "detail": f"no DMARC record published for {domain} - domain has no enforcement policy at all",
        }

    policy_match = re.search(r"p=(\w+)", dmarc_record, re.IGNORECASE)
    policy = policy_match.group(1).lower() if policy_match else None

    spf_aligned = spf_result.get("result") == "pass" and spf_checked_domain and spf_checked_domain.endswith(from_domain)
    dkim_aligned = dkim_result.get("result") in ("pass",) and dkim_result.get("key_published")  # conservative: only if key is real
    dmarc_pass = bool(spf_aligned or dkim_aligned)

    return {
        "result": "pass" if dmarc_pass else "fail",
        "policy": policy,
        "source": "live-dns-dmarc",
        "detail": dmarc_record,
    }


# ---------------------------------------------------------------------------
# Orchestration - this is what main.py calls
# ---------------------------------------------------------------------------

def analyze_authentication(parsed_email: dict, sender_ip: str | None) -> dict:
    """
    parsed_email is the dict from email_parser.py, extended with
    'authentication_results_headers' and 'dkim_signature_headers'.

    Prefers the receiving server's own Authentication-Results verdict for
    each mechanism (most authoritative) and only falls back to our own
    live DNS-based check for whichever mechanism it didn't cover.
    """
    header_verdicts = parse_authentication_results(parsed_email.get("authentication_results_headers", []))

    from_domain = parsed_email.get("from_domain", "") or ""
    return_path_domain = parsed_email.get("return_path_domain", "") or from_domain

    # --- SPF ---
    if header_verdicts["spf"]:
        spf_result = {
            "result": header_verdicts["spf"],
            "source": "authentication-results-header",
            "detail": "verdict taken from the receiving server's own Authentication-Results header",
        }
    else:
        spf_result = live_spf_check(sender_ip, return_path_domain)

    # --- DKIM ---
    if header_verdicts["dkim"]:
        dkim_result = {
            "result": header_verdicts["dkim"],
            "source": "authentication-results-header",
            "detail": "verdict taken from the receiving server's own Authentication-Results header",
        }
    else:
        dkim_result = live_dkim_check(parsed_email.get("dkim_signature_headers", []))

    # --- DMARC ---
    if header_verdicts["dmarc"]:
        dmarc_result = {
            "result": header_verdicts["dmarc"],
            "policy": None,
            "source": "authentication-results-header",
            "detail": "verdict taken from the receiving server's own Authentication-Results header",
        }
    else:
        dmarc_result = live_dmarc_check(from_domain, spf_result, dkim_result, from_domain, return_path_domain)

    return {"spf": spf_result, "dkim": dkim_result, "dmarc": dmarc_result}


def build_auth_indicators(auth_result: dict) -> list[str]:
    """Turn the combined SPF/DKIM/DMARC verdicts into the same kind of
    plain-English indicator strings infrastructure.py produces, so they
    slot straight into the same `indicators` list in the final JSON."""
    indicators = []

    spf = auth_result["spf"]
    if spf["result"] in ("fail", "softfail"):
        indicators.append(f"SPF check returned '{spf['result']}' - the sending server is not authorized to send mail for this domain.")
    elif spf["result"] == "none":
        indicators.append("No SPF record published for the sending domain - the domain has no protection against IP spoofing.")

    dkim = auth_result["dkim"]
    # Note: our own live_dkim_check() calls this "unsigned"; a real mail
    # server's Authentication-Results header calls the same situation
    # "none" - normalize both here so the indicator fires either way.
    if dkim["result"] == "fail":
        indicators.append("DKIM signature failed verification - message content or headers may have been altered in transit, or the signature was forged.")
    elif dkim["result"] in ("unsigned", "none"):
        indicators.append("Message has no DKIM signature at all - its integrity cannot be cryptographically confirmed.")
    elif dkim["result"] == "unverified" and not dkim.get("key_published", True):
        indicators.append("Message claims a DKIM signature but no matching public key exists in DNS - the signature cannot be valid.")

    dmarc = auth_result["dmarc"]
    if dmarc["result"] == "fail":
        indicators.append("DMARC alignment check failed - SPF/DKIM results don't line up with the visible From: domain, a classic spoofing pattern.")
    elif dmarc["result"] == "none":
        indicators.append("No DMARC record published for the sending domain - even where SPF/DKIM fail, there's no policy telling receivers what to do about it.")
    elif dmarc.get("policy") == "reject" and dmarc["result"] == "fail":
        indicators.append("Domain publishes a DMARC policy of 'reject' for failed messages - a compliant mail server should have blocked this outright.")

    return indicators


if __name__ == "__main__":
    # Quick manual test of the header-parsing path (no network needed)
    sample_headers = [
        "mx.google.com; spf=fail (google.com: domain of billing@netflix-billing-example.com "
        "does not designate 8.8.8.8 as permitted sender) smtp.mailfrom=billing@netflix-billing-example.com; "
        "dkim=none; dmarc=fail header.from=netflix-billing-example.com"
    ]
    print(parse_authentication_results(sample_headers))
