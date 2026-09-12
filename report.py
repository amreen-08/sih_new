"""
report.py
---------
Turns the pipeline's JSON result into a clean, human-readable report for
the terminal - the kind of thing you'd actually want to screenshot for a
PPT slide or read out loud during a demo, instead of squinting at a wall
of raw JSON.

The JSON output from main.py isn't going away - other teammates' modules
(fraud scoring, the blockchain evidence log, the dashboard) still need
that machine-readable shape. This is purely an additional, human-facing
view on top of the same data - run with `--report` instead of the
default JSON mode.
"""

import shutil

# ANSI color codes. Kept simple and dependency-free (no `colorama`/`rich`)
# on purpose - one less thing that can fail to install on someone's laptop
# five minutes before a demo.
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_GREEN = "\033[32m"
_CYAN = "\033[36m"

_RISK_COLOR = {"high": _RED, "medium": _YELLOW, "low": _GREEN}
_CLASSIFICATION_COLOR = {
    "Critical Risk": _RED, "High Risk": _RED,
    "Medium Risk": _YELLOW, "Low Risk": _GREEN,
}
_AUTH_COLOR = {"pass": _GREEN, "fail": _RED, "none": _YELLOW, "unsigned": _YELLOW,
               "unverified": _YELLOW, "softfail": _YELLOW, "neutral": _YELLOW, "unknown": _DIM}


def _c(text: str, color: str, use_color: bool) -> str:
    """Wrap `text` in an ANSI color code. Coloring is applied to the text
    BEFORE any padding/alignment happens elsewhere, so padding widths are
    never thrown off by invisible escape codes."""
    if not use_color or not color:
        return text
    return f"{color}{text}{_RESET}"


def _rule(width: int, char: str = "-") -> str:
    return char * width


def _wrap_bullet(text: str, width: int, indent: str = "   ") -> str:
    """Word-wrap a single bullet point to `width` columns, indenting continuation lines."""
    words = text.split()
    lines, current = [], indent
    for word in words:
        candidate = f"{current} {word}" if current.strip() else f"{current}{word}"
        if len(candidate) > width and current.strip():
            lines.append(current)
            current = f"{indent}{word}"
        else:
            current = candidate
    if current.strip():
        lines.append(current)
    return "\n".join(lines)


def _pad(text: str, width: int) -> str:
    """Left-justify plain (uncolored) text to `width`. Always call this
    BEFORE wrapping the result in _c() - padding colored text directly
    would count the invisible ANSI escape codes as visible characters
    and break column alignment."""
    return text.ljust(width)


def format_report(result: dict, use_color: bool = True) -> str:
    width = min(shutil.get_terminal_size(fallback=(100, 24)).columns, 100)
    lines = []

    def header(title: str):
        lines.append("")
        lines.append(_c(title, _BOLD + _CYAN, use_color))
        lines.append(_c(_rule(width), _DIM, use_color))

    # --- Title ---
    lines.append(_c("=" * width, _CYAN, use_color))
    lines.append(_c("EMAIL FORENSICS REPORT".center(width), _BOLD + _CYAN, use_color))
    lines.append(_c("=" * width, _CYAN, use_color))

    # --- Email metadata ---
    email = result.get("email", {})
    lines.append(f"{_c(_pad('Subject:', 14), _BOLD, use_color)} {email.get('subject', '(none)')}")
    lines.append(
        f"{_c(_pad('From:', 14), _BOLD, use_color)} {email.get('from_address', '(none)')}  "
        f"{_c('(domain: ' + str(email.get('from_domain')) + ')', _DIM, use_color)}"
    )
    lines.append(f"{_c(_pad('Date:', 14), _BOLD, use_color)} {email.get('date', '(none)')}")
    lines.append(f"{_c(_pad('Message-ID:', 14), _BOLD, use_color)} {email.get('message_id', '(none)')}")

    # --- Risk verdict, front and center ---
    # fraud_classification is the single authoritative verdict: the
    # indicator-based risk_level signal is no longer a separate,
    # potentially-disagreeing label - it's folded directly into the
    # weighted fraud_score itself as indicator_score (see fraud_score.py),
    # so fraud_classification already reflects it. risk_level is still
    # shown below as one of the contributing inputs, not a competing verdict.
    fraud_score = result.get("fraud_score")
    fraud_classification = result.get("fraud_classification")
    risk = (result.get("risk_level") or "unknown").lower()

    lines.append("")
    if fraud_score is not None and fraud_classification:
        classification_color = _CLASSIFICATION_COLOR.get(fraud_classification, _DIM)
        lines.append(_c(f"  VERDICT: {fraud_classification.upper()}  (fraud score {fraud_score}/100)  ", _BOLD + classification_color, use_color))
        lines.append(_c(f"  (includes the indicator-based risk_level signal: {risk.upper()} - see breakdown below)", _DIM, use_color))
    else:
        risk_color = _RISK_COLOR.get(risk, _DIM)
        lines.append(_c(f"  RISK LEVEL: {risk.upper()}  ", _BOLD + risk_color, use_color))
        lines.append(_c("  (fraud_score not yet set - pending the NLP/ML module)", _DIM, use_color))

    breakdown = result.get("fraud_score_breakdown")
    if breakdown:
        weights = breakdown.get("weights", {})
        lines.append(_c(
            f"  geo {breakdown.get('geo_score', 0):.0f}×{weights.get('geo', 0):.2f}  +  "
            f"attachment {breakdown.get('attachment_score', 0):.0f}×{weights.get('attachment', 0):.2f}  +  "
            f"campaign {breakdown.get('campaign_score', 0):.0f}×{weights.get('campaign', 0):.2f}  +  "
            f"indicator {breakdown.get('indicator_score', 0):.0f}×{weights.get('indicator', 0):.2f}",
            _DIM, use_color,
        ))

    # --- Origin trace ---
    header("ORIGIN TRACE")
    geo = result.get("geo") or {}
    lines.append(f"{_c(_pad('Sender IP:', 16), _BOLD, use_color)} {result.get('sender_ip') or 'unknown'}")
    location = ", ".join(v for v in (geo.get("city"), geo.get("country")) if v) or "unknown"
    lines.append(f"{_c(_pad('Location:', 16), _BOLD, use_color)} {location}")

    hop_trace = result.get("hop_trace", [])
    if hop_trace:
        col_widths = (5, 16, 14, 28, 10)
        headers_row = ("Hop", "IP", "Country", "ISP / ASN Owner", "Matches?")
        lines.append("")
        lines.append(_c(
            " ".join(_pad(h, w) for h, w in zip(headers_row, col_widths)),
            _BOLD, use_color,
        ))
        for hop in hop_trace:
            if "note" in hop:
                row_plain = " ".join(_pad(v, w) for v, w in zip(
                    (str(hop.get("hop")), "(internal)", "-", "-", "-"), col_widths
                ))
                lines.append(_c(row_plain, _DIM, use_color))
                continue

            matches = hop.get("hostname_matches_claimed_domain")
            match_str = "Yes" if matches else "No"
            owner = hop.get("asn_description") or hop.get("isp") or "unknown"
            if len(owner) > col_widths[3] - 2:
                owner = owner[: col_widths[3] - 4] + ".."

            cells = [
                _pad(str(hop.get("hop")), col_widths[0]),
                _pad(hop.get("ip") or "unknown", col_widths[1]),
                _pad(hop.get("country") or "unknown", col_widths[2]),
                _pad(owner, col_widths[3]),
                _c(_pad(match_str, col_widths[4]), _GREEN if matches else _RED, use_color),
            ]
            lines.append(" ".join(cells))

    # --- Authentication ---
    header("AUTHENTICATION  (SPF / DKIM / DMARC)")
    for label, key in (("SPF", "spf"), ("DKIM", "dkim"), ("DMARC", "dmarc")):
        entry = result.get(key) or {}
        verdict = (entry.get("result") or "unknown").lower()
        color = _AUTH_COLOR.get(verdict, _DIM)
        source = entry.get("source", "unknown")
        lines.append(
            f"{_pad(label, 8)} {_c(_pad(verdict.upper(), 10), color, use_color)} "
            f"{_c('(source: ' + source + ')', _DIM, use_color)}"
        )

    # --- Attachments ---
    attachments_block = result.get("attachments") or {}
    attachment_count = attachments_block.get("attachment_count", 0)
    header(f"ATTACHMENTS ({attachment_count})")
    if attachment_count == 0:
        lines.append(_c("  No attachments on this message.", _DIM, use_color))
    else:
        summary = attachments_block.get("summary", {})
        summary_bits = [
            f"{summary.get('executable_attachments', 0)} executable",
            f"{summary.get('macro_attachments', 0)} macro-bearing",
            f"{summary.get('script_attachments', 0)} script",
            f"{summary.get('signature_mismatches', 0)} signature mismatch",
        ]
        lines.append(_c("  " + ", ".join(summary_bits), _DIM, use_color))
        lines.append("")

        for attachment in attachments_block.get("attachments", []):
            risky = bool(attachment.get("forensic_indicators"))
            name_color = _RED if risky else _GREEN
            lines.append(
                f"  {_c(attachment.get('filename', '(unnamed)'), _BOLD + name_color, use_color)} "
                f"{_c('(' + attachment.get('detected_mime_type', 'unknown') + ', ' + str(attachment.get('size', 0)) + ' bytes, sha256 ' + attachment.get('sha256', '')[:12] + '...)', _DIM, use_color)}"
            )
            for finding in attachment.get("forensic_indicators", []):
                lines.append(_wrap_bullet(f"- {finding}", width, indent="      "))
            if not attachment.get("forensic_indicators"):
                lines.append(_c("      No red flags found in static analysis.", _GREEN, use_color))
            lines.append("")

    # --- Campaign correlation ---
    campaign = result.get("campaign_correlation") or {}
    if campaign:
        mode = campaign.get("mode", "single")
        mode_label = "batch (correlated against related .eml files)" if mode == "batch" else "single-email heuristics only"
        header(f"CAMPAIGN CORRELATION ({mode_label})")
        for reason in campaign.get("reasons", []):
            lines.append(_wrap_bullet(f"- {reason}", width))

    # --- Indicators ---
    indicators = result.get("indicators", [])
    header(f"SUSPICIOUS INDICATORS ({len(indicators)})")
    if not indicators:
        lines.append(_c("  None found - this email's headers look clean.", _GREEN, use_color))
    else:
        for i, indicator in enumerate(indicators, start=1):
            lines.append(_wrap_bullet(f"{i}. {indicator}", width))

    lines.append("")
    lines.append(_c("=" * width, _CYAN, use_color))
    return "\n".join(lines)


def print_report(result: dict, use_color: bool = True):
    print(format_report(result, use_color=use_color))


if __name__ == "__main__":
    # Quick manual test with a fabricated result, no pipeline run needed
    sample_result = {
        "email": {
            "subject": "Urgent: verify your account",
            "from_address": "billing@paypa1-secure.com",
            "from_domain": "paypa1-secure.com",
            "date": "Thu, 03 Sep 2026 08:15:10 -0700",
            "message_id": "<abc123@paypa1-secure.com>",
        },
        "sender_ip": "8.8.8.8",
        "geo": {"country": "United States", "city": "Ashburn"},
        "hop_trace": [
            {"hop": 1, "ip": None, "note": "skipped - not a public IP"},
            {"hop": 2, "ip": "8.8.8.8", "country": "United States", "asn_description": "AS15169 Google LLC",
             "hostname_matches_claimed_domain": False},
        ],
        "spf": {"result": "fail", "source": "live-dns-spf"},
        "dkim": {"result": "unsigned", "source": "live-dkim-check"},
        "dmarc": {"result": "none", "source": "live-dns-dmarc"},
        "indicators": ["SPF check returned 'fail' - the sending server is not authorized.",
                       "Message has no DKIM signature at all."],
        "risk_level": "high",
        "fraud_score": None,
    }
    print_report(sample_result)
