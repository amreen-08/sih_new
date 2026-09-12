"""
main.py
-------
Final orchestrator for the complete email-forensics pipeline. This
combines what used to be two separate, half-overlapping entry points
(one wired up attachment analysis, the other wired up SPF/DKIM/DMARC +
the human-readable --report formatter) into a single pipeline that does
both, plus a real fraud score at the end instead of a "None" placeholder:

    main.py
      -> email_parser        (parse raw .eml into structured headers)
      -> ip_extractor         (pull an IP out of every Received: header)
      -> ip_validator         (drop private/invalid IPs, mark traceable hops)
      -> geolocation           \
      -> asn_lookup             > per traceable hop, independent lookups
      -> dns_lookup             /
      -> infrastructure        (combine hop lookups -> hop profiles + indicators)
      -> auth_checker         (SPF / DKIM / DMARC - "is the sender who they claim?")
      -> attachment_analyzer  (static attachment forensics - no execution)
      -> fraud_score           (weighted 0-100 score across all of the above)
      -> report / JSON RESULT

Usage:
    python main.py sample_email.eml                        # raw JSON
    python main.py sample_email.eml --pretty                # indented JSON
    python main.py sample_email.eml --report                # human-readable report
    python main.py sample_email.eml -o result.json          # save JSON to a file
    python main.py sample_email.eml --report -o report.txt  # save the formatted report

    # Campaign correlation mode: score this email against a batch of
    # related .eml files (a quarantine folder, a mailbox export, etc.)
    # instead of falling back to single-email heuristics for the
    # campaign sub-score:
    python main.py sample_email.eml --campaign-dir ./sample_campaign/
"""

import argparse
import glob
import json
import os
import sys

from email_parser import parse_email_file
from ip_extractor import extract_hops
from ip_validator import validate_hops
from geolocation import geolocate_ip
from asn_lookup import asn_lookup
from dns_lookup import reverse_dns_lookup
from infrastructure import build_hop_profile, analyze_infrastructure, risk_level_from_indicators
from auth_checker import analyze_authentication, build_auth_indicators
from attachment_analyzer import analyze_eml_attachments
from fraud_score import (
    calculate_fraud_score,
    score_from_infrastructure,
    score_from_attachments,
    score_from_campaign,
    score_from_risk_level,
)
from report import format_report


def run_pipeline(eml_path: str, campaign_dir: str | None = None) -> dict:
    # Step 1: parse the raw email into structured header data
    parsed = parse_email_file(eml_path)
    claimed_domain = parsed["from_domain"]

    # Step 2: pull an IP out of every Received header, in hop order
    hops = extract_hops(parsed["received_headers"])

    # Step 3: drop private/invalid IPs, mark which hops are actually traceable
    validated_hops = validate_hops(hops)

    # Steps 4-6: for each traceable hop, geolocate + ASN lookup + reverse DNS.
    # These three are independent of each other, so a v2 of this could run
    # them concurrently (threading / asyncio) for speed - kept sequential
    # here for simplicity and easy debugging.
    hop_profiles = []
    for hop in validated_hops:
        if not hop["traceable"]:
            hop_profiles.append({
                "hop": hop["hop"],
                "ip": hop["ip"],
                "classification": hop["classification"],
                "note": "skipped - not a public IP",
            })
            continue

        ip = hop["ip"]
        geo_result = geolocate_ip(ip)
        asn_result = asn_lookup(ip, fallback_geo_result=geo_result)
        dns_result = reverse_dns_lookup(ip)

        hop_profiles.append(
            build_hop_profile(hop, geo_result, asn_result, dns_result, claimed_domain)
        )

    # Step 7: combine everything into overall infrastructure indicators.
    #
    # hop_profiles is in hop order: hop 1 = newest (closest to the
    # recipient), last entry = oldest (closest to the TRUE original
    # sender). So the right pick for "sender_ip" is the LAST traceable
    # hop, not the first one - grabbing the first would pick a relay in
    # the middle of the chain instead of the actual origin. (Traceable
    # hops always carry a "country" key from build_hop_profile, even if
    # that lookup itself failed and came back None - a skipped
    # private-IP hop has no such key at all, which is how we tell them apart.)
    infra_analysis = analyze_infrastructure(hop_profiles, claimed_domain)

    traceable_hops = [h for h in hop_profiles if "country" in h]
    original_sender_hop = traceable_hops[-1] if traceable_hops else None
    sender_ip = original_sender_hop["ip"] if original_sender_hop else None

    # Step 7b: SPF / DKIM / DMARC - "is the sender really who they claim
    # to be?" Reuses the headers email_parser.py already extracted and
    # the sender_ip the IP-trace steps above already resolved.
    auth_result = analyze_authentication(parsed, sender_ip)
    auth_indicators = build_auth_indicators(auth_result)

    # Combine infra + auth indicators into one list and re-score risk
    # using the same thresholds, so a fraud email that passes the IP
    # trace cleanly but fails SPF/DKIM/DMARC still gets flagged correctly.
    all_indicators = infra_analysis["indicators"] + auth_indicators
    overall_risk_level = risk_level_from_indicators(all_indicators)

    # Step 7c: static attachment forensics - metadata, file-type detection,
    # macro analysis, embedded IOCs. Nothing is ever executed or opened.
    attachment_analysis = analyze_eml_attachments(eml_path)

    # Step 7d: fraud score - combine infra/auth risk, attachment risk, and
    # campaign-correlation risk into one weighted 0-100 number.
    geo_score = score_from_infrastructure(all_indicators)
    attachment_score = score_from_attachments(attachment_analysis)

    related_eml_files = None
    if campaign_dir:
        related_eml_files = sorted(glob.glob(os.path.join(campaign_dir, "*.eml")))
        if eml_path not in related_eml_files:
            related_eml_files.append(eml_path)

    campaign_result = score_from_campaign(
        parsed_email=parsed,
        auth_result=auth_result,
        related_eml_files=related_eml_files,
        this_eml_path=eml_path,
    )

    # Step 7e: fold risk_level (the count-based low/medium/high signal
    # from infrastructure.py) into the fraud score itself as a fourth
    # weighted input, instead of only surfacing it as a separate label
    # that could disagree with fraud_classification. See
    # fraud_score.INDICATOR_WEIGHT for the honest note on why this
    # slightly double-counts the infra/auth indicator signal on purpose.
    indicator_score = score_from_risk_level(overall_risk_level)

    fraud_result = calculate_fraud_score(
        geo_score=geo_score,
        attachment_score=attachment_score,
        campaign_score=campaign_result["score"],
        indicator_score=indicator_score,
    )

    # Step 8 (JSON RESULT): shape the final output to match the shared
    # team schema so downstream modules (dashboard, blockchain evidence
    # log) can consume it without needing to reshape anything.
    result = {
        "email": {
            "subject": parsed["subject"],
            "from_address": parsed["from_address"],
            "from_domain": claimed_domain,
            "message_id": parsed["message_id"],
            "date": parsed["date"],
        },
        "sender_ip": sender_ip,
        "geo": {
            "country": original_sender_hop.get("country") if original_sender_hop else None,
            "city": original_sender_hop.get("city") if original_sender_hop else None,
        } if original_sender_hop else None,
        "hop_trace": hop_profiles,
        "spf": auth_result["spf"],
        "dkim": auth_result["dkim"],
        "dmarc": auth_result["dmarc"],
        "indicators": all_indicators,
        "risk_level": overall_risk_level,
        "attachments": attachment_analysis,
        "fraud_score": fraud_result["fraud_score"],
        "fraud_classification": fraud_result["fraud_classification"],
        "fraud_score_breakdown": fraud_result["breakdown"],
        "campaign_correlation": {
            "mode": campaign_result["mode"],
            "reasons": campaign_result["reasons"],
        },
    }
    return result


def main():
    parser = argparse.ArgumentParser(description="Trace an email's origin from its headers and score its fraud risk.")
    parser.add_argument("eml_file", help="Path to a raw .eml file")
    parser.add_argument("-o", "--output", help="Write the result to this file instead of stdout")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON with indentation")
    parser.add_argument(
        "--report", action="store_true",
        help="Print a formatted, human-readable report instead of raw JSON - good for demos/PPTs.",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI colors in --report output (colors are auto-disabled when writing to a file).",
    )
    parser.add_argument(
        "--campaign-dir",
        help="Folder of related .eml files to correlate this email against for the campaign fraud sub-score. "
             "Without this, campaign scoring falls back to single-email heuristics (subject language + auth failures).",
    )
    args = parser.parse_args()

    result = run_pipeline(args.eml_file, campaign_dir=args.campaign_dir)

    if args.report:
        # Auto-disable color when writing to a file - nobody wants raw
        # \033[31m escape codes cluttering a .txt file they open later.
        use_color = not args.no_color and not args.output
        output_text = format_report(result, use_color=use_color)
    else:
        indent = 2 if args.pretty or args.output else None
        output_text = json.dumps(result, indent=indent, default=str)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output_text)
        print(f"Result written to {args.output}")
    else:
        print(output_text)


if __name__ == "__main__":
    sys.exit(main())
