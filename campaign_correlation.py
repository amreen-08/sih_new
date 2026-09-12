"""
campaign_correlation.py
------------------------
Multi-email campaign correlation and attribution.

This is the batch-analysis half of what used to be two separate,
overlapping scripts (fraud_score.py and final_codex.py both computed a
"campaign score", one with hardcoded numbers and one against a hardcoded
list of six sample .eml files). This module keeps the genuinely useful
part of that logic - the cross-email fingerprinting - as reusable
functions instead of a script that only works against one hardcoded
folder of demo emails.

What "campaign correlation" means here: a single phishing email in
isolation only tells you so much. But phishing is usually sent as a
BATCH - the same campaign_id header, the same relay IP, the same HTML
body template, reused across hundreds of near-identical messages with
only the recipient/subject tweaked. If you have more than one .eml file
on hand (a mailbox export, a SOC's quarantine folder, samples from
several reported phishing emails), this module links them together and
flags which ones share infrastructure/template fingerprints with a
"anchor" email that already looks clearly malicious (lookalike domain,
or multiple auth failures).

Used by:
    - fraud_score.py, when the caller passes a list of related .eml paths
      for full cross-email correlation instead of just a single email's
      own indicators.
    - directly from the command line for ad-hoc batch triage.
"""

import re
import difflib
import glob
import os
from collections import defaultdict
from email import policy
from email.parser import BytesParser


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def get_body(message) -> str:
    """Return the readable email body, preferring HTML then falling back to plaintext."""
    for part in message.walk():
        if part.get_content_type() == "text/html":
            try:
                return part.get_content()
            except Exception:
                return (part.get_payload(decode=True) or b"").decode(
                    "utf-8", errors="ignore"
                )

    for part in message.walk():
        if part.get_content_type() == "text/plain":
            try:
                return part.get_content()
            except Exception:
                return (part.get_payload(decode=True) or b"").decode(
                    "utf-8", errors="ignore"
                )

    return ""


def normalize_body(body: str) -> str:
    """Strip HTML/whitespace so near-identical templates fingerprint the same."""
    body = re.sub(r"<[^>]+>", " ", body)
    body = re.sub(r"\s+", " ", body)
    return body.strip().lower()


def extract_email_features(filename: str) -> dict:
    """Extract the fingerprints needed for campaign correlation from one .eml file."""
    with open(filename, "rb") as f:
        message = BytesParser(policy=policy.default).parse(f)

    auth = message.get("Authentication-Results", "")

    dkim = re.search(r"dkim=(pass|fail)", auth, re.IGNORECASE)
    spf = re.search(r"spf=(pass|fail)", auth, re.IGNORECASE)
    dmarc = re.search(r"dmarc=(pass|fail)", auth, re.IGNORECASE)

    sender = message.get("from", "")
    sender_match = re.search(r"@([^>\s]+)", sender)

    received = " ".join(message.get_all("received", []) or [])
    ip_match = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", received)

    return {
        "filename": filename,
        "campaign_id": (message.get("x-campaignid") or "").strip(),
        "sender_domain": (
            sender_match.group(1).lower() if sender_match else ""
        ),
        "reply_to": (message.get("reply-to") or "").lower().strip(),
        "subject": (message.get("subject") or "").strip(),
        "source_ip": ip_match.group(1) if ip_match else "",
        "dkim": dkim.group(1).lower() if dkim else "unknown",
        "spf": spf.group(1).lower() if spf else "unknown",
        "dmarc": dmarc.group(1).lower() if dmarc else "unknown",
        "body_template": normalize_body(get_body(message)),
    }


# ============================================================
# SIMILARITY HELPERS
# ============================================================

def domain_similarity(domain1: str, domain2: str) -> float:
    """Measure how similar two sender domains are (0.0-1.0)."""
    if not domain1 or not domain2:
        return 0.0
    return difflib.SequenceMatcher(None, domain1.lower(), domain2.lower()).ratio()


def subject_similarity(subject1: str, subject2: str) -> float:
    """Measure similarity between two subjects (0.0-1.0)."""
    if not subject1 or not subject2:
        return 0.0
    return difflib.SequenceMatcher(None, subject1.lower(), subject2.lower()).ratio()


SUSPICIOUS_SUBJECT_WORDS = [
    "urgent", "suspended", "suspend", "verify", "verify now",
    "24 hours", "reward", "selected", "claim", "account",
]


def suspicious_subject(subject: str) -> bool:
    """Look for common urgency/account/reward social-engineering language."""
    subject = (subject or "").lower()
    return any(word in subject for word in SUSPICIOUS_SUBJECT_WORDS)


def calculate_pair_score(email_a: dict, email_b: dict) -> int:
    """
    Calculate how strongly two emails belong to the same campaign (0-100).

    x-campaignid is useful for grouping but is NOT enough by itself to
    flag an email, because legitimate and malicious variants can share
    infrastructure/campaign metadata (e.g. a compromised legitimate
    mailing-list account reused to blast phishing).
    """
    score = 0

    if email_a["campaign_id"] and email_a["campaign_id"] == email_b["campaign_id"]:
        score += 30

    if email_a["source_ip"] and email_a["source_ip"] == email_b["source_ip"]:
        score += 15

    if email_a["body_template"] and email_a["body_template"] == email_b["body_template"]:
        score += 20

    if email_a["reply_to"] and email_a["reply_to"] == email_b["reply_to"]:
        score += 10

    if (
        email_a["sender_domain"]
        and email_b["sender_domain"]
        and email_a["sender_domain"] == email_b["sender_domain"]
    ):
        score += 10

    if (
        email_a["sender_domain"]
        and email_b["sender_domain"]
        and domain_similarity(email_a["sender_domain"], email_b["sender_domain"]) >= 0.85
    ):
        score += 10

    if subject_similarity(email_a["subject"], email_b["subject"]) >= 0.70:
        score += 15

    return min(score, 100)


def has_multiple_auth_failures(email: dict) -> bool:
    """True when at least two of SPF/DKIM/DMARC failed - high-confidence signal."""
    failures = sum(
        value == "fail" for value in (email["dkim"], email["spf"], email["dmarc"])
    )
    return failures >= 2


def is_high_confidence_anchor(email: dict, known_domains: set[str]) -> bool:
    """
    An "anchor" is an email that gives the correlation engine a strong,
    independent reason to consider a whole campaign suspicious, so its
    fingerprints can be safely propagated to other emails that match it.
    """
    lookalike = any(
        email["sender_domain"] != domain
        and domain_similarity(email["sender_domain"], domain) >= 0.85
        for domain in known_domains
    )
    return lookalike or has_multiple_auth_failures(email)


# ============================================================
# BATCH CORRELATION
# ============================================================

def calculate_campaign_scores(email_files: list[str]) -> dict:
    """
    Return a campaign/correlation risk score (0-100) + reasons for every
    email in `email_files`. Needs at least two emails to find anything -
    correlation is inherently a multi-email operation.
    """
    emails = [extract_email_features(filename) for filename in email_files]

    # The most common sender domain across the batch is used as the
    # reference "legitimate" domain - safer than trusting SPF/DKIM alone,
    # since a lookalike domain can still technically pass its own checks.
    domain_counts: dict[str, int] = {}
    for email in emails:
        domain = email["sender_domain"]
        if domain:
            domain_counts[domain] = domain_counts.get(domain, 0) + 1

    reference_domain = max(domain_counts, key=domain_counts.get) if domain_counts else ""
    known_domains = {reference_domain} if reference_domain else set()

    anchors = [e for e in emails if is_high_confidence_anchor(e, known_domains)]

    results = {}

    for email in emails:
        score = 0
        reasons = []

        if email["dkim"] == "fail":
            score += 20
            reasons.append("DKIM failure")
        if email["spf"] == "fail":
            score += 15
            reasons.append("SPF failure")
        if email["dmarc"] == "fail":
            score += 20
            reasons.append("DMARC failure")

        if any(
            email["sender_domain"] != domain
            and domain_similarity(email["sender_domain"], domain) >= 0.85
            for domain in known_domains
        ):
            score += 25
            reasons.append("lookalike sender domain")

        if suspicious_subject(email["subject"]):
            score += 10
            reasons.append("suspicious/urgent subject")

        best_anchor_score = 0
        for anchor in anchors:
            if anchor["filename"] == email["filename"]:
                continue
            pair_score = calculate_pair_score(email, anchor)

            # Two ways to count as correlated with an anchor:
            #   1. Same X-CampaignID + a solid pair score (60+) - the
            #      strongest possible signal, but only present when the
            #      sender helpfully stamped a campaign header (true of
            #      hand-built demo data, almost never true of real
            #      captured phishing mail "in the wild").
            #   2. No campaign_id on one/both sides, but the pair score
            #      alone is very high (70+) - i.e. matching body
            #      template + reply-to/source-IP/domain overlap is
            #      already strong enough evidence on its own that two
            #      real-world samples are the same campaign, without
            #      needing a header nobody actually sends.
            same_campaign_id = (
                email["campaign_id"] and email["campaign_id"] == anchor["campaign_id"]
            )
            if (same_campaign_id and pair_score >= 60) or pair_score >= 70:
                best_anchor_score = max(best_anchor_score, pair_score)

        if best_anchor_score >= 60:
            score += 20
            reasons.append(
                f"correlated with known suspicious campaign (match {best_anchor_score}/100)"
            )

        score = min(score, 100)
        if not reasons:
            reasons.append("no strong campaign indicators")

        results[email["filename"]] = {"score": score, "reasons": reasons}

    return results


# ============================================================
# GENERAL-PURPOSE SIMILARITY CLUSTERING
# ============================================================
#
# calculate_campaign_scores() above answers "is THIS ONE email part of a
# suspicious campaign?" by comparing it against a single inferred
# "legitimate reference domain" - built for the case where a batch is
# mostly one brand plus a few spoofed variants (e.g. a hand-crafted demo
# set, or a mailbox's own outgoing mail plus impersonations of it).
#
# find_campaign_clusters() below answers a different, more general
# question: "I have a PILE of unrelated real-world phishing samples -
# which of them are actually the same campaign wearing different
# outfits?" No single email is treated as "the" reference; every pair is
# compared and emails that match strongly enough are grouped together
# (simple union-find over calculate_pair_score()). This is what actually
# finds similarities across a batch of samples pulled from a public
# corpus rather than one team's synthetic demo data.

def find_campaign_clusters(email_files: list[str], threshold: int = 55) -> list[dict]:
    """
    Group a batch of .eml files into campaign clusters by pairwise
    similarity. Returns clusters of size 2+ only (a lone email with no
    match to anything else in the batch isn't a "cluster"), largest first.

    threshold: minimum calculate_pair_score() (0-100) for two emails to
    be considered the same campaign. 55 is deliberately a bit looser than
    the 60/70 thresholds used inside calculate_campaign_scores() - this
    function's whole job is finding matches, so it's tuned to surface
    borderline pairs for a human to look at rather than staying silent.
    """
    emails = [extract_email_features(f) for f in email_files]
    n = len(emails)

    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    pair_scores = {}
    for i in range(n):
        for j in range(i + 1, n):
            score = calculate_pair_score(emails[i], emails[j])
            if score >= threshold:
                pair_scores[(i, j)] = score
                union(i, j)

    groups = defaultdict(list)
    for i in range(n):
        groups[find(i)].append(i)

    clusters = []
    for indices in groups.values():
        if len(indices) < 2:
            continue

        edges = sorted(
            (
                {"a": emails[i]["filename"], "b": emails[j]["filename"], "score": s}
                for (i, j), s in pair_scores.items()
                if i in indices and j in indices
            ),
            key=lambda e: -e["score"],
        )

        clusters.append(
            {
                "members": [emails[i]["filename"] for i in indices],
                "size": len(indices),
                "top_matches": edges[:5],
                # a quick human-readable hint of what's actually shared -
                # helpful when eyeballing results from a large real corpus
                "shared_sender_domains": sorted(
                    {emails[i]["sender_domain"] for i in indices if emails[i]["sender_domain"]}
                ),
                "shared_subjects": sorted(
                    {emails[i]["subject"] for i in indices if emails[i]["subject"]}
                )[:5],
            }
        )

    clusters.sort(key=lambda c: -c["size"])
    return clusters


if __name__ == "__main__":
    import sys
    import json

    args = sys.argv[1:]
    if not args:
        print(
            "Usage:\n"
            "  python campaign_correlation.py <email1.eml> <email2.eml> [...]\n"
            "  python campaign_correlation.py --dir <folder_of_eml_files>\n"
            "  python campaign_correlation.py --cluster <email1.eml> [...]\n"
            "  python campaign_correlation.py --cluster --dir <folder_of_eml_files>"
        )
        sys.exit(1)

    cluster_mode = "--cluster" in args
    if cluster_mode:
        args.remove("--cluster")

    if "--dir" in args:
        idx = args.index("--dir")
        folder = args[idx + 1]
        files = sorted(glob.glob(os.path.join(folder, "*.eml")))
    else:
        files = args

    if cluster_mode:
        print(json.dumps(find_campaign_clusters(files), indent=2))
    else:
        print(json.dumps(calculate_campaign_scores(files), indent=2))
