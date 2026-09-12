"""
fraud_score.py
---------------
Final fraud-score calculation. Combines three independent risk signals
already produced by the rest of the pipeline:

    1. Infrastructure/geolocation risk  (infrastructure.py + auth_checker.py)
    2. Attachment risk                  (attachment_analyzer.py)
    3. Campaign-correlation risk        (campaign_correlation.py, or a
                                          lightweight single-email fallback
                                          when no related .eml files are
                                          available to correlate against)

This replaces the two earlier, overlapping versions of this file
(fraud_score.py with three hardcoded numbers, and final_codex.py with a
hardcoded list of six demo .eml files). Both are gone; what's kept is
everything reusable from them, now wired to the REAL pipeline output
instead of placeholder constants - main.py calls calculate_fraud_score()
directly and gets a real, explainable number back.
"""

from campaign_correlation import (
    calculate_campaign_scores,
    find_campaign_clusters,
    suspicious_subject,
)


# ------------------------------------------------------------
# WEIGHTS
# Total must equal 1.0 (100%)
# ------------------------------------------------------------
#
# Four weighted sub-scores now feed the final number - the original
# three (geo/attachment/campaign) plus indicator_score, which folds in
# the indicator-COUNT-based risk_level signal (infrastructure.py's
# risk_level_from_indicators()) as its own explicit, weighted term
# instead of only surfacing it as a separate, disagreeing label next to
# the fraud score. Re-normalized so all four still sum to 1.0.
#
# Worth being upfront about: geo_score and indicator_score are both
# derived from the SAME underlying indicator list (infra + auth
# indicators) - geo_score reads it as a continuous count
# (30 + count*18), indicator_score reads it as a coarser low/medium/high
# bucket. That means this signal is now counted twice, deliberately -
# once granularly, once categorically - which is a real design choice
# (it makes indicator count harder to under-weight) worth stating
# honestly rather than presenting as if all four inputs are fully
# independent.

GEO_WEIGHT = 0.20
ATTACHMENT_WEIGHT = 0.30
CAMPAIGN_WEIGHT = 0.35
INDICATOR_WEIGHT = 0.15

if abs(GEO_WEIGHT + ATTACHMENT_WEIGHT + CAMPAIGN_WEIGHT + INDICATOR_WEIGHT - 1.0) > 1e-9:
    raise ValueError("Fraud score weights must add up to 1.0")


# ------------------------------------------------------------
# VALIDATION
# ------------------------------------------------------------

def validate_score(score, name: str) -> None:
    if not isinstance(score, (int, float)):
        raise TypeError(f"{name} must be a number")
    if not 0 <= score <= 100:
        raise ValueError(f"{name} must be between 0 and 100")


# ------------------------------------------------------------
# SUB-SCORE 1: INFRASTRUCTURE / GEOLOCATION
# ------------------------------------------------------------

def score_from_infrastructure(indicators: list[str]) -> float:
    """
    Derive a 0-100 geo/infrastructure risk score from the plain-English
    indicator strings infrastructure.py + auth_checker.py already
    produced (hosting-provider origin, hostname/domain mismatch, SPF/
    DKIM/DMARC failures, etc.). Count-based on purpose: each indicator
    already represents a distinct, independently-checked red flag, so
    more of them stacking up is itself meaningful signal.
    """
    count = len(indicators)
    if count == 0:
        return 5.0
    return min(100.0, 30.0 + (count * 18.0))


# ------------------------------------------------------------
# SUB-SCORE 2: ATTACHMENTS
# ------------------------------------------------------------

def score_from_attachments(attachment_analysis: dict | None) -> float:
    """
    Derive a 0-100 attachment risk score from attachment_analyzer.py's
    output. No attachments at all scores 0 (nothing to be risky about);
    executables and macro-bearing documents are weighted far above a
    plain signature mismatch, reflecting how much more dangerous they
    are to an end user who opens them.
    """
    if not attachment_analysis or attachment_analysis.get("attachment_count", 0) == 0:
        return 0.0

    summary = attachment_analysis.get("summary", {})

    score = 0.0
    score += summary.get("executable_attachments", 0) * 45
    score += summary.get("macro_attachments", 0) * 35
    score += summary.get("script_attachments", 0) * 35
    score += summary.get("signature_mismatches", 0) * 25

    # Small extra bump for the sheer volume of forensic indicators raised
    # across all attachments (obfuscated macros, embedded IOCs, etc.),
    # capped so it can't dominate the score on its own.
    total_indicators = sum(
        len(attachment.get("forensic_indicators", []))
        for attachment in attachment_analysis.get("attachments", [])
    )
    score += min(total_indicators * 4, 20)

    return min(100.0, score)


# ------------------------------------------------------------
# SUB-SCORE 3: CAMPAIGN CORRELATION
# ------------------------------------------------------------

def score_from_campaign(
    parsed_email: dict,
    auth_result: dict,
    related_eml_files: list[str] | None = None,
    this_eml_path: str | None = None,
) -> dict:
    """
    Two modes:

    1. BATCH MODE - if `related_eml_files` (2+ paths, including this
       email's own file as `this_eml_path`) is supplied, this combines
       TWO independent cross-email signals from campaign_correlation.py:

         a. calculate_campaign_scores() - the anchor-based scorer. Only
            gives credit when this email pairs strongly (60+) with an
            email that's ALREADY independently suspicious (a lookalike
            domain, or 2+ auth failures) - deliberately conservative, so
            it stays silent on a batch of real-world samples where
            nothing happens to look like a classic spoofing anchor even
            though they're clearly the same spam/phishing run.

         b. find_campaign_clusters() - the general similarity grouper.
            Groups ANY emails in the batch that match each other closely
            enough (same body template, shared reply-to/IP/domain
            overlap), with no anchor requirement at all. This is what
            actually catches real-world campaigns like a dating-scam
            blast caught by a honeypot multiple times, where none of the
            individual copies looks like a "lookalike domain" case.

       The final campaign score is the MAX of the two - either signal
       firing is enough to say "this looks like a batch/campaign", and
       reasons from both are reported so it's clear which one fired.

    2. SINGLE-EMAIL FALLBACK - the common case when main.py is run
       against just one .eml file with nothing to correlate against.
       Falls back to lightweight, self-contained heuristics: urgency/
       social-engineering language in the subject, and multiple
       authentication failures (a single email with both SPF and DKIM
       failing is already a strong standalone signal, campaign or not).

    Returns: {"score": float 0-100, "reasons": [str, ...], "mode": "batch"|"single"}
    """

    if related_eml_files and len(related_eml_files) >= 2:
        results = calculate_campaign_scores(related_eml_files)

        if this_eml_path and this_eml_path in results:
            entry = results[this_eml_path]
            anchor_score = float(entry["score"])
            reasons = list(entry["reasons"])
        else:
            # This email's own path wasn't in the batch (or wasn't given) -
            # fall back to the batch's highest score as the worst-case
            # exposure, since this email is presumed related to that batch.
            worst = max(results.values(), key=lambda r: r["score"]) if results else {"score": 0, "reasons": []}
            anchor_score = float(worst["score"])
            reasons = list(worst["reasons"])

        # --- cluster-based signal (see docstring point b above) ---
        cluster_score = 0.0
        if this_eml_path:
            for cluster in find_campaign_clusters(related_eml_files):
                if this_eml_path not in cluster["members"]:
                    continue

                edges_touching_this = [
                    e for e in cluster["top_matches"]
                    if e["a"] == this_eml_path or e["b"] == this_eml_path
                ]
                if edges_touching_this:
                    cluster_score = max(e["score"] for e in edges_touching_this)
                else:
                    # Union-find confirmed this email belongs to the
                    # cluster, but its own edge didn't make the cluster's
                    # top-5 list (only happens on a larger cluster) -
                    # still real membership, just use a flat baseline
                    # instead of re-deriving the exact pairwise number.
                    cluster_score = 50.0

                other_count = len(cluster["members"]) - 1
                reasons.append(
                    f"matched {other_count} other real-world sample(s) in the same "
                    f"campaign cluster (pairwise similarity {cluster_score:.0f}/100)"
                )
                break

        final_score = max(anchor_score, cluster_score)

        # "no strong campaign indicators" was only accurate before the
        # cluster check above potentially found something - drop it if a
        # real reason got added alongside it.
        if len(reasons) > 1:
            reasons = [r for r in reasons if r != "no strong campaign indicators"]
        if not reasons:
            reasons = ["no strong campaign indicators"]

        return {"score": min(100.0, final_score), "reasons": reasons, "mode": "batch"}

    # --- single-email fallback ---
    score = 0
    reasons = []

    subject = parsed_email.get("subject", "")
    if suspicious_subject(subject):
        score += 25
        reasons.append("subject line uses urgency/account/reward social-engineering language")

    failure_count = sum(
        (auth_result.get(mechanism) or {}).get("result") == "fail"
        for mechanism in ("spf", "dkim", "dmarc")
    )
    if failure_count >= 2:
        score += 35
        reasons.append(f"{failure_count} of 3 authentication checks (SPF/DKIM/DMARC) failed")
    elif failure_count == 1:
        score += 15
        reasons.append("one authentication check (SPF/DKIM/DMARC) failed")

    if not reasons:
        reasons.append(
            "no related emails supplied for campaign correlation, and no "
            "standalone urgency/auth-failure indicators found"
        )

    return {"score": min(100.0, float(score)), "reasons": reasons, "mode": "single"}


# ------------------------------------------------------------
# SUB-SCORE 4: INDICATOR-BASED RISK LEVEL
# ------------------------------------------------------------

_RISK_LEVEL_SCORE = {"low": 10.0, "medium": 50.0, "high": 90.0}


def score_from_risk_level(risk_level: str) -> float:
    """
    Turn infrastructure.py's count-based risk_level ("low"/"medium"/"high")
    into a 0-100 number so it can take its own weighted slot in the final
    fraud score, instead of only being shown as a separate label that
    could disagree with fraud_classification. 10/50/90 keeps each bucket
    clearly separated when multiplied by INDICATOR_WEIGHT below.
    """
    return _RISK_LEVEL_SCORE.get((risk_level or "").lower(), 10.0)


# ------------------------------------------------------------
# RISK CLASSIFICATION
# ------------------------------------------------------------

def classify_risk(score: float) -> str:
    if score < 30:
        return "Low Risk"
    elif score < 60:
        return "Medium Risk"
    elif score < 80:
        return "High Risk"
    else:
        return "Critical Risk"


# ------------------------------------------------------------
# FINAL COMBINE
# ------------------------------------------------------------

def calculate_fraud_score(
    geo_score: float,
    attachment_score: float,
    campaign_score: float,
    indicator_score: float,
) -> dict:
    """
    Combine all four weighted sub-scores into the final headline number.
    This is the function main.py calls once it has all four inputs -
    indicator_score (from score_from_risk_level()) is what folds the
    indicator-count-based risk_level signal directly into the fraud
    score itself, rather than leaving it as a separate label that could
    read as disagreeing with fraud_classification.
    """
    validate_score(geo_score, "Geolocation/infrastructure score")
    validate_score(attachment_score, "Attachment score")
    validate_score(campaign_score, "Campaign score")
    validate_score(indicator_score, "Indicator-based risk score")

    fraud_score = (
        geo_score * GEO_WEIGHT
        + attachment_score * ATTACHMENT_WEIGHT
        + campaign_score * CAMPAIGN_WEIGHT
        + indicator_score * INDICATOR_WEIGHT
    )
    fraud_score = max(0.0, min(100.0, fraud_score))

    return {
        "fraud_score": round(fraud_score, 2),
        "fraud_classification": classify_risk(fraud_score),
        "breakdown": {
            "geo_score": round(geo_score, 2),
            "attachment_score": round(attachment_score, 2),
            "campaign_score": round(campaign_score, 2),
            "indicator_score": round(indicator_score, 2),
            "weights": {
                "geo": GEO_WEIGHT,
                "attachment": ATTACHMENT_WEIGHT,
                "campaign": CAMPAIGN_WEIGHT,
                "indicator": INDICATOR_WEIGHT,
            },
        },
    }


if __name__ == "__main__":
    demo = calculate_fraud_score(geo_score=75, attachment_score=60, campaign_score=90, indicator_score=50)
    print("========== EMAIL FRAUD ASSESSMENT (demo values) ==========")
    print(demo)
