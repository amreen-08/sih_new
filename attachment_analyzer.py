"""
attachment_analyzer.py
----------------------

Coordinator for the complete Attachment Analysis subsystem.

This module combines:

    attachment_extractor
    attachment_metadata
    attachment_detector
    attachment_macro_analyzer
    attachment_ioc

IMPORTANT:

    This module does NOT calculate a risk score.

    Fraud/risk scoring belongs to the Fraud Score module.
"""


from attachment_extractor import extract_attachments_from_eml
from attachment_metadata import extract_metadata
from attachment_detector import detect_attachment
from attachment_macro_analyzer import analyze_macros
from attachment_ioc import extract_iocs


# ============================================================
# SINGLE ATTACHMENT
# ============================================================

def analyze_single_attachment(attachment: dict) -> dict:
    """
    Analyze one extracted attachment.
    """

    filename = attachment.get(
        "filename",
        "unnamed_attachment"
    )

    declared_mime_type = attachment.get(
        "mime_type",
        "application/octet-stream"
    )

    data = attachment.get(
        "data",
        b""
    )

    if data is None:
        data = b""

    # ========================================================
    # 1. METADATA
    # ========================================================

    metadata = extract_metadata(
        filename,
        data
    )

    # ========================================================
    # 2. FILE DETECTION
    # ========================================================

    detection = detect_attachment(
        filename=filename,
        data=data,
        detected_mime_type=metadata["detected_mime_type"],
        declared_mime_type=declared_mime_type,
    )

    # ========================================================
    # 3. MACRO ANALYSIS
    # ========================================================

    macro_analysis = analyze_macros(
        filename,
        data
    )

    # ========================================================
    # 4. IOC EXTRACTION
    # ========================================================

    iocs = extract_iocs(
        data
    )

    # ========================================================
    # 5. COMBINE FORENSIC INDICATORS
    # ========================================================

    forensic_indicators = []

    # High entropy
    if metadata["entropy"] >= 7.5:
        forensic_indicators.append(
            "Very high entropy detected; attachment may be compressed or encrypted."
        )

    # Empty attachment
    if metadata["size"] == 0:
        forensic_indicators.append(
            "Attachment contains no payload bytes."
        )

    # Unknown binary
    if metadata["detected_mime_type"] == "application/octet-stream":
        forensic_indicators.append(
            "Unknown binary attachment detected."
        )

    # File detection indicators
    forensic_indicators.extend(
        detection.get(
            "forensic_indicators",
            []
        )
    )

    # Macro detected
    if macro_analysis.get(
        "macro_detected",
        False
    ):
        forensic_indicators.append(
            "VBA macro capability or VBA macros detected."
        )

    # Auto-executable macros
    if macro_analysis.get(
        "autoexec_count",
        0
    ) > 0:
        forensic_indicators.append(
            "Auto-executable VBA macro behavior detected."
        )

    # Suspicious VBA keywords
    if macro_analysis.get(
        "suspicious_count",
        0
    ) > 0:
        forensic_indicators.append(
            "Suspicious VBA keywords detected."
        )

    # VBA obfuscation
    if (
        macro_analysis.get(
            "hex_obfuscation_count",
            0
        ) > 0
        or
        macro_analysis.get(
            "base64_obfuscation_count",
            0
        ) > 0
        or
        macro_analysis.get(
            "dridex_obfuscation_count",
            0
        ) > 0
        or
        macro_analysis.get(
            "vba_obfuscation_count",
            0
        ) > 0
    ):
        forensic_indicators.append(
            "Potentially obfuscated VBA strings detected."
        )

    # IOC indicators
    forensic_indicators.extend(
        iocs.get(
            "forensic_indicators",
            []
        )
    )

    # Remove duplicate indicators while preserving order
    forensic_indicators = list(
        dict.fromkeys(
            forensic_indicators
        )
    )

    # ========================================================
    # 6. FINAL ATTACHMENT RECORD
    # ========================================================

    return {

        # ----------------------------------------------------
        # Identity
        # ----------------------------------------------------

        "filename": filename,

        "extension": metadata[
            "extension"
        ],

        # ----------------------------------------------------
        # MIME / Metadata
        # ----------------------------------------------------

        "declared_mime_type": declared_mime_type,

        "detected_mime_type": metadata[
            "detected_mime_type"
        ],

        "size": metadata[
            "size"
        ],

        "sha256": metadata[
            "sha256"
        ],

        "entropy": metadata[
            "entropy"
        ],

        # ----------------------------------------------------
        # File Detection
        # ----------------------------------------------------

        "file_signature": detection[
            "file_signature"
        ],

        "executable_detected": detection[
            "executable_detected"
        ],

        "script_detected": detection[
            "script_detected"
        ],

        "macro_capable": detection[
            "macro_capable"
        ],

        "double_extension": detection[
            "double_extension"
        ],

        "signature_mismatch": detection[
            "signature_mismatch"
        ],

        "signature_mismatch_reason": detection[
            "signature_mismatch_reason"
        ],

        # ----------------------------------------------------
        # Macro Analysis
        # ----------------------------------------------------

        "macro_analysis": macro_analysis,

        # ----------------------------------------------------
        # IOCs
        # ----------------------------------------------------

        "iocs": iocs,

        # ----------------------------------------------------
        # Combined Evidence
        # ----------------------------------------------------

        "forensic_indicators": forensic_indicators,
    }


# ============================================================
# COMPLETE EMAIL ATTACHMENT ANALYSIS
# ============================================================

def analyze_email_attachments(
    attachments: list[dict]
) -> dict:
    """
    Analyze every attachment belonging to an email.
    """

    results = []

    for attachment in attachments:

        result = analyze_single_attachment(
            attachment
        )

        results.append(
            result
        )

    # ========================================================
    # SUMMARY
    # ========================================================

    executable_count = sum(
        1
        for result in results
        if result.get(
            "executable_detected",
            False
        )
    )

    macro_count = sum(
        1
        for result in results
        if result.get(
            "macro_analysis",
            {}
        ).get(
            "macro_detected",
            False
        )
    )

    script_count = sum(
        1
        for result in results
        if result.get(
            "script_detected",
            False
        )
    )

    mismatch_count = sum(
        1
        for result in results
        if result.get(
            "signature_mismatch",
            False
        )
    )

    # ========================================================
    # FINAL OUTPUT
    # ========================================================

    return {

        "attachment_count": len(
            results
        ),

        "attachments": results,

        "summary": {
            "executable_attachments": executable_count,
            "macro_attachments": macro_count,
            "script_attachments": script_count,
            "signature_mismatches": mismatch_count,
        },

        # Evidence only — NOT a risk score
        "analysis_scope": (
            "Static attachment analysis only. "
            "No attachment was executed and no extracted "
            "URL was visited."
        ),
    }


# ============================================================
# DIRECT EML ANALYSIS
# ============================================================

def analyze_eml_attachments(
    eml_path: str
) -> dict:
    """
    Takes an .eml file directly and performs
    the complete attachment-analysis pipeline.
    """

    attachments = extract_attachments_from_eml(
        eml_path
    )

    return analyze_email_attachments(
        attachments
    )


# ============================================================
# COMMAND LINE TEST
# ============================================================

if __name__ == "__main__":

    import json
    import sys

    if len(sys.argv) < 2:

        print(
            "Usage:"
        )

        print(
            "python attachment_analyzer.py <email.eml>"
        )

        sys.exit(1)

    eml_file = sys.argv[1]

    result = analyze_eml_attachments(
        eml_file
    )

    print(
        json.dumps(
            result,
            indent=2,
            default=str
        )
    )