"""
attachment_detector.py
----------------------

Static file-type and suspicious-structure detection.

Detects:

    - actual file signature
    - executable files
    - script files
    - MIME/signature mismatch
    - suspicious double extensions

Nothing is executed.
"""

import re
from pathlib import Path


# ============================================================
# EXTENSION GROUPS
# ============================================================

EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".com",
    ".msi",
}


SCRIPT_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
}


MACRO_EXTENSIONS = {
    ".docm",
    ".dotm",
    ".xlsm",
    ".xltm",
    ".xlam",
    ".pptm",
    ".potm",
    ".ppsm",
    ".ppam",
}


# ============================================================
# FILE SIGNATURES
# ============================================================

FILE_SIGNATURES = [
    (
        b"%PDF-",
        "PDF"
    ),

    (
        b"MZ",
        "PE_EXECUTABLE"
    ),

    (
        b"\xD0\xCF\x11\xE0",
        "OLE_DOCUMENT"
    ),

    (
        b"\x89PNG\r\n\x1a\n",
        "PNG"
    ),

    (
        b"\xFF\xD8\xFF",
        "JPEG"
    ),

    (
        b"GIF87a",
        "GIF"
    ),

    (
        b"GIF89a",
        "GIF"
    ),

    (
        b"PK\x03\x04",
        "ZIP_CONTAINER"
    ),

    (
        b"PK\x05\x06",
        "ZIP_CONTAINER"
    ),

    (
        b"PK\x07\x08",
        "ZIP_CONTAINER"
    ),
]


# ============================================================
# SIGNATURE DETECTION
# ============================================================

def detect_file_signature(
    data: bytes
) -> str:
    """
    Determine the file type from its magic bytes.
    """

    for signature, file_type in FILE_SIGNATURES:

        if data.startswith(signature):
            return file_type

    return "UNKNOWN"


# ============================================================
# EXECUTABLE DETECTION
# ============================================================

def detect_executable(
    filename: str,
    data: bytes,
    detected_mime_type: str
) -> bool:
    """
    Detect whether an attachment is or appears to be
    an executable.
    """

    extension = Path(
        filename
    ).suffix.lower()

    # Filename-based detection.
    if extension in EXECUTABLE_EXTENSIONS:
        return True

    # PE executable magic bytes.
    if data.startswith(b"MZ"):
        return True

    # libmagic detection.
    if detected_mime_type in {
        "application/x-dosexec",
        "application/vnd.microsoft.portable-executable",
    }:
        return True

    return False


# ============================================================
# SCRIPT DETECTION
# ============================================================

def detect_script(
    filename: str
) -> bool:
    """
    Detect common script/interpreter extensions.
    """

    extension = Path(
        filename
    ).suffix.lower()

    return extension in SCRIPT_EXTENSIONS


# ============================================================
# MACRO CAPABLE FILE
# ============================================================

def detect_macro_capable_file(
    filename: str
) -> bool:
    """
    Detect Office extensions that support VBA macros.
    """

    extension = Path(
        filename
    ).suffix.lower()

    return extension in MACRO_EXTENSIONS


# ============================================================
# DOUBLE EXTENSION
# ============================================================

DOUBLE_EXTENSION_PATTERN = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|ppt|pptx|"
    r"jpg|jpeg|png|txt|zip)"
    r"\.(exe|scr|bat|cmd|com|msi|js|jse|"
    r"vbs|vbe|ps1|hta)$",
    re.IGNORECASE,
)


def detect_double_extension(
    filename: str
) -> bool:
    """
    Detect filenames such as:

        invoice.pdf.exe
        payment.xlsx.js
        document.docx.hta
    """

    return bool(
        DOUBLE_EXTENSION_PATTERN.search(
            filename
        )
    )


# ============================================================
# SIGNATURE / FILENAME MISMATCH
# ============================================================

def detect_signature_mismatch(
    filename: str,
    declared_mime_type: str,
    detected_mime_type: str,
    signature: str,
) -> dict:
    """
    Compare filename/MIME information with actual file
    signature.

    Returns:

        {
            "mismatch": True/False,
            "reason": "..."
        }
    """

    extension = Path(
        filename
    ).suffix.lower()


    # --------------------------------------------------------
    # Executable disguised as another file
    # --------------------------------------------------------

    if signature == "PE_EXECUTABLE":

        if extension not in EXECUTABLE_EXTENSIONS:

            return {
                "mismatch": True,
                "reason": (
                    "File content is a Windows executable "
                    "but the filename does not use an "
                    "executable extension."
                ),
            }


    # --------------------------------------------------------
    # PDF
    # --------------------------------------------------------

    if extension == ".pdf":

        if signature not in {
            "PDF",
            "UNKNOWN",
        }:

            return {
                "mismatch": True,
                "reason": (
                    f"File is named as PDF but actual "
                    f"signature is {signature}."
                ),
            }


    # --------------------------------------------------------
    # PNG
    # --------------------------------------------------------

    if extension == ".png":

        if signature not in {
            "PNG",
            "UNKNOWN",
        }:

            return {
                "mismatch": True,
                "reason": (
                    f"PNG filename does not match "
                    f"actual signature {signature}."
                ),
            }


    # --------------------------------------------------------
    # JPEG
    # --------------------------------------------------------

    if extension in {
        ".jpg",
        ".jpeg",
    }:

        if signature not in {
            "JPEG",
            "UNKNOWN",
        }:

            return {
                "mismatch": True,
                "reason": (
                    f"JPEG filename does not match "
                    f"actual signature {signature}."
                ),
            }


    # --------------------------------------------------------
    # Office OpenXML
    # --------------------------------------------------------

    office_extensions = {
        ".docx",
        ".docm",
        ".dotx",
        ".dotm",
        ".xlsx",
        ".xlsm",
        ".xltx",
        ".xltm",
        ".pptx",
        ".pptm",
        ".potx",
        ".potm",
        ".ppsx",
        ".ppsm",
    }

    if extension in office_extensions:

        if signature not in {
            "ZIP_CONTAINER",
            "UNKNOWN",
        }:

            return {
                "mismatch": True,
                "reason": (
                    "Office OpenXML filename does not "
                    "match expected ZIP container structure."
                ),
            }


    return {
        "mismatch": False,
        "reason": None,
    }


# ============================================================
# COMPLETE DETECTION
# ============================================================

def detect_attachment(
    filename: str,
    data: bytes,
    detected_mime_type: str,
    declared_mime_type: str,
) -> dict:
    """
    Run all static file-type detection.
    """

    signature = detect_file_signature(
        data
    )

    executable = detect_executable(
        filename,
        data,
        detected_mime_type,
    )

    script = detect_script(
        filename
    )

    macro_capable = detect_macro_capable_file(
        filename
    )

    double_extension = detect_double_extension(
        filename
    )

    mismatch = detect_signature_mismatch(
        filename,
        declared_mime_type,
        detected_mime_type,
        signature,
    )

    indicators = []

    if executable:
        indicators.append(
            "Executable content detected."
        )

    if script:
        indicators.append(
            "Script/interpreter file detected."
        )

    if macro_capable:
        indicators.append(
            "Macro-capable Office file detected."
        )

    if double_extension:
        indicators.append(
            "Suspicious double extension detected."
        )

    if mismatch["mismatch"]:
        indicators.append(
            mismatch["reason"]
        )

    return {
        "file_signature": signature,
        "executable_detected": executable,
        "script_detected": script,
        "macro_capable": macro_capable,
        "double_extension": double_extension,
        "signature_mismatch": mismatch["mismatch"],
        "signature_mismatch_reason": mismatch["reason"],
        "forensic_indicators": indicators,
    }


if __name__ == "__main__":

    # Harmless test bytes that begin with MZ,
    # representing an executable signature.
    test_data = (
        b"MZ"
        + b"\x00" * 100
    )

    result = detect_attachment(
        filename="invoice.pdf",
        data=test_data,
        detected_mime_type="application/octet-stream",
        declared_mime_type="application/pdf",)
    for key, value in result.items():
        print(f"{key}: {value}")