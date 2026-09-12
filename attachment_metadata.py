"""
attachment_metadata.py
----------------------

Extracts static metadata from email attachments.

Provides:

- SHA-256 hash
- File size
- Shannon entropy
- File extension
- MIME type detection

No attachment is executed.
"""

import hashlib
import math
import mimetypes
from collections import Counter


# Optional python-magic support
try:
    import magic

    MAGIC_AVAILABLE = True

except ImportError:
    MAGIC_AVAILABLE = False


# ============================================================
# SHA-256
# ============================================================

def calculate_sha256(data: bytes) -> str:
    """
    Calculate SHA-256 hash of attachment bytes.
    """

    return hashlib.sha256(data).hexdigest()


# ============================================================
# ENTROPY
# ============================================================

def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of attachment bytes.

    Higher entropy can indicate compressed or encrypted
    content, but entropy alone is NOT proof of maliciousness.
    """

    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    entropy = 0.0

    for count in counts.values():

        probability = count / length

        entropy -= (
            probability
            * math.log2(probability)
        )

    return round(entropy, 4)


# ============================================================
# EXTENSION
# ============================================================

def get_extension(filename: str) -> str:
    """
    Extract lowercase file extension.
    """

    if not filename:
        return ""

    filename = filename.lower().strip()

    if "." not in filename:
        return ""

    return "." + filename.rsplit(".", 1)[1]


# ============================================================
# MIME TYPE
# ============================================================

def detect_mime_type(
    data: bytes,
    filename: str
) -> str:
    """
    Detect MIME type using libmagic when available.

    Falls back to Python's mimetypes module.
    """

    # --------------------------------------------------------
    # Try libmagic
    # --------------------------------------------------------

    if MAGIC_AVAILABLE and data:

        try:

            detected = magic.from_buffer(
                data,
                mime=True
            )

            if detected:
                return detected

        except Exception:
            pass

    # --------------------------------------------------------
    # Fallback to filename
    # --------------------------------------------------------

    guessed_type, _ = mimetypes.guess_type(
        filename
    )

    if guessed_type:
        return guessed_type

    return "application/octet-stream"


# ============================================================
# COMPLETE METADATA
# ============================================================

def extract_metadata(
    filename: str,
    data: bytes
) -> dict:
    """
    Extract complete static metadata for an attachment.
    """

    if data is None:
        data = b""

    entropy = calculate_entropy(data)

    return {

        "filename": filename,

        "extension": get_extension(
            filename
        ),

        "size": len(data),

        "sha256": calculate_sha256(
            data
        ),

        "entropy": entropy,

        "detected_mime_type": detect_mime_type(
            data,
            filename
        ),
    }