"""
attachment_macro_analyzer.py
----------------------------

Static VBA/macro analysis using oletools.

IMPORTANT:

    - VBA is parsed statically.
    - Macros are NEVER executed.
    - Only appropriate Office/OLE/OpenXML files are sent
      to oletools.

This module deliberately avoids sending PDFs, images,
executables, etc. to oletools.
"""

import zipfile
from io import BytesIO


try:
    from oletools.olevba import VBA_Parser

    OLETOOLS_AVAILABLE = True

except ImportError:

    OLETOOLS_AVAILABLE = False


# ============================================================
# FILE TYPES THAT CAN CONTAIN VBA
# ============================================================

LEGACY_OFFICE_EXTENSIONS = {
    ".doc",
    ".dot",
    ".xls",
    ".xlt",
    ".ppt",
    ".pot",
    ".pps",
}


OPENXML_MACRO_EXTENSIONS = {
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


ALL_MACRO_EXTENSIONS = (
    LEGACY_OFFICE_EXTENSIONS
    | OPENXML_MACRO_EXTENSIONS
)


# ============================================================
# FILE SIGNATURES
# ============================================================

OLE_SIGNATURE = b"\xD0\xCF\x11\xE0"

ZIP_SIGNATURES = {
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
}


# ============================================================
# ZIP VBA CHECK
# ============================================================

def contains_vba_project(
    data: bytes
) -> bool:
    """
    Check an Office OpenXML ZIP container for
    vbaProject.bin.

    Example:

        word/vbaProject.bin
        xl/vbaProject.bin
        ppt/vbaProject.bin
    """

    try:

        with zipfile.ZipFile(
            BytesIO(data)
        ) as archive:

            for filename in archive.namelist():

                if filename.lower().endswith(
                    "vbaproject.bin"
                ):
                    return True

    except (
        zipfile.BadZipFile,
        OSError,
        ValueError,
    ):
        pass

    return False


# ============================================================
# CHECK IF FILE IS OFFICE-LIKE
# ============================================================

def is_office_candidate(
    filename: str,
    data: bytes
) -> bool:
    """
    Determine whether it makes sense to send this
    attachment to oletools.

    We use BOTH:

        1. Filename extension
        2. Actual file signature

    This prevents files such as PDFs from being incorrectly
    analyzed as VBA documents.
    """

    filename_lower = (
        filename.lower()
    )

    extension = ""

    if "." in filename_lower:
        extension = (
            "."
            + filename_lower.rsplit(
                ".",
                1
            )[1]
        )


    # --------------------------------------------------------
    # Legacy Office
    # --------------------------------------------------------

    if extension in LEGACY_OFFICE_EXTENSIONS:

        return data.startswith(
            OLE_SIGNATURE
        )


    # --------------------------------------------------------
    # Modern Office OpenXML
    # --------------------------------------------------------

    if extension in OPENXML_MACRO_EXTENSIONS:

        return (
            data.startswith(
                tuple(
                    ZIP_SIGNATURES
                )
            )
            or data.startswith(
                OLE_SIGNATURE
            )
        )


    # --------------------------------------------------------
    # Other supported OLE documents
    #
    # We only consider them if the actual bytes are OLE.
    # --------------------------------------------------------

    if data.startswith(
        OLE_SIGNATURE
    ):

        return True


    return False


# ============================================================
# MACRO ANALYSIS
# ============================================================

def analyze_macros(
    filename: str,
    data: bytes
) -> dict:
    """
    Perform safe static VBA analysis.

    PDFs, images, EXEs, ZIPs without Office structure,
    and unrelated files are NOT passed to oletools.
    """

    result = {

        "oletools_available": (
            OLETOOLS_AVAILABLE
        ),

        "analysis_performed": False,

        "macro_detected": False,

        "autoexec_count": 0,
        "suspicious_count": 0,
        "ioc_count": 0,

        "hex_obfuscation_count": 0,
        "base64_obfuscation_count": 0,
        "dridex_obfuscation_count": 0,
        "vba_obfuscation_count": 0,

        "findings": [],

        "error": None,
    }


    # ========================================================
    # SAFETY / FORMAT CHECK
    # ========================================================

    office_candidate = is_office_candidate(
        filename,
        data
    )


    # --------------------------------------------------------
    # Not an Office candidate
    # --------------------------------------------------------

    if not office_candidate:

        result["analysis_performed"] = False
        result["findings"].append(
    "Attachment is not an Office/OLE macro candidate; VBA analysis was not performed.")
        return result


    # ========================================================
    # STRUCTURAL VBA CHECK
    # ========================================================

    structural_macro = (
        contains_vba_project(data)
    )


    # ========================================================
    # OLETOOLS NOT AVAILABLE
    # ========================================================

    if not OLETOOLS_AVAILABLE:

        result["analysis_performed"] = True

        result["macro_detected"] = (
            structural_macro
        )

        if structural_macro:

            result["findings"].append(
                "vbaProject.bin detected."
            )

        result["error"] = (
            "oletools is not installed."
        )

        return result


    # ========================================================
    # OLETOOLS STATIC ANALYSIS
    # ========================================================

    vba_parser = None


    try:

        result["analysis_performed"] = True


        # ----------------------------------------------------
        # Create parser
        # ----------------------------------------------------

        vba_parser = VBA_Parser(
            filename,
            data=data
        )


        # ----------------------------------------------------
        # Detect VBA
        # ----------------------------------------------------

        has_macros = (
            vba_parser.detect_vba_macros()
        )


        result["macro_detected"] = bool(
            has_macros
            or structural_macro
        )


        # ----------------------------------------------------
        # Analyze macros
        # ----------------------------------------------------

        if has_macros:

            analysis_results = (
                vba_parser.analyze_macros()
            )


            # ------------------------------------------------
            # Counters
            # ------------------------------------------------

            result["autoexec_count"] = getattr(
                vba_parser,
                "nb_autoexec",
                0
            )

            result["suspicious_count"] = getattr(
                vba_parser,
                "nb_suspicious",
                0
            )

            result["ioc_count"] = getattr(
                vba_parser,
                "nb_iocs",
                0
            )

            result["hex_obfuscation_count"] = getattr(
                vba_parser,
                "nb_hexstrings",
                0
            )

            result["base64_obfuscation_count"] = getattr(
                vba_parser,
                "nb_base64strings",
                0
            )

            result["dridex_obfuscation_count"] = getattr(
                vba_parser,
                "nb_dridexstrings",
                0
            )

            result["vba_obfuscation_count"] = getattr(
                vba_parser,
                "nb_vbastrings",
                0
            )


            # ------------------------------------------------
            # Findings
            # ------------------------------------------------

            for item in analysis_results[:50]:

                try:

                    if len(item) == 3:

                        finding_type = item[0]

                        keyword = item[1]

                        description = item[2]

                        result["findings"].append(
                            {
                                "type": str(
                                    finding_type
                                ),

                                "keyword": str(
                                    keyword
                                ),

                                "description": str(
                                    description
                                ),
                            }
                        )

                except Exception:

                    continue


        elif structural_macro:

            result["findings"].append(
                "vbaProject.bin detected inside the Office file."
            )


    except Exception as exc:

        result["error"] = str(
            exc
        )

        result["macro_detected"] = (
            structural_macro
        )


    finally:

        if vba_parser is not None:

            try:

                vba_parser.close()

            except Exception:

                pass


    return result


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    # --------------------------------------------------------
    # Harmless PDF test
    # --------------------------------------------------------

    pdf_data = (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog >>\n"
        b"endobj\n"
        b"%%EOF\n"
    )


    result = analyze_macros(
        "test_invoice.pdf",
        pdf_data
    )


    print(
        "PDF test:"
    )

    print(
        result
    )