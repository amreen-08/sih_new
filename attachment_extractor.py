"""
attachment_extractor.py
------------------------

Extracts file attachments from a raw .eml email.
This module ONLY extracts attachments.
It does not:
    - execute files
    - scan files
    - calculate risk
    - open URLs
    - execute macros
"""
from email.parser import BytesParser
from email.policy import default as default_policy

def extract_attachments_from_eml(eml_path: str) -> list[dict]:
    """
    Read a raw .eml file and extract its attachments.
    Returns:
    [{            "filename": "...",
                "mime_type": "...",
                "content_disposition": "...",
                "data": b"..."}]
    """
    attachments = []
    with open(eml_path, "rb") as file:
        message = BytesParser(policy=default_policy).parse(file)

    for part in message.walk():
        # Multipart containers are not actual attachments.
        if part.is_multipart():
            continue

        filename = part.get_filename()

        # No filename means this is normally a body/content part.
        if not filename:
            continue
        try:
            data = part.get_payload(decode=True)
        except Exception:
            data = None
        if data is None:
            data = b""

        attachments.append(
            {"filename": filename,
                "mime_type": part.get_content_type(),
                "content_disposition": (part.get_content_disposition()),"data": data,})
    return attachments

def extract_attachments_from_message(message) -> list[dict]:
    """
    Extract attachments from an already parsed email.message.Message.
    This function is useful when main.py/email_parser.py has already
    parsed the .eml file.
    """
    attachments = []

    for part in message.walk():
        if part.is_multipart():
            continue

        filename = part.get_filename()
        if not filename:
            continue
        try:
            data = part.get_payload(decode=True)
        except Exception:
            data = None
        if data is None:
            data = b""
        attachments.append({"filename": filename,
                "mime_type": part.get_content_type(),
                "content_disposition": (part.get_content_disposition()),"data": data,})

    return attachments

if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python attachment_extractor.py <email.eml>")
        sys.exit(1)

    eml_file = sys.argv[1]
    attachments = extract_attachments_from_eml(eml_file)
    output = []

    for attachment in attachments:
        output.append({"filename": attachment["filename"],
                "mime_type": attachment["mime_type"],
                "content_disposition": attachment["content_disposition"],
                "size": len(attachment["data"]),})
    print(json.dumps(output,indent=2))