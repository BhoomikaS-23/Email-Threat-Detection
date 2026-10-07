import sys
sys.stdout.reconfigure(encoding="utf-8")

import email
import ipaddress
import re

from email.header import decode_header
from email import policy
from html.parser import HTMLParser

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from schemas import ParsedEmail


# ============================================================
# HTML → TEXT
# ============================================================

class HTMLToTextParser(HTMLParser):

    def __init__(self):
        super().__init__(convert_charrefs=True)

        self.text = []
        self.ignore_depth = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        tag = tag.lower()

        if tag in {"script", "style", "noscript", "template"}:
            self.ignore_depth += 1
            return

        style = attrs.get("style", "")
        normalized_style = re.sub(r"\s+", "", style.lower())

        if (
            "display:none" in normalized_style
            or "visibility:hidden" in normalized_style
        ):
            self.ignore_depth += 1

    def handle_endtag(self, tag):
        tag = tag.lower()

        if tag in {"script", "style", "noscript", "template"}:
            if self.ignore_depth > 0:
                self.ignore_depth -= 1
            return

        if self.ignore_depth > 0:
            self.ignore_depth -= 1

    def handle_data(self, data):
        if self.ignore_depth == 0:
            self.text.append(data)

    def handle_comment(self, data):
        pass

    def get_text(self):
        text = " ".join(self.text)
        text = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff\u00ad]", "", text)
        text = re.sub(r"\s+", " ", text)
        return text.strip()


# ============================================================
# MIME HEADER DECODING
# ============================================================

def decode_mime_words(value):
    if not value:
        return ""

    decoded = []
    try:
        for part, encoding in decode_header(value):
            if isinstance(part, bytes):
                try:
                    decoded.append(part.decode(encoding or "utf-8", errors="replace"))
                except (LookupError, UnicodeDecodeError):
                    decoded.append(part.decode("utf-8", errors="replace"))
            else:
                decoded.append(part)
    except Exception:
        return str(value)

    return "".join(decoded)


# ============================================================
# IP VALIDATION
# ============================================================

def is_public_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_global
    except ValueError:
        return False


# ============================================================
# EXTRACT IPs FROM RECEIVED HEADER
# ============================================================

def extract_ips(text):
    candidates = []

    ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    candidates.extend(re.findall(ipv4_pattern, text))

    ipv6_pattern = r"""
        (?:
            (?:[0-9A-Fa-f]{1,4}:){2,7}
            [0-9A-Fa-f]{0,4}
        )
    """
    candidates.extend(re.findall(ipv6_pattern, text, re.VERBOSE))

    valid_ips = []
    for candidate in candidates:
        try:
            ipaddress.ip_address(candidate)
            if candidate not in valid_ips:
                valid_ips.append(candidate)
        except ValueError:
            continue

    return valid_ips


# ============================================================
# ORIGIN IP
# ============================================================

def extract_origin_ip(received_lines):
    if not received_lines:
        return None

    for line in reversed(received_lines):
        ips = extract_ips(line)
        for ip in ips:
            if is_public_ip(ip):
                return ip

    return None


# ============================================================
# BODY EXTRACTION
# ============================================================

def decode_payload(part):
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""

    charset = part.get_content_charset()
    if not charset:
        charset = "utf-8"

    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return payload.decode("utf-8", errors="replace")


def html_to_text(html):
    parser = HTMLToTextParser()
    try:
        parser.feed(html)
        parser.close()
        return parser.get_text()
    except Exception:
        return ""


def get_body(msg):
    plain_text = None
    html_text = None

    if msg.is_multipart():
        for part in msg.walk():
            disposition = part.get_content_disposition()
            if disposition == "attachment":
                continue

            content_type = part.get_content_type()

            if content_type == "text/plain":
                text = decode_payload(part)
                if text.strip():
                    plain_text = text

            elif content_type == "text/html":
                text = decode_payload(part)
                if text.strip():
                    html_text = text
    else:
        content_type = msg.get_content_type()
        text = decode_payload(msg)

        if content_type == "text/plain":
            plain_text = text
        elif content_type == "text/html":
            html_text = text

    if plain_text:
        return clean_text(plain_text)

    if html_text:
        return clean_text(html_to_text(html_text))

    return ""


# ============================================================
# TEXT CLEANING
# ============================================================

def clean_text(text):
    if not text:
        return ""

    text = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff\u00ad]", "", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


# ============================================================
# PARSE EMAIL
# ============================================================

def parse_email_file(filename):

    with open(filename, "rb") as f:
        raw_email = f.read()

    msg = email.message_from_bytes(raw_email, policy=policy.default)

    # --------------------------------------------------------
    # Headers
    # --------------------------------------------------------

    subject = decode_mime_words(msg.get("Subject", ""))
    sender = decode_mime_words(msg.get("From", ""))
    recipient = decode_mime_words(msg.get("To", ""))

    received_lines = msg.get_all("Received", [])

    # --------------------------------------------------------
    # Origin IP
    # --------------------------------------------------------

    origin_ip = extract_origin_ip(received_lines)

    # --------------------------------------------------------
    # Body
    # --------------------------------------------------------

    body = get_body(msg)

    # --------------------------------------------------------
    # Result — built as a ParsedEmail, matching schemas.py
    # --------------------------------------------------------

    return ParsedEmail(
        subject=subject,
        body=body,
        sender=sender,
        recipients=[recipient] if recipient else [],
        headers=dict(msg.items()),
        received_lines=received_lines,
        origin_ip=origin_ip,
        attachments=[],
    )


# ============================================================
# TEST
# ============================================================
import os

if __name__ == "__main__":

    result = parse_email_file("parser/demo.eml")

    print("\n===== SUBJECT =====")
    print(result.subject)

    print("\n===== SENDER =====")
    print(result.sender)

    print("\n===== RECIPIENTS =====")
    print(result.recipients)

    print("\n===== ORIGIN IP =====")
    print(result.origin_ip)

    print("\n===== RECEIVED =====")
    for line in result.received_lines:
        print(line)

    print("\n===== BODY =====")
    print(result.body)