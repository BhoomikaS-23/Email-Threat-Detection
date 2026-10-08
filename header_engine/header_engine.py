import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
from schemas import ParsedEmail, EngineResult


def check_spf(auth_results_header):
    if not auth_results_header:
        return "absent"
    match = re.search(r"spf=(\w+)", auth_results_header, re.IGNORECASE)
    return match.group(1).lower() if match else "absent"


def check_dkim(auth_results_header):
    if not auth_results_header:
        return "absent"
    match = re.search(r"dkim=(\w+)", auth_results_header, re.IGNORECASE)
    return match.group(1).lower() if match else "absent"


def check_dmarc(auth_results_header):
    if not auth_results_header:
        return "absent"
    match = re.search(r"dmarc=(\w+)", auth_results_header, re.IGNORECASE)
    return match.group(1).lower() if match else "absent"


def extract_email_address(header_value):
    if not header_value:
        return ""
    match = re.search(r"[\w\.\-]+@[\w\.\-]+", header_value)
    return match.group(0).lower() if match else ""


def analyze_headers(parsed_email: ParsedEmail) -> EngineResult:
    evidence = []
    score = 0.0

    auth_results = parsed_email.headers.get("Authentication-Results", "")

    spf = check_spf(auth_results)
    dkim = check_dkim(auth_results)
    dmarc = check_dmarc(auth_results)

    if spf not in ("pass",):
        score += 0.3
        evidence.append(f"SPF check: {spf}")

    if dkim not in ("pass",):
        score += 0.3
        evidence.append(f"DKIM check: {dkim}")

    if dmarc not in ("pass",):
        score += 0.2
        evidence.append(f"DMARC check: {dmarc}")

    from_addr = extract_email_address(parsed_email.sender)
    reply_to = extract_email_address(parsed_email.headers.get("Reply-To", ""))

    if reply_to and reply_to != from_addr:
        score += 0.2
        evidence.append(f"Reply-To ({reply_to}) differs from From ({from_addr})")

    score = min(score, 1.0)

    if score >= 0.6:
        verdict = "fail"
    elif score > 0:
        verdict = "suspicious"
    else:
        verdict = "pass"

    return EngineResult(
        engine_name="header_engine",
        score=score,
        verdict=verdict,
        evidence=evidence if evidence else ["All header checks passed"],
    )
if __name__ == "__main__":
    import sys, os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from parser.parser import parse_email_file

    email = parse_email_file("parser/demo.eml")
    result = analyze_headers(email)

    print(result.engine_name, result.score, result.verdict)
    for e in result.evidence:
        print(" -", e)