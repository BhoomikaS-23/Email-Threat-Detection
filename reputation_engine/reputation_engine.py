import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import socket

from schemas import ParsedEmail, EngineResult

DNSBLS = ["zen.spamhaus.org", "bl.spamcop.net"]


def reverse_ip(ip):
    return ".".join(reversed(ip.split(".")))


def check_dnsbl(ip, zone):
    query = f"{reverse_ip(ip)}.{zone}"

    try:
        answer = socket.gethostbyname(query)
    except socket.gaierror:
        return False  # name not found = not listed

    # Spamhaus answers 127.255.255.x when it refuses the query
    if answer.startswith("127.255.255."):
        return None

    return True


def check_reputation(parsed_email: ParsedEmail) -> EngineResult:
    ip = parsed_email.origin_ip

    if not ip or ":" in ip:
        return EngineResult(
            engine_name="reputation_engine",
            score=0.0,
            verdict="unknown",
            evidence=["No IPv4 origin IP available for reputation check"],
        )

    score = 0.0
    evidence = []

    for zone in DNSBLS:
        listed = check_dnsbl(ip, zone)

        if listed is True:
            score += 0.5
            evidence.append(f"{ip} is listed on {zone}")
        elif listed is None:
            evidence.append(f"{zone} refused the query (inconclusive)")

    score = min(score, 1.0)

    if score >= 0.5:
        verdict = "fail"
    else:
        verdict = "pass"
        evidence.append(f"{ip} not found on checked blocklists")

    return EngineResult(
        engine_name="reputation_engine",
        score=score,
        verdict=verdict,
        evidence=evidence,
    )


if __name__ == "__main__":
    import os
    import sys

    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.stdout.reconfigure(encoding="utf-8")

    from parser.parser import parse_email_file

    email = parse_email_file("data/raw/real.eml")
    result = check_reputation(email)

    print(result.engine_name, result.score, result.verdict)
    for e in result.evidence:
        print(" -", e)

    # Sanity check: 127.0.0.2 is the standard "always listed" test address
    print("Test listing (should be True):", check_dnsbl("127.0.0.2", "bl.spamcop.net"))