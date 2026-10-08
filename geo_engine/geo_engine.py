import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import urllib.request

from schemas import ParsedEmail, EngineResult

GEO_URL = (
    "http://ip-api.com/json/{ip}"
    "?fields=status,country,regionName,city,isp,proxy,hosting"
)


def lookup_ip(ip):
    try:
        with urllib.request.urlopen(GEO_URL.format(ip=ip), timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None

    if data.get("status") != "success":
        return None

    return data


def trace_origin(parsed_email: ParsedEmail) -> EngineResult:
    ip = parsed_email.origin_ip

    if not ip:
        return EngineResult(
            engine_name="geo_engine",
            score=0.2,
            verdict="suspicious",
            evidence=["No public origin IP found in Received headers"],
        )

    data = lookup_ip(ip)

    if data is None:
        return EngineResult(
            engine_name="geo_engine",
            score=0.0,
            verdict="unknown",
            evidence=[f"Origin IP {ip}: geolocation lookup failed"],
        )

    evidence = [
        f"Origin IP: {ip}",
        f"Location: {data['city']}, {data['regionName']}, {data['country']}",
        f"Network: {data['isp']}",
    ]

    score = 0.0

    if data.get("proxy"):
        score += 0.5
        evidence.append("Origin IP is flagged as a proxy/VPN")

    if data.get("hosting"):
        evidence.append("Origin IP belongs to a hosting/data-center network")

    verdict = "suspicious" if score > 0 else "pass"

    return EngineResult(
        engine_name="geo_engine",
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
    result = trace_origin(email)

    print(result.engine_name, result.score, result.verdict)
    for e in result.evidence:
        print(" -", e)