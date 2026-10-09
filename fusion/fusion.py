import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from schemas import ParsedEmail, EngineResult
from header_engine.header_engine import analyze_headers
from geo_engine.geo_engine import trace_origin
from reputation_engine.reputation_engine import check_reputation

# Each engine returns a score from 0 to 1. Weights say how much each one counts.
# nlp_engine will be added here later.
ENGINES = {
    "header_engine": (analyze_headers, 0.4),
    "geo_engine": (trace_origin, 0.2),
    "reputation_engine": (check_reputation, 0.4),
}


def run_engines(parsed_email: ParsedEmail) -> list[EngineResult]:
    results = []

    for name, (func, _) in ENGINES.items():
        try:
            results.append(func(parsed_email))
        except Exception as e:
            results.append(EngineResult(
                engine_name=name,
                score=0.0,
                verdict="unknown",
                evidence=[f"{name} failed: {e}"],
            ))

    return results


def fuse(results: list[EngineResult]) -> dict:
    total_weight = 0.0
    weighted_sum = 0.0

    for r in results:
        if r.verdict == "unknown":
            continue  # engines that couldn't decide don't count

        weight = ENGINES[r.engine_name][1]
        weighted_sum += r.score * weight
        total_weight += weight

    risk_score = weighted_sum / total_weight if total_weight else 0.0

    if risk_score >= 0.6:
        level = "HIGH"
    elif risk_score >= 0.3:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "risk_score": round(risk_score, 2),
        "risk_level": level,
        "engine_results": results,
    }


def analyze_email(parsed_email: ParsedEmail) -> dict:
    return fuse(run_engines(parsed_email))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")

    from parser.parser import parse_email_file

    email = parse_email_file("data/raw/real.eml")
    report = analyze_email(email)

    print("RISK:", report["risk_level"], report["risk_score"])
    for r in report["engine_results"]:
        print(f"\n[{r.engine_name}] {r.verdict} ({r.score})")
        for e in r.evidence:
            print("  -", e)