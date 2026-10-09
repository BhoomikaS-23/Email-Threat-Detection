import os
import sys

import joblib

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from schemas import ParsedEmail, EngineResult

MODEL_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "models", "phishing_model.joblib"
)

_bundle = None


def _load():
    global _bundle
    if _bundle is None:
        _bundle = joblib.load(MODEL_PATH)
    return _bundle


def classify_email(parsed_email: ParsedEmail) -> EngineResult:
    bundle = _load()
    vectorizer, model = bundle["vectorizer"], bundle["model"]

    text = f"{parsed_email.subject} {parsed_email.body}"
    vec = vectorizer.transform([text]).tocsr()

    prob = float(model.predict_proba(vec)[0][1])

    names = vectorizer.get_feature_names_out()
    contributions = vec.data * model.coef_[0][vec.indices]
    ranked = sorted(zip(contributions, vec.indices), reverse=True)[:5]
    top_words = [names[i] for value, i in ranked if value > 0]

    if prob >= 0.7:
        verdict = "fail"
    elif prob >= 0.4:
        verdict = "suspicious"
    else:
        verdict = "pass"

    evidence = [f"Phishing probability: {prob:.2f}"]
    if top_words:
        evidence.append("Words pushing toward phishing: " + ", ".join(top_words))

    return EngineResult(
        engine_name="nlp_engine",
        score=round(prob, 2),
        verdict=verdict,
        evidence=evidence,
    )


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")

    from parser.parser import parse_email_file

    for path in ["data/raw/real.eml", "parser/demo.eml"]:
        result = classify_email(parse_email_file(path))
        print(path, "->", result.verdict, result.score)
        for e in result.evidence:
            print("  -", e)