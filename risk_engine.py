"""Explainable URL-risk assessment built on the project model and URL analyzer.

This module does not train or alter the existing model.  Its result combines
the model's phishing-class score with transparent structural heuristics.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import re
from typing import Any

try:
    import joblib
except ImportError:  # Lets URL analysis remain usable in a partially installed environment.
    joblib = None

from url_analyzer import analyze_url


PROJECT_DIR = Path(__file__).resolve().parent
MODEL_WEIGHT = 0.60
HEURISTIC_WEIGHT = 0.40


def _normalize_for_model(url: str) -> str:
    """Match the preprocessing used when the existing classifier was trained."""
    value = str(url).lower()
    value = re.sub(r"^https?://", "", value)
    return re.sub(r"^www\.", "", value)


@lru_cache(maxsize=1)
def load_model() -> tuple[Any, Any]:
    """Load and cache the existing classifier and vectorizer without retraining."""
    if joblib is None:
        raise RuntimeError("joblib is not installed; the ML score is unavailable.")
    model = joblib.load(PROJECT_DIR / "phishing_model.pkl")
    vectorizer = joblib.load(PROJECT_DIR / "vectorizer.pkl")
    return model, vectorizer


@lru_cache(maxsize=1)
def load_trusted_domains() -> set[str]:
    """Load normalized base domains from the project's trusted-domain list."""
    try:
        with (PROJECT_DIR / "trusted_domains.txt").open(encoding="utf-8") as file:
            return {line.strip().lower() for line in file if line.strip() and not line.startswith("#")}
    except OSError:
        return set()


def calculate_ml_score(url: str) -> tuple[float | None, str | None]:
    """Return the model's phishing-class score on a 0--100 scale.

    This is a classifier output, not a real-world probability of phishing.
    """
    try:
        model, vectorizer = load_model()
        probabilities = model.predict_proba(vectorizer.transform([_normalize_for_model(url)]))[0]
        classes = list(model.classes_)
        phishing_index = classes.index(1) if 1 in classes else len(classes) - 1
        return round(float(probabilities[phishing_index]) * 100, 2), None
    except Exception as exc:  # A bad installation or corrupt model must not break URL analysis.
        return None, "ML score unavailable: " + str(exc)


def calculate_heuristic_score(analysis: dict, is_trusted_domain: bool) -> tuple[int, list[str], list[str]]:
    """Calculate a bounded, readable structural-risk score and explanations."""
    score = 0
    negative: list[str] = []
    positive: list[str] = []

    def add(points: int, message: str) -> None:
        nonlocal score
        score += points
        negative.append(message)

    if is_trusted_domain:
        # Trusted status is a legitimacy signal, not negative structural risk.
        # Do not subtract it here: that could erase real URL-level warning signs.
        # Its bounded benefit is applied later as the ML-score safeguard.
        positive.append("Trusted base domain matched the local trusted-domain list")
    if analysis.get("is_https"):
        positive.append("Uses HTTPS")
    else:
        add(4, "Uses HTTP instead of HTTPS")
    if analysis.get("is_ip_address"):
        add(22, "Uses an IP address instead of a domain name")
    else:
        positive.append("Uses a domain name rather than an IP address")
    if analysis.get("is_localhost_or_private_ip"):
        add(18, "Uses localhost or a private IP address")
    if analysis.get("has_suspicious_keywords"):
        words = ", ".join(analysis["suspicious_keywords"])
        add(min(20, 5 * len(analysis["suspicious_keywords"])), "Suspicious keywords found: " + words)
    if analysis.get("has_suspicious_tld"):
        add(18, "Suspicious TLD detected: ." + analysis.get("tld", ""))
    if analysis.get("has_excessive_hyphens"):
        add(7, "Excessive hyphens in the host name")
    if analysis.get("has_at_symbol"):
        add(12, "Contains an @ symbol")
    if analysis.get("has_non_standard_port"):
        add(8, "Uses a non-standard port: " + str(analysis.get("port")))
    if analysis.get("is_punycode_or_idn"):
        add(14, "Uses a punycode or internationalized domain")
    if analysis.get("has_encoded_characters"):
        add(8, "Contains URL-encoded characters")
    if analysis.get("url_length", 0) > 200:
        add(10, "Unusually long URL")
    elif analysis.get("url_length", 0) > 100:
        add(5, "Long URL")
    if analysis.get("domain_length", 0) > 50:
        add(6, "Unusually long domain name")
    if analysis.get("subdomain_count", 0) >= 3:
        add(8, "Many subdomains")
    if analysis.get("query_parameter_count", 0) >= 5:
        add(5, "Many query parameters")

    return max(0, min(100, score)), positive, negative


def get_strong_malicious_signals(analysis: dict) -> list[str]:
    """Return structural signals strong enough to bypass trusted-domain capping.

    A single weak sign (for example, HTTP or a custom port) is not sufficient.
    The combined rules below make the definition visible and easy to adjust.
    """
    strong: list[str] = []
    if analysis.get("is_ip_address"):
        strong.append("IP address used as host")
    if analysis.get("is_localhost_or_private_ip"):
        strong.append("localhost or private IP address")
    if analysis.get("has_at_symbol"):
        strong.append("@ symbol in URL")
    if analysis.get("is_punycode_or_idn"):
        strong.append("punycode or IDN domain")
    if analysis.get("has_suspicious_tld"):
        strong.append("suspicious TLD")
    if len(analysis.get("suspicious_keywords", [])) >= 2:
        strong.append("multiple suspicious keywords")

    other_suspicious = any((
        analysis.get("is_ip_address"),
        analysis.get("is_localhost_or_private_ip"),
        analysis.get("has_at_symbol"),
        analysis.get("is_punycode_or_idn"),
        analysis.get("has_suspicious_tld"),
        analysis.get("has_encoded_characters"),
        bool(analysis.get("suspicious_keywords")),
    ))
    if analysis.get("has_excessive_hyphens") and other_suspicious:
        strong.append("excessive hyphens combined with another suspicious signal")
    if analysis.get("has_non_standard_port") and other_suspicious:
        strong.append("non-standard port combined with another suspicious signal")
    return strong


def get_risk_level(score: float) -> tuple[str, str]:
    """Map the final 0--100 score to dashboard-friendly labels."""
    if score < 25:
        return "Low", "Likely Safe"
    if score < 50:
        return "Medium", "Suspicious"
    if score < 75:
        return "High", "Likely Phishing"
    return "Critical", "Likely Phishing"


def analyze_url_risk(url: str) -> dict:
    """Return a safe, explainable combined ML and structural URL assessment."""
    analysis = analyze_url(url)
    safe_url = url if isinstance(url, str) else str(url)

    if not analysis.get("valid"):
        message = "URL could not be structurally parsed: " + (analysis.get("error") or "unknown error")
        return {
            "url": safe_url,
            "risk_score": 25,
            "risk_level": "Medium",
            "verdict": "Suspicious",
            "model_score": None,
            "signals": [message],
            "positive_signals": [],
            "negative_signals": [message],
            "analysis": analysis,
        }

    is_trusted_domain = analysis.get("domain", "").lower() in load_trusted_domains()
    heuristic_score, positive, negative = calculate_heuristic_score(analysis, is_trusted_domain)
    strong_signals = get_strong_malicious_signals(analysis)
    model_score, model_error = calculate_ml_score(safe_url)
    trusted_safeguard_applied = False

    if model_score is None:
        # A missing ML dependency should degrade gracefully, not hide structural signals.
        risk_score = heuristic_score
        negative.append(model_error or "ML score unavailable")
    else:
        risk_score = round(MODEL_WEIGHT * model_score + HEURISTIC_WEIGHT * heuristic_score)
        if is_trusted_domain and not strong_signals:
            # A model can overreact to a harmless path or text on a known domain.
            # The cap still allows weak structural concerns to produce Medium risk.
            safeguard_cap = 20
            if risk_score > safeguard_cap:
                risk_score = safeguard_cap
                trusted_safeguard_applied = True
                positive.append(
                    "Trusted-domain safeguard limited ML-only score inflation; no strong malicious structure was found"
                )

    risk_level, verdict = get_risk_level(risk_score)
    return {
        "url": safe_url,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "model_score": model_score,
        "heuristic_score": heuristic_score,
        "strong_malicious_signals": strong_signals,
        "trusted_domain_safeguard_applied": trusted_safeguard_applied,
        "signals": negative + positive,
        "positive_signals": positive,
        "negative_signals": negative,
        "analysis": analysis,
    }
