"""Fuse the four pillars into one shared-schema verdict.

Design rules (each one exists because of a failure we saw):
  * Evidence combines with noisy-OR, so several weak signals add up but no
    single weak signal can cross "dangerous" by itself.
  * The ML URL score is capped and only counted when something *else* also looks
    off. On its own it flags github.com/ and example.com as 98% phishing.
  * Community "confirmed" verdicts act as strong evidence, not as an override:
    confirmed-safe only lowers the score if there is no high-severity finding.
  * A pillar that could not run (offline, TLS refused) reports `unavailable`
    instead of silently counting as "clean".
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .schema import level_from_score, make_result, clamp

SEVERITY_WEIGHT = {"high": 0.55, "medium": 0.25, "low": 0.08}
ML_CAP = 0.30
# Reasons that are informational/hygiene: shown, but weighted down because legit sites trigger them.
HYGIENE = {"cookies_missing_secure", "weak_tls", "expiring_certificate", "new_certificate", "urgency_language",
           "long_url", "hidden_link_targets"}
HYGIENE_FACTOR = 0.6

PILLARS = ("threat", "web", "certificate", "intel")


def _noisy_or(weights: List[float]) -> float:
    p = 1.0
    for w in weights:
        p *= 1.0 - clamp(w)
    return 1.0 - p


def _pillar_score(reasons: List[dict]) -> float:
    ws = []
    for r in reasons:
        w = SEVERITY_WEIGHT.get(r.get("severity", "medium"), 0.25)
        if r["code"] in HYGIENE:
            w *= HYGIENE_FACTOR
        ws.append(w)
    return _noisy_or(ws)


def fuse(url: str, *, threat: List[dict], web: List[dict], cert: List[dict], intel: List[dict],
         ml: Optional[Dict[str, float]], intel_status: str, status: Dict[str, str],
         extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    groups = {"threat": list(threat), "web": list(web), "certificate": list(cert), "intel": list(intel)}

    # ML: add as a capped, explained signal, only with corroboration or an extreme score.
    ml_reason: Optional[dict] = None
    other = [r for g in groups.values() for r in g if r["code"] not in HYGIENE]
    if ml and ml["risk"] >= 0.95 and other and not ml.get("popular_domain"):
        ml_reason = {"code": "ml_phishing_url", "severity": "medium", "source": "threat",
                     "message": "The URL's character patterns resemble known phishing links.",
                     "details": {"model_risk": round(ml["risk"], 3), "capped_weight": ML_CAP}}
        groups["threat"].append(ml_reason)

    pillar_scores = {}
    for name, rs in groups.items():
        s = _pillar_score([r for r in rs if r is not ml_reason])
        if name == "threat" and ml_reason:
            s = _noisy_or([s, ML_CAP * ml["risk"]])
        pillar_scores[name] = round(s, 3)

    score = _noisy_or(list(pillar_scores.values()))

    # Community consensus
    if intel_status == "confirmed_malicious":
        score = max(score, 0.9)
    elif intel_status == "confirmed_safe":
        has_high = any(r.get("severity") == "high" for g in groups.values() for r in g)
        if not has_high:
            score = min(score, 0.15)

    all_reasons = [r for g in groups.values() for r in g]
    order = {"high": 0, "medium": 1, "low": 2}
    all_reasons.sort(key=lambda r: order.get(r.get("severity", "medium"), 1))
    pillars = {n: {"score": pillar_scores[n], "level": level_from_score(pillar_scores[n]), "status": status.get(n, "ok"),
                   "reasons": [r["code"] for r in groups[n]]} for n in groups}
    result = make_result(url, score, all_reasons, pillars=pillars)
    if ml:
        result["ml"] = {k: (round(v, 4) if isinstance(v, float) else v) for k, v in ml.items()}
        result["ml"]["note"] = "hostname model, held-out AUC 0.91: a supporting signal only; ignored for top-100k domains"
    if extra:
        result.update(extra)
    unavailable = [n for n, st in status.items() if st != "ok"]
    result["coverage"] = {"unavailable_pillars": unavailable,
                          "complete": not unavailable}
    return result
