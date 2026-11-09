"""Olfa shared risk-score helpers (Python).

Mirrors features/shared/risk-schema.js so Python services and JS features emit
exactly the same JSON. Dependency-free on purpose: the backend services and the
core app both import it.

Usage:
    from features.shared.risk_schema import make_result, reason
    make_result("https://x.example", 0.93, [reason("typosquat", "Imitates paypal.", "high")])
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

# Keep in sync with features/shared/README.md and risk-schema.js.
THRESHOLDS = {"suspicious": 0.4, "dangerous": 0.75}
LEVELS = ["safe", "suspicious", "dangerous"]
SEVERITIES = ["low", "medium", "high"]


def clamp_score(value: Any) -> float:
    """Clamp anything into [0, 1]; non-numbers become 0.0."""
    try:
        score = float(value)
    except (TypeError, ValueError):
        return 0.0
    if score != score:  # NaN
        return 0.0
    return min(1.0, max(0.0, score))


def level_from_score(score: Any) -> str:
    """Map a score to 'safe' | 'suspicious' | 'dangerous'."""
    s = clamp_score(score)
    if s >= THRESHOLDS["dangerous"]:
        return "dangerous"
    if s >= THRESHOLDS["suspicious"]:
        return "suspicious"
    return "safe"


def reason(
    code: str,
    message: str,
    severity: str = "medium",
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build one entry for the ``reasons`` array."""
    entry: Dict[str, Any] = {
        "code": str(code),
        "message": str(message),
        "severity": severity if severity in SEVERITIES else "medium",
    }
    if details:
        entry["details"] = details
    return entry


def make_result(
    url: str,
    score: Any,
    reasons: Optional[Iterable[Dict[str, Any]]] = None,
    **extra: Any,
) -> Dict[str, Any]:
    """Build a complete risk result in the shared schema."""
    s = round(clamp_score(score), 4)
    result: Dict[str, Any] = {
        "url": str(url or ""),
        "score": s,
        "level": level_from_score(s),
        "reasons": list(reasons or []),
    }
    result.update(extra)
    return result


def validate_result(obj: Any) -> List[str]:
    """Cheap structural validation. Returns a list of problems (empty = valid)."""
    if not isinstance(obj, dict):
        return ["result is not a dict"]
    problems: List[str] = []
    if not isinstance(obj.get("url"), str):
        problems.append("url must be a string")
    score = obj.get("score")
    if not isinstance(score, (int, float)) or isinstance(score, bool) or not 0 <= score <= 1:
        problems.append("score must be a number between 0 and 1")
    if obj.get("level") not in LEVELS:
        problems.append("level must be safe|suspicious|dangerous")
    reasons = obj.get("reasons")
    if not isinstance(reasons, list):
        problems.append("reasons must be a list")
    else:
        for i, entry in enumerate(reasons):
            if not isinstance(entry, dict) or not isinstance(entry.get("code"), str) or not isinstance(entry.get("message"), str):
                problems.append(f"reasons[{i}] needs string code and message")
    return problems
