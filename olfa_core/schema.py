"""Shared Olfa risk-score helpers (same contract as features/shared/risk_schema.py)."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

THRESHOLDS = {"suspicious": 0.4, "dangerous": 0.75}
SEVERITIES = ["low", "medium", "high"]


def clamp(value: Any) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return 0.0
    if v != v:
        return 0.0
    return min(1.0, max(0.0, v))


def level_from_score(score: Any) -> str:
    s = clamp(score)
    if s >= THRESHOLDS["dangerous"]:
        return "dangerous"
    if s >= THRESHOLDS["suspicious"]:
        return "suspicious"
    return "safe"


def reason(code: str, message: str, severity: str = "medium", details: Optional[Dict[str, Any]] = None,
           source: Optional[str] = None) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "code": code,
        "message": message,
        "severity": severity if severity in SEVERITIES else "medium",
    }
    if source:
        entry["source"] = source  # which pillar produced it
    if details:
        entry["details"] = details
    return entry


def make_result(url: str, score: Any, reasons: Optional[Iterable[Dict[str, Any]]] = None, **extra: Any) -> Dict[str, Any]:
    s = round(clamp(score), 4)
    out: Dict[str, Any] = {"url": url, "score": s, "level": level_from_score(s), "reasons": list(reasons or [])}
    out.update(extra)
    return out
