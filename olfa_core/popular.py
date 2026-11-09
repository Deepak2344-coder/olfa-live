"""Popular-domain lookup (top-100k list shipped with the ML model).

Attackers register fresh domains, which are not on this list, so an established
site is safe from *name-based* brand rules (amazonaws.com, mail.ru, line.me).
"""
from __future__ import annotations
from functools import lru_cache
from pathlib import Path

_FILE = Path(__file__).resolve().parent.parent / "models" / "top100k_domains.txt"


@lru_cache(maxsize=1)
def _load() -> frozenset:
    try:
        return frozenset(l.strip().lower() for l in _FILE.read_text().splitlines() if l.strip())
    except OSError:
        return frozenset()


def is_popular(registrable: str) -> bool:
    return (registrable or "").lower() in _load()
