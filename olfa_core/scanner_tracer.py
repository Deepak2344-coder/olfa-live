"""Loads features/redirect-tracer/tracer.py by path (that folder also has an app.py
that would shadow ours if it were put on sys.path)."""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("olfa_tracer", ROOT / "features" / "redirect-tracer" / "tracer.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["olfa_tracer"] = mod  # dataclasses need the module registered
    spec.loader.exec_module(mod)
    return mod


tracer = _load()
