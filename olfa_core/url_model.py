"""Pillar 1a: ML URL classifier (XGBoost + char-n-gram logistic ensemble).

The artifacts ship without their feature extractor, so `extract_features`
re-implements the 27 columns named in metadata.json. The model's positive class
(1) means *legitimate*; everything here converts to a phishing *risk*.
"""

from __future__ import annotations

import json
import math
import re
import warnings
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlsplit

import numpy as np

from .urlparts import host_of, is_ip, split_domain

SUSPICIOUS_WORDS = (
    "login", "signin", "verify", "secure", "account", "update", "confirm", "banking", "password",
    "webscr", "ebayisapi", "paypal", "wallet", "invoice", "suspend", "unlock", "authenticate",
    "credential", "recover", "billing", "support", "alert", "free", "bonus", "kyc",
)
_HEX = re.compile(r"%[0-9a-fA-F]{2}")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def extract_features(url: str) -> Dict[str, float]:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    path_query = parts.path + (("?" + parts.query) if parts.query else "")
    sub, reg, suffix = split_domain(host)
    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    labels = host.split(".") if host else [""]
    try:
        port = parts.port
    except ValueError:
        port = None
    lowered = url.lower()
    return {
        "url_len": len(url),
        "host_len": len(host),
        "path_query_len": len(path_query),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),
        "num_at": url.count("@"),
        "num_question": url.count("?"),
        "num_equal": url.count("="),
        "num_ampersand": url.count("&"),
        "num_percent": url.count("%"),
        "num_digits": digits,
        "digit_ratio": digits / max(len(url), 1),
        "num_letters": letters,
        "num_special": sum(not c.isalnum() for c in url),
        "url_entropy": _entropy(url),
        "host_entropy": _entropy(host),
        "subdomain_count": len([p for p in sub.split(".") if p]) if sub else 0,
        "is_ip_host": 1 if is_ip(host) else 0,
        "https": 1 if parts.scheme == "https" else 0,
        "port_nonstandard": 1 if port not in (None, 80, 443) else 0,
        "punycode": 1 if "xn--" in host else 0,
        "has_hex_escape": 1 if _HEX.search(url) else 0,
        "suspicious_word_count": sum(lowered.count(w) for w in SUSPICIOUS_WORDS),
        "longest_label": max(len(l) for l in labels),
        "tld_len": len(suffix.split(".")[-1]) if suffix else 0,
    }


class UrlModel:
    """Hostname-only phishing model (olfa-host-v2). Polarity is 1 = phishing.

    Served from portable files (JSON/NPZ plus XGBoost's native JSON) so it does
    NOT depend on the scikit-learn version that trained it, and never unpickles.
    Trained on ~200k current phishing hostnames vs ~280k legitimate ones, split
    by registrable domain. Held-out AUC 0.91: a supporting signal, not a judge.
    Domains in the Tranco top 100k are exempted (brand names fool the model).
    """

    NGRAM = (2, 5)

    def __init__(self, model_dir: Path):
        self.dir = Path(model_dir)
        self.available = False
        self.error: Optional[str] = None
        self.popular: set = set()
        self._load()

    def _load(self) -> None:
        try:
            import xgboost as xgb

            d = self.dir / "olfa_host_v2_portable"
            self._vocab = json.loads((d / "tfidf.json").read_text())["vocab"]
            z = np.load(d / "lr.npz")
            self._idf, self._coef, self._b = z["idf"], z["coef"], float(z["intercept"])
            self._meta = json.loads((d / "meta.json").read_text())
            self._booster = xgb.Booster()
            self._booster.load_model(str(d / "xgb.json"))
            pop = self.dir / "top100k_domains.txt"
            if pop.exists():
                self.popular = {l.strip().lower() for l in pop.read_text().splitlines() if l.strip()}
            self.predict("http://selftest.example.com/")  # fail at startup, not on the first user request
            self.available = True
        except Exception as exc:  # noqa: BLE001 - degrade gracefully, the app still runs without ML
            self.available, self.error = False, f"{type(exc).__name__}: {exc}"

    def _lr_score(self, host: str) -> float:
        text = re.sub(r"\s\s+", " ", ("^" + host + "$").lower())
        counts: Dict[int, int] = {}
        for n in range(self.NGRAM[0], self.NGRAM[1] + 1):
            for i in range(len(text) - n + 1):
                idx = self._vocab.get(text[i:i + n])
                if idx is not None:
                    counts[idx] = counts.get(idx, 0) + 1
        if not counts:
            return 1.0 / (1.0 + math.exp(-self._b))
        w = {i: (1.0 + math.log(c)) * self._idf[i] for i, c in counts.items()}  # sublinear tf * idf
        norm = math.sqrt(sum(v * v for v in w.values()))
        z = sum(v / norm * self._coef[i] for i, v in w.items()) + self._b
        return 1.0 / (1.0 + math.exp(-z))

    def predict(self, url: str) -> Dict[str, float]:
        import xgboost as xgb
        from .host_features import _ext, host_of, numeric, registrable

        host = host_of(url)
        f = numeric(host)
        f["suffix_rate"] = self._meta["suffix_map"].get(_ext(host).suffix, self._meta["suffix_prior"])
        f["lr_score"] = self._lr_score(host)
        cols = self._meta["columns"]
        row = np.array([[float(f[c]) for c in cols]], dtype=np.float32)
        risk = float(self._booster.predict(xgb.DMatrix(row, feature_names=cols))[0])
        return {"risk": risk, "p_legit": 1.0 - risk, "popular_domain": registrable(host) in self.popular}
