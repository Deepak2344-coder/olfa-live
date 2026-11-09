"""The portable model must match the original pickle, and must not need scikit-learn at runtime."""
import subprocess, sys, warnings
from pathlib import Path
import numpy as np, pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from olfa_core.url_model import UrlModel  # noqa: E402


def test_portable_loads_and_scores():
    m = UrlModel(ROOT / "models")
    assert m.available, m.error
    assert m.predict("http://paypa1-secure-login.verify-account.tk/signin")["risk"] > 0.9
    assert m.predict("https://github.com/")["risk"] < 0.5


def test_portable_matches_original_pickle():
    joblib = pytest.importorskip("joblib")
    pd = pytest.importorskip("pandas")
    warnings.simplefilter("ignore")
    from olfa_core.host_features import _ext, host_of, numeric
    try:
        b = joblib.load(ROOT / "models" / "olfa_host_v2.joblib")
        b["lr"].predict_proba(b["vec"].transform(["^probe.example$"]))  # can this scikit-learn score it at all?
    except Exception:  # noqa: BLE001 - pickle needs the scikit-learn it was trained with (>= 1.8)
        pytest.skip("pickle not usable with this scikit-learn (that is the point of the portable files)")
    m = UrlModel(ROOT / "models")
    hosts = ["github.com", "paypa1-secure-login.verify-account.tk", "web.whatsapp.com", "mylocalbakery.in", "xk3j9qv2lm.top",
             "login-microsoftonline.com.evil-host.ru", "192.0.2.7", "sbi-kyc-update-online.xyz", "stripe.com", "a.b.c.d.example.co.uk"]
    for h in hosts:
        lr = float(b["lr"].predict_proba(b["vec"].transform(["^" + h + "$"]))[0, 1])
        f = pd.DataFrame([numeric(h)]); f["suffix_rate"] = b["suffix_map"].get(_ext(h).suffix, b["suffix_prior"]); f["lr_score"] = lr
        want = float(b["xgb"].predict_proba(f[b["columns"]])[0, 1])
        assert abs(m.predict("http://" + h)["risk"] - want) < 1e-3, h
        assert abs(m._lr_score(h) - lr) < 1e-6, h


def test_runtime_does_not_import_sklearn():
    code = ("import sys; sys.modules['sklearn']=None; sys.modules['joblib']=None; sys.modules['pandas']=None;"
            f"sys.path.insert(0, r'{ROOT}'); from olfa_core.url_model import UrlModel;"
            f"m=UrlModel(r'{ROOT / 'models'}'); assert m.available, m.error; print('ok')")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0 and "ok" in out.stdout, out.stderr[-500:]
