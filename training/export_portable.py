"""Export olfa_host_v2.joblib to version-independent files (run once, with the sklearn that trained it).
Output: models/olfa_host_v2_portable/{tfidf.json, lr.npz, xgb.json, meta.json}"""
import json, sys, warnings
from pathlib import Path
import joblib, numpy as np
warnings.simplefilter("ignore")
root = Path(__file__).resolve().parent.parent
b = joblib.load(root / "models" / "olfa_host_v2.joblib")
out = root / "models" / "olfa_host_v2_portable"; out.mkdir(exist_ok=True)
vec = b["vec"]
assert vec.analyzer == "char" and vec.ngram_range == (2, 5) and vec.lowercase and vec.sublinear_tf and vec.norm == "l2" and vec.use_idf
json.dump({"vocab": {k: int(v) for k, v in vec.vocabulary_.items()}}, open(out / "tfidf.json", "w"))
np.savez(out / "lr.npz", idf=vec.idf_.astype(np.float64), coef=b["lr"].coef_[0].astype(np.float64), intercept=np.float64(b["lr"].intercept_[0]))
b["xgb"].get_booster().save_model(str(out / "xgb.json"))
json.dump({"columns": b["columns"], "suffix_map": b["suffix_map"], "suffix_prior": float(b["suffix_prior"]),
           "polarity": "1 = phishing", "version": b["version"], "auc": b["auc"]}, open(out / "meta.json", "w"))
print("exported to", out)
