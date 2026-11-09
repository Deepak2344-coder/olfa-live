import sys, json, random, time, collections
sys.path.insert(0, "/home/claude/train")
import numpy as np, pandas as pd, joblib
from olfa_model.host_features import host_of, registrable, numeric
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupShuffleSplit, GroupKFold
from sklearn.metrics import roc_auc_score, average_precision_score
from xgboost import XGBClassifier

t0 = time.time(); R = random.Random(42)
log = lambda *a: print(f"[{time.time()-t0:6.0f}s]", *a, flush=True)

# ---------- data
tr = pd.read_csv("data/top-1m.csv", header=None, names=["rank", "domain"])
tranco_regs = set(tr.domain.str.lower())
log("tranco", len(tr))

phish_raw = [l.strip() for l in open("data/phish_urls.txt", errors="ignore") if l.strip()]
rows, seen, per_reg, dropped_pop, total_parsed = [], set(), collections.Counter(), 0, 0
R.shuffle(phish_raw)
for u in phish_raw:
    h = host_of(u)
    if not h or "." not in h or len(h) > 100: continue
    total_parsed += 1
    reg = registrable(h)
    if reg in tranco_regs: dropped_pop += 1; continue          # phishing on a popular domain: host alone cannot tell
    if h in seen or per_reg[reg] >= 8: continue
    seen.add(h); per_reg[reg] += 1; rows.append((h, reg, 1, "new_phish"))
    if len(rows) >= 200_000: break
log(f"new phishing hosts {len(rows)}; phishing URLs on top-1M domains (excluded, ambiguous): {dropped_pop}/{total_parsed}")

old = pd.read_csv("../hm_backend/data/urlset.csv", encoding="latin-1", on_bad_lines="skip", low_memory=False)[["domain", "label"]].dropna()
old = old[old.label.isin([0, 1, "0", "1", 0.0, 1.0])]
n_old = collections.Counter()
for d, l in zip(old.domain, old.label.astype(float).astype(int)):
    h = host_of(str(d)); 
    if not h or "." not in h or len(h) > 100 or h in seen: continue
    reg = registrable(h)
    if l == 1 and reg in tranco_regs: continue
    seen.add(h); rows.append((h, reg, l, "old_phish" if l else "old_legit")); n_old[l] += 1
log("urlset.csv hosts:", dict(n_old))

SUBS = ["docs","mail","app","blog","support","login","accounts","shop","api","help","secure","portal","my","m","store","cdn","news","careers","community","status","dev","web","online"]
sample = tr.sample(260_000, random_state=42)
phish_regs = {r[1] for r in rows if r[2] == 1}
for d in sample.domain:
    d = d.lower()
    if d in phish_regs or "." not in d: continue
    h = (R.choice(SUBS) + "." + d) if R.random() < 0.25 else d
    rows.append((h, d, 0, "tranco"))
df = pd.DataFrame(rows, columns=["host", "reg", "y", "src"]).drop_duplicates("host")
log(df.groupby(["src", "y"]).size().to_dict())

# ---------- split by registrable domain
gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
tri, tei = next(gss.split(df, df.y, df.reg))
train, test = df.iloc[tri].reset_index(drop=True), df.iloc[tei].reset_index(drop=True)
log("train", len(train), "test", len(test), "phish share", round(train.y.mean(), 3))

wrap = lambda s: "^" + s + "$"
def make_vec(): return TfidfVectorizer(analyzer="char", ngram_range=(2, 5), min_df=3, max_features=300_000, sublinear_tf=True, dtype=np.float32)
def fit_lr(X, y): return LogisticRegression(C=4.0, max_iter=300, solver="liblinear", class_weight="balanced").fit(X, y)

# stage 1: char n-gram LR, out-of-fold for the train set so stage 2 never sees its own labels
oof = np.zeros(len(train))
for k, (a, b) in enumerate(GroupKFold(4).split(train, train.y, train.reg)):
    v = make_vec(); Xa = v.fit_transform(train.host.iloc[a].map(wrap)); m = fit_lr(Xa, train.y.iloc[a])
    oof[b] = m.predict_proba(v.transform(train.host.iloc[b].map(wrap)))[:, 1]; log("lr fold", k)
vec = make_vec(); Xtr = vec.fit_transform(train.host.map(wrap)); lr = fit_lr(Xtr, train.y)
lr_test = lr.predict_proba(vec.transform(test.host.map(wrap)))[:, 1]
log("lr-only test AUC", round(roc_auc_score(test.y, lr_test), 5))

# stage 2: gradient boosting on hand features + LR score
def suffix_of(h): 
    from olfa_model.host_features import _ext
    return _ext(h).suffix
def feats(hosts): return pd.DataFrame([numeric(h) for h in hosts])
Ftr, Fte = feats(train.host), feats(test.host); log("features done")
# smoothed suffix prior, out-of-fold
tr_suf = train.host.map(suffix_of); te_suf = test.host.map(suffix_of)
def te_map(suf, y, a=20):
    g = pd.DataFrame({"s": suf, "y": y}).groupby("s").y.agg(["sum", "count"]); p = y.mean()
    return ((g["sum"] + a * p) / (g["count"] + a)).to_dict(), p
suf_oof = np.zeros(len(train))
for a, b in GroupKFold(4).split(train, train.y, train.reg):
    mp, p = te_map(tr_suf.iloc[a], train.y.iloc[a]); suf_oof[b] = tr_suf.iloc[b].map(mp).fillna(p).values
suf_map, suf_prior = te_map(tr_suf, train.y)
Ftr["suffix_rate"], Fte["suffix_rate"] = suf_oof, te_suf.map(suf_map).fillna(suf_prior).values
Ftr["lr_score"], Fte["lr_score"] = oof, lr_test
xgb = XGBClassifier(n_estimators=400, max_depth=6, learning_rate=0.06, subsample=0.8, colsample_bytree=0.8, tree_method="hist", n_jobs=-1, eval_metric="logloss", random_state=42)
xgb.fit(Ftr, train.y)
p_test = xgb.predict_proba(Fte)[:, 1]
# also an OOF-free estimate of train scores for threshold picking: use LR OOF stacked prediction via quick CV of xgb is costly; pick threshold on a held-out slice of TRAIN groups
log("xgb-stack test AUC", round(roc_auc_score(test.y, p_test), 5))

# ---------- honest evaluation
def report(mask, name):
    y, p = test.y[mask], p_test[mask]
    return {"n": int(mask.sum())}
res = {"auc": roc_auc_score(test.y, p_test), "ap": average_precision_score(test.y, p_test)}
for thr in (0.5, 0.8, 0.9, 0.95, 0.99):
    pred = p_test >= thr
    fpr_all = pred[(test.y == 0).values].mean(); fpr_old = pred[((test.src == "old_legit")).values].mean(); fpr_tr = pred[((test.src == "tranco")).values].mean()
    rec_new = pred[((test.src == "new_phish")).values].mean(); rec_old = pred[((test.src == "old_phish")).values].mean()
    log(f"thr {thr:.2f}: false-alarm all {fpr_all:.4f} | small old sites {fpr_old:.4f} | tranco {fpr_tr:.4f} | catches new phish {rec_new:.4f} | old phish {rec_old:.4f}")
res["by_thr"] = None
joblib.dump({"vec": vec, "lr": lr, "xgb": xgb, "suffix_map": suf_map, "suffix_prior": suf_prior, "columns": list(Ftr.columns),
             "polarity": "1 = phishing, 0 = legitimate", "version": "olfa-host-v2",
             "auc": float(res["auc"]), "ap": float(res["ap"]), "n_train": len(train)}, "olfa_model/olfa_host_v2.joblib", compress=3)
test.assign(p=p_test).to_csv("olfa_model/test_predictions.csv", index=False)
log("saved")
