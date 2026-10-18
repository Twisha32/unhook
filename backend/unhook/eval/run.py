"""Train and evaluate on a labelled corpus.

The discipline here is the point of the module:

* messages from the same sender domain always land in the same split, so the model
  can't memorise a campaign and then be graded on it
* near-duplicate messages are collapsed before splitting
* the model is fit on train, the blend weight and thresholds are chosen on
  validation, and every number in the report comes from the untouched test split
* intervals come from resampling whole sender groups, not single messages
"""

import hashlib
import json
import os
import re
import time
from concurrent.futures import ProcessPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    log_loss,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)

from ..analysis.brands import FREEMAIL
from ..analysis.features import FEATURE_NAMES, FEATURES, extract
from ..analysis.hostutil import registered_domain
from ..analysis.message import parse
from ..analysis.model import Calibration, LinearModel
from ..analysis.pipeline import build_context, offline_services
from ..analysis.rules import RULES, combine, evaluate
from ..analysis.verdict import CRITICAL
from .corpus import Sample
from .metrics import (
    CostModel,
    best_thresholds,
    cluster_bootstrap,
    confusion,
    economics,
    rates,
    thin,
)

_SERVICES = None

LIMITATIONS = [
    "Rules were written by the same people who read these corpora, so rule recall on them is optimistic.",
    "The public ham is old mailing-list traffic and the phishing is mostly bank and webmail lures. "
    "The model can learn that difference (HTML, link count, formatting) instead of 'phishing'. Treat the model-only numbers with suspicion.",
    "Corpus prevalence is not your prevalence. Precision is recomputed at the assumed prevalence in the cost model.",
    "Historical mail has little sender-authentication data, and domain-age, threat-intel and sandbox signals can't be reproduced offline, so those are barely exercised here.",
]


def _row(raw: bytes):
    global _SERVICES
    if _SERVICES is None:
        _SERVICES = offline_services()
    try:
        msg = parse(raw)
        ctx = build_context(msg, _SERVICES, online=False)
        findings = evaluate(ctx)
        rules_p, _ = combine(findings)
        critical = [f.confidence for f in findings if f.confidence >= CRITICAL]
        values = extract(ctx)
        body = re.sub(r"\W+", " ", msg.visible_text.lower())[:2000]
        return {
            "x": [values[n] for n in FEATURE_NAMES],
            "rules": rules_p,
            "floor": max(critical) if critical else 0.0,
            "rule_ids": [f.rule_id for f in findings],
            # Free-mail domains hold thousands of unrelated senders, so group those by address.
            "group": (msg.sender.address if msg.sender.domain in FREEMAIL else registered_domain(msg.sender.domain)) or "unknown",
            "key": hashlib.sha1(f"{msg.subject}|{body}".encode()).hexdigest(),
        }
    except Exception:
        return None


def _compute_rows(samples: list[Sample], workers: int | None):
    raws = [s.raw for s in samples]
    if len(raws) < 200 or workers == 1:
        return [_row(r) for r in raws]
    with ProcessPoolExecutor(max_workers=workers or os.cpu_count()) as pool:
        return list(pool.map(_row, raws, chunksize=64))


def _bucket(group: str, seed: int) -> int:
    return int(hashlib.sha1(f"{seed}:{group}".encode()).hexdigest(), 16) % 100


def _blend(rules, model, floor, alpha):
    return np.maximum((1 - alpha) * rules + alpha * model, floor)


def evaluate_corpus(samples: list[Sample], cost: CostModel | None = None, seed: int = 7, workers: int | None = None,
                    corpus_meta: dict | None = None, log=print) -> tuple[dict, LinearModel]:
    cost = cost or CostModel()
    t0 = time.time()
    rows = _compute_rows(samples, workers)
    log(f"analysed {len(samples)} messages in {time.time() - t0:.0f}s")

    by_key: dict[str, set[int]] = {}
    for s, r in zip(samples, rows, strict=True):
        if r is not None:
            by_key.setdefault(r["key"], set()).add(s.label)
    conflicts = {k for k, labels in by_key.items() if len(labels) > 1}

    kept, emitted, dropped_dupes, dropped_conflict, failed = [], set(), 0, 0, 0
    for s, r in zip(samples, rows, strict=True):
        if r is None:
            failed += 1
        elif r["key"] in conflicts:
            dropped_conflict += 1  # the same text filed as both phishing and legitimate is label noise
        elif r["key"] in emitted:
            dropped_dupes += 1
        else:
            emitted.add(r["key"])
            kept.append((s, r))

    X = np.array([r["x"] for _, r in kept], dtype=float)
    y = np.array([s.label for s, _ in kept])
    rules = np.array([r["rules"] for _, r in kept])
    floor = np.array([r["floor"] for _, r in kept])
    groups = np.array([r["group"] for _, r in kept])
    sources = np.array([s.source for s, _ in kept])

    buckets = np.array([_bucket(g, seed) for g in groups])
    split = np.where(buckets < 60, "train", np.where(buckets < 80, "val", "test"))
    notes = []

    def enough(mask):
        return (y[mask] == 1).sum() >= 20 and (y[mask] == 0).sum() >= 20

    if not all(enough(split == name) for name in ("train", "val", "test")):
        # One huge sender group can starve a split. Fall back to message-level and say so.
        ids = np.array([int(hashlib.sha1(f"{seed}:{s.id}".encode()).hexdigest(), 16) % 100 for s, _ in kept])
        split = np.where(ids < 60, "train", np.where(ids < 80, "val", "test"))
        notes.append("Group-level split left a partition too small, so messages were split individually. Intervals are optimistic.")

    tr, va, te = (split == "train"), (split == "val"), (split == "test")
    mean = X[tr].mean(axis=0)
    scale = X[tr].std(axis=0)
    scale[scale < 1e-9] = 1.0
    Z = (X - mean) / scale

    best_c, best_ll, clf = 0.3, float("inf"), None
    for c in (0.03, 0.1, 0.3, 1.0, 3.0):
        trial = LogisticRegression(C=c, class_weight="balanced", max_iter=3000).fit(Z[tr], y[tr])
        ll = log_loss(y[va], trial.predict_proba(Z[va])[:, 1], labels=[0, 1])
        if ll < best_ll:
            best_c, best_ll, clf = c, ll, trial
    model_p = clf.predict_proba(Z)[:, 1]

    def tune(alpha):
        s = _blend(rules, model_p, floor, alpha)
        return best_thresholds(s[va & (y == 1)], s[va & (y == 0)], cost)

    best = None
    for alpha in (0.0, 0.25, 0.5, 0.75, 1.0):
        ts, tm = tune(alpha)
        s = _blend(rules, model_p, floor, alpha)
        c = economics(rates(s[va & (y == 1)], s[va & (y == 0)], ts, tm), cost)["per_1000"]["total_cost_minutes"]
        if best is None or c < best[0] - 1e-9:
            best = (c, alpha, ts, tm)
    _, alpha, t_susp, t_mal = best

    scores = _blend(rules, model_p, floor, alpha)
    ph, hm = scores[te & (y == 1)], scores[te & (y == 0)]
    flag = confusion(ph, hm, t_susp)
    block = confusion(ph, hm, t_mal)
    cis = cluster_bootstrap(scores[te], y[te], groups[te], t_susp)
    pi = cost.prevalence
    tpr, fpr_ = flag["recall"], flag["fpr"]
    precision_pi = pi * tpr / (pi * tpr + (1 - pi) * fpr_) if (pi * tpr + (1 - pi) * fpr_) else 0.0
    econ = economics(rates(ph, hm, t_susp, t_mal), cost)

    def variant(name, a, use_floor):
        s = _blend(rules, model_p, floor if use_floor else np.zeros_like(floor), a)
        ts, tm = best_thresholds(s[va & (y == 1)], s[va & (y == 0)], cost)
        p, h = s[te & (y == 1)], s[te & (y == 0)]
        c = confusion(p, h, ts)
        eco = economics(rates(p, h, ts, tm), cost)["per_1000"]
        return {
            "name": name,
            "auc": round(float(roc_auc_score(y[te], s[te])), 4),
            "precision": round(c["precision"], 4), "recall": round(c["recall"], 4), "fpr": round(c["fpr"], 4),
            "net_saved_per_1000": eco["net_minutes_saved"],
            "missed_per_1000": eco["missed_phish"],
            "thresholds": [ts, tm],
        }

    ablation = [variant("Rules only", 0.0, True), variant("Model only", 1.0, False), variant("Rules + model (shipped)", alpha, True)]

    per_rule = []
    ids_te = [r["rule_ids"] for (s, r), m in zip(kept, te, strict=True) if m]
    labels_te = y[te]
    for rule in RULES:
        hits = np.array([rule.id in ids for ids in ids_te])
        hp, hh = int((hits & (labels_te == 1)).sum()), int((hits & (labels_te == 0)).sum())
        per_rule.append({"rule_id": rule.id, "title": rule.title, "group": rule.group, "confidence": rule.confidence,
                         "phish_hits": hp, "ham_hits": hh,
                         "precision": round(hp / (hp + hh), 3) if hp + hh else None,
                         "coverage": round(hp / max(int((labels_te == 1).sum()), 1), 3)})
    per_rule.sort(key=lambda r: (r["phish_hits"] + r["ham_hits"]), reverse=True)

    per_source = []
    for src in sorted(set(sources[te])):
        m = te & (sources == src)
        per_source.append({"source": src, "n": int(m.sum()), "flagged": round(float((scores[m] >= t_susp).mean()), 4),
                           "blocked": round(float((scores[m] >= t_mal).mean()), 4)})

    fpr_c, tpr_c, _ = roc_curve(y[te], scores[te])
    prec_c, rec_c, _ = precision_recall_curve(y[te], scores[te])
    cost_curve = []
    for t in np.round(np.arange(0.05, 0.96, 0.025), 3):
        tm = max(t_mal, t + 0.05)
        e = economics(rates(ph, hm, float(t), float(tm)), cost)["per_1000"]
        cost_curve.append({"t": float(t), "cost": e["total_cost_minutes"], "net_saved": e["net_minutes_saved"], "missed": e["missed_phish"]})

    top = sorted(zip(FEATURE_NAMES, clf.coef_[0], strict=True), key=lambda kv: abs(kv[1]), reverse=True)[:12]
    model = LinearModel(
        version=datetime.now(UTC).strftime("%Y.%m.%d"),
        features=FEATURE_NAMES, mean=[float(v) for v in mean], scale=[float(v) for v in scale],
        coef=[float(v) for v in clf.coef_[0]], intercept=float(clf.intercept_[0]),
        calibration=Calibration(alpha=float(alpha), suspicious=float(t_susp), malicious=float(t_mal)),
        meta={"C": best_c, "n_train": int(tr.sum()), "corpus": (corpus_meta or {}).get("name", "unknown"),
              "kind": (corpus_meta or {}).get("kind", "unknown")},
    )

    def cap(arr, n=2500):
        arr = np.sort(arr)
        if len(arr) > n:
            arr = arr[np.linspace(0, len(arr) - 1, n).astype(int)]
        return [round(float(v), 3) for v in arr]

    def counts(mask):
        return {"phish": int((y[mask] == 1).sum()), "ham": int((y[mask] == 0).sum())}

    report = {
        "schema": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "corpus": {
            **(corpus_meta or {}),
            "messages_read": len(samples),
            "unparseable": failed,
            "duplicates_removed": dropped_dupes,
            "label_conflicts_removed": dropped_conflict,
            "splits": {"train": counts(tr), "val": counts(va), "test": counts(te)},
            "split_by": "sender domain" if not notes else "message",
            "seed": seed,
            "notes": notes,
        },
        "assumptions": cost.to_dict(),
        "operating_point": {"alpha": alpha, "suspicious": t_susp, "malicious": t_mal},
        "metrics": {
            "flag": {**{k: (round(v, 4) if isinstance(v, float) else v) for k, v in flag.items()},
                     "ci95": {k: [round(a, 4), round(b, 4)] for k, (a, b) in cis.items()}},
            "block": {k: (round(v, 4) if isinstance(v, float) else v) for k, v in block.items()},
            "auc_roc": round(float(roc_auc_score(y[te], scores[te])), 4),
            "auc_pr": round(float(average_precision_score(y[te], scores[te])), 4),
            "at_prevalence": {"prevalence": pi, "precision": round(precision_pi, 4), "recall": round(tpr, 4), "fpr": round(fpr_, 4)},
        },
        "economics": {**econ, "assumptions": cost.to_dict()},
        "ablation": ablation,
        "per_rule": per_rule,
        "per_source": per_source,
        "model": {"version": model.version, "C": best_c, "n_features": len(FEATURE_NAMES),
                  "top_features": [{"feature": n, "label": FEATURES[n], "coef": round(float(c), 3)} for n, c in top]},
        "curves": {
            "roc": thin([[round(float(a), 4), round(float(b), 4)] for a, b in zip(fpr_c, tpr_c, strict=True)]),
            "pr": thin([[round(float(a), 4), round(float(b), 4)] for a, b in zip(rec_c, prec_c, strict=True)]),
            "cost": cost_curve,
        },
        "scores": {"phish": cap(ph), "ham": cap(hm)},
        "limitations": LIMITATIONS,
    }
    return report, model


def write_report(report: dict, path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=1) + "\n")


def summarize(report: dict) -> str:
    m, f = report["metrics"], report["metrics"]["flag"]
    e = report["economics"]["per_1000"]
    ci = f["ci95"]
    lines = [
        f"corpus: {report['corpus'].get('name')} ({report['corpus'].get('kind')}), "
        f"test split {report['corpus']['splits']['test']}",
        f"operating point: alpha={report['operating_point']['alpha']}, suspicious>={report['operating_point']['suspicious']}, malicious>={report['operating_point']['malicious']}",
        f"flag precision {f['precision']:.3f} {tuple(ci['precision'])}  recall {f['recall']:.3f} {tuple(ci['recall'])}  FPR {f['fpr']:.3f} {tuple(ci['fpr'])}",
        f"AUC {m['auc_roc']:.3f}   PR-AUC {m['auc_pr']:.3f}   precision at {m['at_prevalence']['prevalence']:.0%} prevalence {m['at_prevalence']['precision']:.3f}",
        f"per 1,000 reports: {e['net_minutes_saved']:.0f} analyst-minutes saved net of mistakes ({e['minutes_saved']:.0f} gross), {e['missed_phish']:.1f} phish missed, {e['false_blocks']:.1f} false blocks",
    ]
    for a in report["ablation"]:
        lines.append(f"  {a['name']:<28} AUC {a['auc']:.3f}  recall {a['recall']:.3f}  FPR {a['fpr']:.3f}  net saved/1000 {a['net_saved_per_1000']:.0f}  missed/1000 {a['missed_per_1000']:.1f}")
    return "\n".join(lines)

