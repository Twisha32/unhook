from dataclasses import asdict, dataclass

import numpy as np


@dataclass
class CostModel:
    """Everything the 'analyst minutes' figures depend on, in one place so it can be argued with.

    Defaults are placeholders for a small organisation, not measurements. Change them
    to match yours; the report records whatever was used.
    """

    manual_minutes: float = 8.0  # someone reads every report and decides, no tooling
    triaged_review_minutes: float = 3.0  # analyst checks a suspicious case that arrives with evidence attached
    malicious_review_minutes: float = 1.0  # analyst glances at a case that was already blocked
    miss_minutes: float = 240.0  # cost of a phish auto-closed as safe: roughly half a day of incident response
    block_error_minutes: float = 15.0  # cleanup after wrongly blocking something legitimate
    prevalence: float = 0.25  # share of staff reports that really are phishing

    def to_dict(self):
        return asdict(self)


def rates(phish: np.ndarray, ham: np.ndarray, t_susp: float, t_mal: float) -> dict:
    def split(scores):
        n = max(len(scores), 1)
        mal = float((scores >= t_mal).sum()) / n
        sus = float(((scores >= t_susp) & (scores < t_mal)).sum()) / n
        return mal, sus, 1.0 - mal - sus

    p_m, p_s, p_l = split(phish)
    h_m, h_s, h_l = split(ham)
    return {"p_m": p_m, "p_s": p_s, "p_l": p_l, "h_m": h_m, "h_s": h_s, "h_l": h_l}


def economics(r: dict, cm: CostModel) -> dict:
    pi = cm.prevalence
    review = 1000 * (pi * (r["p_m"] * cm.malicious_review_minutes + r["p_s"] * cm.triaged_review_minutes)
                     + (1 - pi) * (r["h_m"] * cm.malicious_review_minutes + r["h_s"] * cm.triaged_review_minutes))
    misses = 1000 * pi * r["p_l"]
    false_blocks = 1000 * (1 - pi) * r["h_m"]
    total = review + misses * cm.miss_minutes + false_blocks * cm.block_error_minutes
    baseline = 1000 * cm.manual_minutes
    return {
        "per_1000": {
            "baseline_minutes": round(baseline, 1),
            "triage_minutes": round(review, 1),
            "minutes_saved": round(baseline - review, 1),  # review time only, before paying for mistakes
            "net_minutes_saved": round(baseline - total, 1),  # after misses and wrong blocks
            "missed_phish": round(misses, 2),
            "false_blocks": round(false_blocks, 2),
            "total_cost_minutes": round(total, 1),
        }
    }


def best_thresholds(phish: np.ndarray, ham: np.ndarray, cm: CostModel) -> tuple[float, float]:
    """Grid search for the two cut-offs that minimise expected cost on validation data."""
    grid = np.round(np.arange(0.05, 0.96, 0.01), 2)
    best, best_cost = (0.40, 0.80), float("inf")
    for ts in grid:
        for tm in grid:
            if tm < ts + 0.05:
                continue
            cost = economics(rates(phish, ham, ts, tm), cm)["per_1000"]["total_cost_minutes"]
            if cost < best_cost:
                best, best_cost = (float(ts), float(tm)), cost
    return best


def confusion(phish: np.ndarray, ham: np.ndarray, threshold: float) -> dict:
    tp = int((phish >= threshold).sum())
    fn = len(phish) - tp
    fp = int((ham >= threshold).sum())
    tn = len(ham) - fp
    return _derive(tp, fp, fn, tn)


def _derive(tp, fp, fn, tn) -> dict:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall, "fpr": fpr, "f1": f1}


def cluster_bootstrap(scores: np.ndarray, labels: np.ndarray, groups: np.ndarray, threshold: float,
                      n: int = 500, seed: int = 11) -> dict:
    """95% intervals that resample whole sender groups, since messages from one sender aren't independent."""
    rng = np.random.default_rng(seed)
    uniq = np.unique(groups)
    index = {g: np.flatnonzero(groups == g) for g in uniq}
    out = {"precision": [], "recall": [], "fpr": []}
    for _ in range(n):
        picks = rng.choice(uniq, size=len(uniq), replace=True)
        idx = np.concatenate([index[g] for g in picks])
        s, y = scores[idx], labels[idx]
        c = confusion(s[y == 1], s[y == 0], threshold)
        for k in out:
            out[k].append(c[k])
    return {k: [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))] for k, v in out.items()}


def thin(points: list, limit: int = 80) -> list:
    if len(points) <= limit:
        return points
    step = (len(points) - 1) / (limit - 1)
    return [points[round(i * step)] for i in range(limit)]
