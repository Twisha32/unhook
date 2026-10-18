from dataclasses import dataclass

from .model import Calibration
from .rules import Finding

# A single finding at or above this confidence (known-bad hash, disguised executable,
# auto-run macro) shouldn't be watered down by a model that hasn't seen the evidence.
CRITICAL = 0.85


@dataclass
class Verdict:
    label: str
    score: float
    rules_score: float
    model_score: float | None
    floor: float | None
    thresholds: dict

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "score": round(self.score, 4),
            "rules_score": round(self.rules_score, 4),
            "model_score": None if self.model_score is None else round(self.model_score, 4),
            "floor": self.floor,
            "thresholds": self.thresholds,
        }


def decide(rules_score: float, model_score: float | None, findings: list[Finding], cal: Calibration) -> Verdict:
    if model_score is None:
        blended = rules_score
    else:
        blended = (1 - cal.alpha) * rules_score + cal.alpha * model_score
    critical = [f.confidence for f in findings if f.confidence >= CRITICAL]
    floor = max(critical) if critical else None
    score = max(blended, floor) if floor else blended
    if score >= cal.malicious:
        label = "malicious"
    elif score >= cal.suspicious:
        label = "suspicious"
    else:
        label = "likely_safe"
    return Verdict(label, score, rules_score, model_score, floor,
                   {"suspicious": cal.suspicious, "malicious": cal.malicious})
