"""A logistic regression small enough to read.

Weights live in a JSON file instead of a pickle: it can be reviewed in a diff, it
can't execute anything when loaded, and scoring needs no scikit-learn at runtime.
For a linear model the explanation is exact, not an approximation: each feature
adds coef * (standardised value) to the log-odds, so the contributions plus the
intercept sum to the score.
"""

import json
import math
from dataclasses import dataclass, field
from pathlib import Path

from .features import FEATURES


@dataclass
class Calibration:
    alpha: float = 0.5  # weight of the model when blending with the rules
    suspicious: float = 0.40
    malicious: float = 0.80

    def to_dict(self):
        return {"alpha": self.alpha, "suspicious": self.suspicious, "malicious": self.malicious}


@dataclass
class LinearModel:
    version: str
    features: list[str]
    mean: list[float]
    scale: list[float]
    coef: list[float]
    intercept: float
    calibration: Calibration = field(default_factory=Calibration)
    meta: dict = field(default_factory=dict)

    def _terms(self, values: dict[str, float]) -> list[float]:
        return [
            c * ((values.get(name, 0.0) - m) / s if s else 0.0)
            for name, c, m, s in zip(self.features, self.coef, self.mean, self.scale, strict=True)
        ]

    def predict(self, values: dict[str, float]) -> float:
        logit = self.intercept + sum(self._terms(values))
        return 1.0 / (1.0 + math.exp(-max(min(logit, 30.0), -30.0)))

    def explain(self, values: dict[str, float], top: int = 8) -> dict:
        terms = self._terms(values)
        ranked = sorted(zip(self.features, terms, strict=True), key=lambda kv: abs(kv[1]), reverse=True)
        contributions = [
            {
                "feature": name,
                "label": FEATURES.get(name, name),
                "value": round(values.get(name, 0.0), 3),
                "contribution": round(term, 4),
            }
            for name, term in ranked[:top]
            if abs(term) >= 0.01
        ]
        return {
            "score": round(self.predict(values), 4),
            "baseline": round(self.intercept, 4),
            "contributions": contributions,
            "version": self.version,
        }

    def save(self, path: Path) -> None:
        payload = {
            "version": self.version,
            "features": self.features,
            "mean": self.mean,
            "scale": self.scale,
            "coef": self.coef,
            "intercept": self.intercept,
            "calibration": self.calibration.to_dict(),
            "meta": self.meta,
        }
        Path(path).write_text(json.dumps(payload, indent=2) + "\n")

    @classmethod
    def load(cls, path: Path) -> "LinearModel | None":
        path = Path(path)
        if not path.exists():
            return None
        raw = json.loads(path.read_text())
        return cls(
            version=raw["version"],
            features=raw["features"],
            mean=raw["mean"],
            scale=raw["scale"],
            coef=raw["coef"],
            intercept=raw["intercept"],
            calibration=Calibration(**raw.get("calibration", {})),
            meta=raw.get("meta", {}),
        )
