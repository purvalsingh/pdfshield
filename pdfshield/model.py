"""Loading the trained model and turning a prediction into a readable verdict."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import joblib

from .features import FEATURE_DESCRIPTIONS, FEATURE_NAMES, PDFFeatures, extract_features

DEFAULT_MODEL_PATH = Path(__file__).parent / "model" / "pdfshield.joblib"

# Risk thresholds on the model's malicious-class probability.
SUSPICIOUS_AT = 0.5
MALICIOUS_AT = 0.8

# Features that are worth surfacing as a reason when present. Size, page and
# object counts are context, not indicators, so they are never listed.
_INDICATORS = [
    "open_action", "additional_actions", "javascript_count", "launch_action",
    "embedded_file_count", "xfa", "acroform", "uri_count", "encrypted",
]
_HIGH_RISK = {"open_action", "additional_actions", "javascript_count", "launch_action", "xfa"}


@dataclass
class Verdict:
    path: str
    score: float
    label: str
    features: PDFFeatures
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "file": self.path,
            "verdict": self.label,
            "risk_score": round(self.score, 4),
            "reasons": self.reasons,
            "features": self.features.to_dict(),
        }


@lru_cache(maxsize=4)
def load_model(path: str | os.PathLike = DEFAULT_MODEL_PATH):
    bundle = joblib.load(path)
    if bundle["feature_names"] != FEATURE_NAMES:
        raise RuntimeError("Model was trained on a different feature set; retrain it with `pdfshield train`.")
    return bundle["model"]


def label_for(score: float) -> str:
    if score >= MALICIOUS_AT:
        return "MALICIOUS"
    if score >= SUSPICIOUS_AT:
        return "SUSPICIOUS"
    return "CLEAN"


def explain(feats: PDFFeatures) -> list[str]:
    """Human-readable reasons, high-risk indicators first."""
    reasons = []
    for name in sorted(_INDICATORS, key=lambda n: n not in _HIGH_RISK):
        value = getattr(feats, name)
        if not value:
            continue
        text = FEATURE_DESCRIPTIONS[name]
        if name.endswith("_count") and value > 1:
            text += f" x{value}"
        reasons.append(text)
    if feats.parse_error:
        reasons.append("File is malformed; features came from a raw byte scan")
    return reasons


def scan(path: str | os.PathLike, model_path: str | os.PathLike = DEFAULT_MODEL_PATH) -> Verdict:
    feats = extract_features(path)
    model = load_model(str(model_path))
    score = float(model.predict_proba([feats.to_vector()])[0][1])
    return Verdict(path=os.fspath(path), score=score, label=label_for(score),
                   features=feats, reasons=explain(feats))
