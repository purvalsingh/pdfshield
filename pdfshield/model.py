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
    if feats.js_calls:
        reasons.insert(0, "JavaScript uses " + ", ".join(feats.js_calls))
    if feats.js_encoded_ratio >= 0.2:
        reasons.insert(0, f"JavaScript is {feats.js_encoded_ratio:.0%} escape-encoded (obfuscation)")
    if feats.js_max_string_len >= 1000 and feats.js_entropy >= 4.5:
        reasons.append(f"JavaScript hides a {feats.js_max_string_len:,}-character dense string")
    if feats.js_length and not (feats.js_suspicious_calls or feats.js_encoded_ratio >= 0.2):
        reasons.append("JavaScript looks like ordinary form/viewer code (no exploit or obfuscation markers)")
    if feats.password_protected:
        reasons.append("Password-protected: contents cannot be inspected without the password")
    elif feats.parse_error:
        reasons.append("File is malformed; features came from a raw byte scan")
    return reasons


def uninspectable_autorun(feats: PDFFeatures) -> bool:
    """Code runs automatically, but we cannot read it.

    Password-protected files hide their scripts, and damaged or re-encrypted
    files can leave only ciphertext behind. The model has nothing to judge the
    script by, so policy decides: flag it for review rather than guess clean.
    """
    auto = feats.open_action or feats.additional_actions
    has_code = feats.javascript_count or feats.launch_action
    unreadable = feats.password_protected or (feats.javascript_count and (feats.js_length == 0 or feats.js_entropy >= 7.0))
    return bool(auto and has_code and unreadable)


def score_features(feats: PDFFeatures, model) -> tuple[float, bool]:
    """Model probability, raised to the review threshold by policy when
    auto-run code cannot be inspected. Returns (score, policy_applied)."""
    score = float(model.predict_proba([feats.to_vector()])[0][1])
    if uninspectable_autorun(feats) and score < SUSPICIOUS_AT:
        return SUSPICIOUS_AT, True
    return score, False


def scan(path: str | os.PathLike, model_path: str | os.PathLike = DEFAULT_MODEL_PATH) -> Verdict:
    feats = extract_features(path)
    model = load_model(str(model_path))
    score, policy = score_features(feats, model)
    reasons = explain(feats)
    if policy:
        reasons.insert(0, "Runs code automatically that cannot be inspected (policy: flag for review)")
    return Verdict(path=os.fspath(path), score=score, label=label_for(score), features=feats, reasons=reasons)
