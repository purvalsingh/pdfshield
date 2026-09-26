"""Generate the synthetic corpus, train the classifier and write an evaluation report."""

from __future__ import annotations

import csv
import json
import random
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import cross_val_score, train_test_split

from .features import FEATURE_NAMES, extract_features
from .model import DEFAULT_MODEL_PATH
from .samples import build_benign, build_malicious


def generate_dataset(out_dir: Path, n_benign: int, n_malicious: int, seed: int) -> Path:
    """Write sample PDFs to ``out_dir`` and a features.csv describing them."""
    rng = random.Random(seed)
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for label, count, builder in (("benign", n_benign, build_benign), ("malicious", n_malicious, build_malicious)):
        (out_dir / label).mkdir(exist_ok=True)
        for i in range(count):
            path = out_dir / label / f"{label}_{i:04d}.pdf"
            path.write_bytes(builder(rng))
            feats = extract_features(path)
            rows.append({"file": str(path.relative_to(out_dir)), **{n: getattr(feats, n) for n in FEATURE_NAMES},
                         "label": int(label == "malicious")})
    csv_path = out_dir / "features.csv"
    with csv_path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["file", *FEATURE_NAMES, "label"])
        writer.writeheader()
        writer.writerows(rows)
    return csv_path


def load_csv(csv_path: Path) -> tuple[np.ndarray, np.ndarray]:
    with csv_path.open() as fh:
        rows = list(csv.DictReader(fh))
    X = np.array([[float(r[n]) for n in FEATURE_NAMES] for r in rows])
    y = np.array([int(r["label"]) for r in rows])
    return X, y


def train(csv_path: Path, model_path: Path = DEFAULT_MODEL_PATH, seed: int = 42) -> dict:
    X, y = load_csv(csv_path)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, stratify=y, random_state=seed)

    model = RandomForestClassifier(n_estimators=200, max_depth=8, class_weight="balanced", random_state=seed)
    cv = cross_val_score(model, X_train, y_train, cv=5, scoring="f1")
    model.fit(X_train, y_train)
    pred = model.predict(X_test)

    report = {
        "samples": {"total": int(len(y)), "benign": int((y == 0).sum()), "malicious": int((y == 1).sum())},
        "cross_val_f1": {"mean": round(float(cv.mean()), 4), "std": round(float(cv.std()), 4)},
        "test": classification_report(y_test, pred, target_names=["benign", "malicious"], output_dict=True),
        "confusion_matrix": {"labels": ["benign", "malicious"], "matrix": confusion_matrix(y_test, pred).tolist()},
        "feature_importance": dict(sorted(
            ((n, round(float(v), 4)) for n, v in zip(FEATURE_NAMES, model.feature_importances_)),
            key=lambda kv: kv[1], reverse=True,
        )),
    }

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "feature_names": FEATURE_NAMES}, model_path, compress=3)
    model_path.with_name("report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def run(data_dir: Path, n_benign: int, n_malicious: int, seed: int, model_path: Path = DEFAULT_MODEL_PATH) -> dict:
    csv_path = generate_dataset(data_dir, n_benign, n_malicious, seed)
    return train(csv_path, model_path, seed)
