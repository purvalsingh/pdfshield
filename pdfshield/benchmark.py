"""Benchmark PDFShield on a labelled corpus of real PDFs, including real malware.

    pdfshield benchmark --malicious /data/malicious --benign /data/benign

Built for collections such as CIC-Evasive-PDFMal2022 or Contagio. Samples are
only *parsed*, never rendered or executed. Run it inside the locked-down
container (scripts/benchmark.sh) anyway: malicious PDFs are designed to attack
parsers.

What makes the numbers defensible:

* **Deduplication by SHA-256.** Malware collections are full of copies, and a
  duplicate in both folders would count twice.
* **Per-file timeout and crash isolation.** Every file is parsed in a worker
  process. A file that hangs or crashes the parser is recorded, never silently
  dropped, and counts as flagged (a scanner would quarantine it).
* **Confidence intervals.** Recall and false-positive rate come with 95%
  Wilson intervals, so small corpora can't overclaim.
* **Two separate questions:**
  1. *As shipped* - the bundled model, trained only on synthetic data, scored
     on real files it has never seen. This is the honest "does it work" number.
  2. *Retrained* - the same model architecture trained on the real corpus,
     scored with stratified 5-fold cross-validation (train and test never
     share a file). This says how good the features are with real data.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import multiprocessing as mp
import os
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from .features import FEATURE_NAMES, PDFFeatures, extract_features
from .model import DEFAULT_MODEL_PATH, MALICIOUS_AT, SUSPICIOUS_AT, load_model, score_features

STATUS_OK, STATUS_TIMEOUT, STATUS_ERROR = "ok", "timeout", "error"


# --- statistics -----------------------------------------------------------------

def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion (well-behaved near 0 and 1)."""
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def _rate(successes: int, n: int) -> dict:
    lo, hi = wilson_interval(successes, n)
    return {"value": round(successes / n, 4) if n else None, "ci95": [round(lo, 4), round(hi, 4)],
            "count": successes, "n": n}


# --- corpus loading ---------------------------------------------------------------

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def is_pdf(path: Path) -> bool:
    """By extension or by the %PDF header (malware sets often use bare hashes
    as file names). Readers accept the header anywhere in the first 1 KB."""
    if path.suffix.lower() == ".pdf":
        return True
    try:
        with path.open("rb") as fh:
            return b"%PDF" in fh.read(1024)
    except OSError:
        return False


def collect(malicious_dirs: list[Path], benign_dirs: list[Path]) -> tuple[list, dict]:
    """Return [(path, sha256, label)] with duplicates removed, plus stats.

    A file that appears under both labels has no trustworthy label and is
    dropped.
    """
    first: dict[str, tuple[Path, int]] = {}
    labels: dict[str, set[int]] = {}
    files = 0
    for label, dirs in ((1, malicious_dirs), (0, benign_dirs)):
        for d in dirs:
            for path in sorted(Path(d).rglob("*")):
                if not path.is_file() or not is_pdf(path):
                    continue
                files += 1
                digest = _sha256(path)
                first.setdefault(digest, (path, label))
                labels.setdefault(digest, set()).add(label)
    conflicts = {h for h, labs in labels.items() if len(labs) > 1}
    items = [(path, h, label) for h, (path, label) in first.items() if h not in conflicts]
    return items, {"duplicates": files - len(first), "conflicting_labels": len(conflicts)}


# --- isolated extraction --------------------------------------------------------------

def _extract_worker(path: str) -> tuple[str, dict | None, str]:
    try:
        return STATUS_OK, extract_features(path).to_dict(), ""
    except Exception as exc:  # noqa: BLE001 - any crash is a result, not a harness failure
        return STATUS_ERROR, None, f"{type(exc).__name__}: {str(exc)[:200]}"


def extract_all(paths: list[Path], workers: int, timeout: float, progress: bool = True) -> list[tuple]:
    """Extract features for every file in isolated worker processes.

    Files are processed in rounds of ``workers``. If any file in a round
    exceeds ``timeout`` seconds, the pool is killed and rebuilt, so one
    hostile file cannot stall or poison the rest of the run.
    """
    ctx = mp.get_context("spawn")
    results: list[tuple] = [None] * len(paths)
    pool = ctx.Pool(workers, maxtasksperchild=50)
    start = time.time()
    try:
        for base in range(0, len(paths), workers):
            batch = list(range(base, min(base + workers, len(paths))))
            handles = {i: pool.apply_async(_extract_worker, (str(paths[i]),)) for i in batch}
            deadline = time.time() + timeout
            timed_out = False
            for i, handle in handles.items():
                try:
                    results[i] = handle.get(timeout=max(0.0, deadline - time.time()))
                except mp.TimeoutError:
                    results[i] = (STATUS_TIMEOUT, None, f"exceeded {timeout:.0f}s")
                    timed_out = True
            if timed_out:
                pool.terminate()
                pool = ctx.Pool(workers, maxtasksperchild=50)
            if progress and (base // workers) % 50 == 0:
                done = base + len(batch)
                print(f"  extracted {done}/{len(paths)}  ({time.time() - start:.0f}s)", flush=True)
    finally:
        pool.terminate()
    return results


# --- scoring ------------------------------------------------------------------------

@dataclass
class Row:
    path: str
    sha256: str
    label: int
    status: str
    detail: str
    features: dict | None
    score: float | None = None

    @property
    def flagged(self) -> bool:
        # A file that hangs or crashes the parser is quarantined by any sane
        # deployment, so it counts as flagged; it is also reported separately.
        return self.status != STATUS_OK or (self.score is not None and self.score >= SUSPICIOUS_AT)


def _to_features(d: dict) -> PDFFeatures:
    return PDFFeatures(**d)


def _confusion(labels: np.ndarray, flagged: np.ndarray) -> dict:
    mal, ben = labels == 1, labels == 0
    return {
        "recall": _rate(int((flagged & mal).sum()), int(mal.sum())),
        "false_positive_rate": _rate(int((flagged & ben).sum()), int(ben.sum())),
        "precision": round(float((flagged & mal).sum() / max(flagged.sum(), 1)), 4),
        "accuracy": round(float((flagged == mal).mean()), 4) if len(labels) else None,
        "tp": int((flagged & mal).sum()), "fn": int((~flagged & mal).sum()),
        "fp": int((flagged & ben).sum()), "tn": int((~flagged & ben).sum()),
    }


def score_as_shipped(rows: list[Row], model_path: Path) -> dict:
    model = load_model(str(model_path))
    for r in rows:
        if r.status == STATUS_OK:
            r.score = score_features(_to_features(r.features), model)[0]
    labels = np.array([r.label for r in rows])
    flagged = np.array([r.flagged for r in rows])
    report = _confusion(labels, flagged)

    ok = [r for r in rows if r.status == STATUS_OK]
    if len({r.label for r in ok}) == 2:
        from sklearn.metrics import roc_auc_score
        report["roc_auc"] = round(float(roc_auc_score([r.label for r in ok], [r.score for r in ok])), 4)
    report["thresholds"] = []
    for t in (0.3, 0.4, SUSPICIOUS_AT, 0.6, 0.7, MALICIOUS_AT, 0.9):
        f = np.array([r.status != STATUS_OK or r.score >= t for r in rows])
        c = _confusion(labels, f)
        report["thresholds"].append({"threshold": t, "recall": c["recall"]["value"],
                                     "false_positive_rate": c["false_positive_rate"]["value"]})
    mal = [r for r in rows if r.label == 1 and r.status == STATUS_OK]
    report["malicious_verdicts"] = {
        "MALICIOUS": sum(r.score >= MALICIOUS_AT for r in mal),
        "SUSPICIOUS": sum(SUSPICIOUS_AT <= r.score < MALICIOUS_AT for r in mal),
        "CLEAN": sum(r.score < SUSPICIOUS_AT for r in mal),
    }
    return report


def cross_validate_retrained(rows: list[Row], folds: int = 5, seed: int = 42) -> dict | None:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import StratifiedKFold

    ok = [r for r in rows if r.status == STATUS_OK]
    y = np.array([r.label for r in ok])
    if len(ok) < folds * 2 or min((y == 0).sum(), (y == 1).sum()) < folds:
        return None
    X = np.array([_to_features(r.features).to_vector() for r in ok])
    per_fold = []
    importances = np.zeros(len(FEATURE_NAMES))
    for train_idx, test_idx in StratifiedKFold(folds, shuffle=True, random_state=seed).split(X, y):
        model = RandomForestClassifier(n_estimators=200, max_depth=8, class_weight="balanced", random_state=seed)
        model.fit(X[train_idx], y[train_idx])
        pred = model.predict_proba(X[test_idx])[:, 1] >= SUSPICIOUS_AT
        c = _confusion(y[test_idx], pred)
        per_fold.append((c["recall"]["value"], c["false_positive_rate"]["value"], c["precision"]))
        importances += model.feature_importances_
    arr = np.array(per_fold, dtype=float)
    return {
        "folds": folds, "n": len(ok),
        "recall": {"mean": round(arr[:, 0].mean(), 4), "std": round(arr[:, 0].std(), 4)},
        "false_positive_rate": {"mean": round(arr[:, 1].mean(), 4), "std": round(arr[:, 1].std(), 4)},
        "precision": {"mean": round(arr[:, 2].mean(), 4), "std": round(arr[:, 2].std(), 4)},
        "feature_importance": dict(sorted(((n, round(float(v / folds), 4)) for n, v in zip(FEATURE_NAMES, importances)),
                                          key=lambda kv: kv[1], reverse=True)),
    }


# --- reporting ---------------------------------------------------------------------

def _pct(rate: dict) -> str:
    if rate["value"] is None:
        return "n/a"
    lo, hi = rate["ci95"]
    return f"{rate['value']:.1%} ({rate['count']}/{rate['n']}, 95% CI {lo:.1%}–{hi:.1%})"


def to_markdown(report: dict) -> str:
    c, s = report["corpus"], report["as_shipped"]
    lines = [
        f"### Benchmark: {report['name']}",
        "",
        f"- **Corpus:** {c['malicious']} malicious + {c['benign']} benign unique files "
        f"({c['duplicates']} duplicates removed, {c['conflicting_labels']} label conflicts dropped)",
        f"- **Parser outcomes:** {c['timeouts']} timeouts, {c['errors']} crashes (counted as flagged)",
        "",
        "**As shipped** (bundled model, trained only on synthetic data, never saw these files):",
        "",
        "| Metric | Result |",
        "|---|---|",
        f"| Detection rate (recall) | {_pct(s['recall'])} |",
        f"| False-positive rate | {_pct(s['false_positive_rate'])} |",
        f"| Precision | {s['precision']:.1%} |",
    ]
    if "roc_auc" in s:
        lines.append(f"| ROC-AUC | {s['roc_auc']:.3f} |")
    v = s["malicious_verdicts"]
    lines += ["", f"Malicious files by verdict: {v['MALICIOUS']} MALICIOUS · {v['SUSPICIOUS']} SUSPICIOUS · "
                  f"{v['CLEAN']} missed", ""]
    rt = report.get("retrained")
    if rt:
        lines += [
            f"**Retrained on this corpus** ({rt['folds']}-fold stratified cross-validation, n={rt['n']}):",
            "",
            "| Metric | Mean ± std |",
            "|---|---|",
            f"| Recall | {rt['recall']['mean']:.1%} ± {rt['recall']['std']:.1%} |",
            f"| False-positive rate | {rt['false_positive_rate']['mean']:.1%} ± {rt['false_positive_rate']['std']:.1%} |",
            f"| Precision | {rt['precision']['mean']:.1%} ± {rt['precision']['std']:.1%} |",
            "",
            "Top features: " + ", ".join(f"`{k}` ({v:.2f})" for k, v in list(rt["feature_importance"].items())[:5]),
        ]
    return "\n".join(lines) + "\n"


def run(malicious: list[Path], benign: list[Path], name: str, model_path: Path = DEFAULT_MODEL_PATH,
        workers: int | None = None, timeout: float = 30.0,
        cache: Path | None = None) -> tuple[dict, list[Row]]:
    items, stats = collect(malicious, benign)
    print(f"Corpus: {sum(l for *_, l in items)} malicious + {sum(1 - l for *_, l in items)} benign "
          f"unique files ({stats['duplicates']} duplicates removed)")

    cached: dict[str, tuple] = {}
    if cache and cache.exists():
        for rec in json.loads(cache.read_text()):
            cached[rec["sha256"]] = (rec["status"], rec["features"], rec["detail"])
    todo = [i for i, (_, h, _) in enumerate(items) if h not in cached]
    extracted = extract_all([items[i][0] for i in todo], workers or max(1, (os.cpu_count() or 2) - 1), timeout)
    for i, res in zip(todo, extracted):
        cached[items[i][1]] = res

    rows = []
    for p, h, lab in items:
        status, features, detail = cached[h]
        rows.append(Row(path=str(p), sha256=h, label=lab, status=status, detail=detail, features=features))
    if cache:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps([{"sha256": r.sha256, "status": r.status, "features": r.features,
                                      "detail": r.detail} for r in rows]))

    report = {
        "name": name,
        "corpus": {"malicious": sum(r.label for r in rows), "benign": sum(1 - r.label for r in rows),
                   **stats, "timeouts": sum(r.status == STATUS_TIMEOUT for r in rows),
                   "errors": sum(r.status == STATUS_ERROR for r in rows)},
        "as_shipped": score_as_shipped(rows, model_path),
        "retrained": cross_validate_retrained(rows),
    }
    return report, rows


def main(args) -> int:
    report, rows = run([Path(p) for p in args.malicious], [Path(p) for p in args.benign], args.name,
                       Path(args.model), args.workers, args.timeout,
                       Path(args.cache) if args.cache else None)
    markdown = to_markdown(report)
    print()
    print(markdown)
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "benchmark.json").write_text(json.dumps(report, indent=2) + "\n")
    (out / "benchmark.md").write_text(markdown)
    with (out / "per_file.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["sha256", "label", "status", "score", "flagged", "detail", "path"])
        for r in rows:
            w.writerow([r.sha256, r.label, r.status, "" if r.score is None else round(r.score, 4),
                        int(r.flagged), r.detail, r.path])
    print(f"Wrote {out}/benchmark.md, benchmark.json and per_file.csv")
    return 0
