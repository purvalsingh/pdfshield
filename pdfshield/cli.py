"""Command-line interface: `pdfshield scan`, `pdfshield features`, `pdfshield train`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .features import FEATURE_NAMES, extract_features
from .model import DEFAULT_MODEL_PATH, Verdict, scan

_COLORS = {"CLEAN": "32", "SUSPICIOUS": "33", "MALICIOUS": "31"}
_ICONS = {"CLEAN": "✔", "SUSPICIOUS": "!", "MALICIOUS": "✖"}


def _paint(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def _collect(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            files.extend(sorted(p.rglob("*.pdf")))
        elif p.exists():
            files.append(p)
        else:
            print(f"pdfshield: no such file: {p}", file=sys.stderr)
    return files


def _print_verdict(v: Verdict, color: bool) -> None:
    code = _COLORS[v.label]
    bar_len = round(v.score * 20)
    bar = _paint("█" * bar_len, code, color) + "░" * (20 - bar_len)
    print(f"{_paint(_ICONS[v.label] + ' ' + v.label, code + ';1', color)}  {v.path}")
    print(f"  risk  {bar} {v.score:.0%}")
    for reason in v.reasons:
        print(f"  • {reason}")
    print()


def cmd_scan(args: argparse.Namespace) -> int:
    files = _collect(args.paths)
    if not files:
        return 2
    verdicts = [scan(f, args.model) for f in files]
    if args.json:
        print(json.dumps([v.to_dict() for v in verdicts], indent=2))
    else:
        color = sys.stdout.isatty() and not args.no_color
        for v in verdicts:
            _print_verdict(v, color)
        if len(verdicts) > 1:
            flagged = sum(v.label != "CLEAN" for v in verdicts)
            print(f"Scanned {len(verdicts)} files: {flagged} flagged, {len(verdicts) - flagged} clean.")
    # Non-zero exit when anything is flagged so the CLI can gate CI pipelines.
    return 1 if any(v.label != "CLEAN" for v in verdicts) else 0


def cmd_features(args: argparse.Namespace) -> int:
    files = _collect(args.paths)
    rows = [{"file": str(f), **extract_features(f).to_dict()} for f in files]
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for row in rows:
            print(row["file"])
            for name in FEATURE_NAMES:
                print(f"  {name:<22} {row[name]}")
            if row["parse_error"]:
                print("  (malformed file: raw byte-scan fallback used)")
            print()
    return 0 if files else 2


def cmd_train(args: argparse.Namespace) -> int:
    from .train import run  # heavier imports only when training

    print(f"Generating {args.benign} benign + {args.malicious} malicious samples in {args.data} ...")
    report = run(Path(args.data), args.benign, args.malicious, args.seed, Path(args.model))
    test = report["test"]
    print(f"Cross-validated F1: {report['cross_val_f1']['mean']:.3f} ± {report['cross_val_f1']['std']:.3f}")
    print(f"Test accuracy:      {test['accuracy']:.3f}")
    print("Top features:")
    for name, value in list(report["feature_importance"].items())[:5]:
        print(f"  {name:<22} {value:.3f}")
    print(f"Model saved to {args.model}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pdfshield",
        description="Detect malicious PDFs from their structure with a trained ML model. Never opens or renders the file.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="scan PDF files or folders and print a verdict")
    p.add_argument("paths", nargs="+", help="PDF files or directories (searched recursively)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    p.add_argument("--model", default=str(DEFAULT_MODEL_PATH), help="path to a trained model")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("features", help="show the raw structural features of PDF files")
    p.add_argument("paths", nargs="+")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_features)

    p = sub.add_parser("train", help="regenerate the dataset and retrain the model")
    p.add_argument("--data", default="data", help="where to write generated samples (default: ./data)")
    p.add_argument("--benign", type=int, default=600)
    p.add_argument("--malicious", type=int, default=600)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--model", default=str(DEFAULT_MODEL_PATH))
    p.set_defaults(func=cmd_train)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
