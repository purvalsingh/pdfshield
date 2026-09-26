import os
import random
import time

import pytest

from pdfshield.benchmark import (STATUS_ERROR, STATUS_OK, STATUS_TIMEOUT, collect, extract_all, run,
                                 wilson_interval)
from pdfshield.samples import build_benign, build_malicious


def test_wilson_interval_is_sane():
    lo, hi = wilson_interval(95, 100)
    assert lo < 0.95 < hi and 0.88 < lo and hi < 0.98
    assert wilson_interval(0, 10)[0] == 0.0          # never below zero
    assert wilson_interval(10, 10)[1] == pytest.approx(1.0)
    assert wilson_interval(0, 0) == (0.0, 0.0)


def test_collect_dedupes_sniffs_and_drops_conflicts(tmp_path):
    rng = random.Random(3)
    mal, ben = tmp_path / "mal", tmp_path / "ben"
    mal.mkdir(), ben.mkdir()
    sample = build_malicious(rng)
    (mal / "a3f9c1").write_bytes(sample)             # hash-style name, no extension
    (mal / "copy.pdf").write_bytes(sample)            # duplicate
    (mal / "notes.txt").write_text("not a pdf")       # ignored
    shared = build_benign(rng)
    (mal / "shared.pdf").write_bytes(shared)          # same file under both labels
    (ben / "shared.pdf").write_bytes(shared)
    (ben / "clean.pdf").write_bytes(build_benign(rng))

    items, stats = collect([mal], [ben])
    assert sorted(lab for *_, lab in items) == [0, 1]
    assert stats == {"duplicates": 2, "conflicting_labels": 1}


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_hanging_file_times_out_without_stalling_the_rest(tmp_path):
    # Reading a named pipe with no writer blocks forever: a genuine parser hang.
    hang = tmp_path / "hang.pdf"
    os.mkfifo(hang)
    good = tmp_path / "good.pdf"
    good.write_bytes(build_benign(random.Random(1)))
    missing = tmp_path / "missing.pdf"

    start = time.time()
    results = extract_all([hang, good, missing, good], workers=2, timeout=5, progress=False)
    assert time.time() - start < 60
    assert [r[0] for r in results] == [STATUS_TIMEOUT, STATUS_OK, STATUS_ERROR, STATUS_OK]


def test_benchmark_end_to_end(tmp_path):
    rng = random.Random(9)
    mal, ben = tmp_path / "mal", tmp_path / "ben"
    mal.mkdir(), ben.mkdir()
    for i in range(25):
        (mal / f"m{i}").write_bytes(build_malicious(rng))
        (ben / f"b{i}.pdf").write_bytes(build_benign(rng))

    report, rows = run([mal], [ben], "unit", workers=2, cache=tmp_path / "cache.json")
    shipped = report["as_shipped"]
    assert report["corpus"]["malicious"] == 25 and report["corpus"]["benign"] == 25
    assert shipped["recall"]["n"] == 25 and shipped["recall"]["value"] >= 0.9
    assert shipped["recall"]["ci95"][0] <= shipped["recall"]["value"] <= shipped["recall"]["ci95"][1]
    assert report["retrained"]["folds"] == 5
    assert (tmp_path / "cache.json").exists()
