import io
import json
import random

import pikepdf
import pytest

from pdfshield import FEATURE_NAMES, extract_features, scan
from pdfshield.cli import main
from pdfshield.samples import (add_navigation_open_action, build_calculating_form, build_document,
                               build_malicious)


@pytest.fixture
def rng():
    # Different seed from training (42) so tests use unseen samples.
    return random.Random(1234)


def write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_plain_document_has_no_risk_markers(tmp_path, rng):
    f = extract_features(write(tmp_path, "plain.pdf", build_document(rng, pages=3, links=2, form=False, encrypt=False)))
    assert f.page_count == 3
    assert f.uri_count == 2
    assert f.javascript_count == f.open_action == f.additional_actions == f.launch_action == 0
    assert not f.parse_error
    assert len(f.to_vector()) == len(FEATURE_NAMES)


def test_encrypted_document_is_detected(tmp_path, rng):
    f = extract_features(write(tmp_path, "enc.pdf", build_document(rng, encrypt=True)))
    assert f.encrypted == 1


def test_navigation_open_action_is_not_auto_run(tmp_path, rng):
    # Word/LibreOffice write /OpenAction [page /XYZ ...] = "open at page 1".
    # Found as a false positive on a real LibreOffice-generated PDF.
    for _ in range(4):
        data = add_navigation_open_action(build_document(rng), rng)
        v = scan(write(tmp_path, "nav.pdf", data))
        assert v.features.open_action == 0
        assert v.label == "CLEAN"


def test_injected_markers_are_extracted(tmp_path, rng):
    f = extract_features(write(tmp_path, "bad.pdf", build_malicious(rng)))
    assert f.open_action or f.additional_actions


def test_obfuscated_names_are_normalised(tmp_path, rng):
    # /J#61vaScript is a classic trick to dodge naive keyword scanners.
    with pikepdf.open(io.BytesIO(build_document(rng, encrypt=False))) as pdf:
        pdf.Root.OpenAction = pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS=pikepdf.String("var a = 1;"))
        buf = io.BytesIO()
        pdf.save(buf)
    data = buf.getvalue()
    assert b"/JavaScript" in data
    data = data.replace(b"/JavaScript", b"/J#61vaScript")
    f = extract_features(write(tmp_path, "obf.pdf", data))
    assert f.javascript_count >= 1


def test_malformed_file_falls_back_to_byte_scan(tmp_path):
    f = extract_features(write(tmp_path, "junk.pdf", b"garbage /OpenAction /J#53 << /S /Launch >>"))
    assert f.parse_error
    assert f.open_action == 1 and f.launch_action == 1 and f.javascript_count == 1

    f = extract_features(write(tmp_path, "junk2.pdf", b"garbage /OpenAction [3 0 R /Fit]"))
    assert f.parse_error and f.open_action == 0


def test_benign_documents_are_clean(tmp_path, rng):
    for i in range(20):
        v = scan(write(tmp_path, f"b{i}.pdf", build_document(rng)))
        assert v.label == "CLEAN", v.to_dict()


def test_malicious_documents_are_flagged(tmp_path, rng):
    for i in range(20):
        v = scan(write(tmp_path, f"m{i}.pdf", build_malicious(rng)))
        assert v.label == "MALICIOUS", v.to_dict()
        assert v.reasons


def test_known_false_positive_calculating_form(tmp_path):
    """Documented limitation: a legitimate form that computes a total with
    JavaScript uses the same mechanism as malware and gets flagged. If this
    test starts failing, the model has learned to tell them apart -- update
    the README's Limitations section."""
    v = scan(write(tmp_path, "order_form.pdf", build_calculating_form()))
    assert v.features.javascript_count == 1
    assert v.label != "CLEAN"


def test_cli_json_and_exit_codes(tmp_path, rng, capsys):
    clean = write(tmp_path, "clean.pdf", build_document(rng))
    bad = write(tmp_path, "bad.pdf", build_malicious(rng))

    assert main(["scan", str(clean)]) == 0
    capsys.readouterr()

    assert main(["scan", "--json", str(tmp_path)]) == 1
    results = json.loads(capsys.readouterr().out)
    assert {r["verdict"] for r in results} == {"CLEAN", "MALICIOUS"}
    assert main(["scan", str(tmp_path / "missing.pdf")]) == 2
