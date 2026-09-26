import io
import json
import random

import pikepdf
import pytest

from pdfshield import FEATURE_NAMES, extract_features, scan
from pdfshield.cli import main
from pdfshield.features import is_risky_action, is_risky_launch
from pdfshield.jsanalysis import analyze as analyze_js
from pdfshield.jsgen import malicious_script
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


def test_benign_documents_with_javascript_are_clean(tmp_path, rng):
    from pdfshield.samples import add_benign_js
    verdicts = [scan(write(tmp_path, f"j{i}.pdf", add_benign_js(build_document(rng, form=True), rng)))
                for i in range(40)]
    assert all(v.features.javascript_count for v in verdicts)
    # ~1% of these use eval() legitimately and score as SUSPICIOUS (measured
    # 198/200 clean); none may reach MALICIOUS.
    assert sum(v.label == "CLEAN" for v in verdicts) >= 38
    assert not any(v.label == "MALICIOUS" for v in verdicts)


def test_malicious_documents_are_flagged(tmp_path, rng):
    # Benign documents now carry JavaScript too, so separation is no longer
    # perfect by construction: an unobfuscated launchURL-on-open looks like a
    # vendor upgrade prompt. Require a high flag rate, not per-file perfection.
    verdicts = [scan(write(tmp_path, f"m{i}.pdf", build_malicious(rng))) for i in range(60)]
    flagged = [v for v in verdicts if v.label != "CLEAN"]
    assert len(flagged) >= 58
    assert sum(v.label == "MALICIOUS" for v in verdicts) >= 45
    assert all(v.reasons for v in flagged)


def test_calculating_form_is_clean(tmp_path):
    """Regression: a legitimate form that computes a total with JavaScript
    uses the same /AA + JavaScript mechanism as malware. It was a documented
    false positive until JavaScript content analysis was added."""
    v = scan(write(tmp_path, "order_form.pdf", build_calculating_form()))
    assert v.features.javascript_count == 1
    assert v.features.js_suspicious_calls == 0
    assert v.label == "CLEAN", v.to_dict()


# --- JavaScript analysis ------------------------------------------------------

@pytest.mark.parametrize("script", [
    'AFSimple_Calculate("SUM", new Array("a", "b"));',
    'AFDate_FormatEx("mm/dd/yyyy");',
    'event.value = this.getField("qty").value * 9.99;',
    "this.print({bUI: true, bSilent: false});",
])
def test_form_javascript_is_not_suspicious(script):
    report = analyze_js([script])
    assert report.suspicious_calls == 0
    assert report.encoded_ratio < 0.2


def test_obfuscated_javascript_is_detected():
    report = analyze_js(['eval(unescape("%u6176%u2072%u203d%u3b31"));'])
    assert {"eval", "unescape"} <= set(report.calls_found)
    assert report.encoded_ratio > 0.3


def test_network_calls_are_counted_separately():
    report = analyze_js(['app.launchURL("https://get.adobe.com/reader/", true);'])
    assert report.network_calls == 1 and report.suspicious_calls == 0


def test_generated_malicious_scripts_always_carry_a_signal():
    rng = random.Random(5)
    for _ in range(200):
        r = analyze_js([malicious_script(rng, "invoice.exe")])
        assert r.suspicious_calls or r.network_calls or r.encoded_ratio >= 0.2


# --- action classification ----------------------------------------------------

@pytest.mark.parametrize("target,risky", [
    ("cmd.exe", True), ("C:\\Windows\\System32\\mshta.exe", True), ("powershell", True),
    ("payload.hta", True), ("toolkit.pdf", False), ("C:/Users/x/PyMuPDF-doc//index", False),
    ("\\\\evil.invalid\\share\\a.pdf", True),
])
def test_launch_targets(target, risky):
    action = pikepdf.Dictionary(S=pikepdf.Name.Launch, F=pikepdf.String(target))
    assert is_risky_launch(action) is risky


def test_remote_gotor_is_risky_but_local_is_not():
    remote = pikepdf.Dictionary(S=pikepdf.Name.GoToR, F=pikepdf.String("\\\\host.invalid\\s\\a.pdf"))
    local = pikepdf.Dictionary(S=pikepdf.Name.GoToR, F=pikepdf.String("chapter2.pdf"))
    assert is_risky_action(remote) and not is_risky_action(local)


def test_document_level_javascript_counts_as_auto_run(tmp_path, rng):
    with pikepdf.open(io.BytesIO(build_document(rng, encrypt=False))) as pdf:
        action = pdf.make_indirect(pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS=pikepdf.String("var a = 1;")))
        pdf.Root.Names = pikepdf.Dictionary(JavaScript=pikepdf.Dictionary(Names=[pikepdf.String("a"), action]))
        buf = io.BytesIO()
        pdf.save(buf)
    assert extract_features(write(tmp_path, "docjs.pdf", buf.getvalue())).open_action == 1


# --- files we cannot fully read -------------------------------------------------

def test_password_protected_autorun_is_flagged_by_policy(tmp_path, rng):
    with pikepdf.open(io.BytesIO(build_malicious(rng))) as pdf:
        buf = io.BytesIO()
        pdf.save(buf, encryption=pikepdf.Encryption(owner="o", user="secret"))
    v = scan(write(tmp_path, "locked.pdf", buf.getvalue()))
    assert v.features.password_protected
    if v.features.open_action or v.features.additional_actions:
        assert v.label != "CLEAN"


def test_fallback_understands_navigation_open_actions(tmp_path):
    for i, raw in enumerate([b"junk /OpenAction << /S /GoTo /D [3 0 R /Fit] >>",
                             b"junk /OpenAction 5 0 R 5 0 obj [3 0 R /Fit] endobj"]):
        f = extract_features(write(tmp_path, f"nav{i}.pdf", raw))
        assert f.parse_error and f.open_action == 0


def test_cli_json_and_exit_codes(tmp_path, rng, capsys):
    clean = write(tmp_path, "clean.pdf", build_document(rng))
    bad = write(tmp_path, "bad.pdf", build_malicious(rng))

    assert main(["scan", str(clean)]) == 0
    capsys.readouterr()

    assert main(["scan", "--json", str(tmp_path)]) == 1
    results = json.loads(capsys.readouterr().out)
    assert {r["verdict"] for r in results} == {"CLEAN", "MALICIOUS"}
    assert main(["scan", str(tmp_path / "missing.pdf")]) == 2
