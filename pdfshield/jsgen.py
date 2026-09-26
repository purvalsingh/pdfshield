"""Generators for the JavaScript that goes into synthetic training PDFs.

Benign scripts imitate what real forms and viewers ship: Acrobat's built-in
form helpers (AFNumber_Format, AFSimple_Calculate ...), custom calculations,
validation, print/zoom-on-open, document-level helper functions and viewer
version checks, including the occasional legitimate ``eval``.

Malicious scripts wrap an *inert* core in the obfuscation layers real PDF
droppers use: escape-encoding + unescape, String.fromCharCode chains,
reversed strings, hex decoders, string timers and dense encoded blobs. The
core only sets a variable, asks the viewer to open an inert attachment, or
opens a URL on the reserved ``.invalid`` domain. No exploit code is generated,
and the vulnerable Acrobat APIs are detected (see jsanalysis.py) but never
called here.
"""

from __future__ import annotations

import base64
import random
import string

_FIELDS = ["qty", "price", "total", "subtotal", "tax", "name", "date", "phone", "amount", "line1", "line2"]


# --- benign -------------------------------------------------------------------

def _field(rng: random.Random) -> str:
    return rng.choice(_FIELDS)


def benign_field_script(rng: random.Random) -> tuple[str, str]:
    """(event key for the field's /AA, script) as written by form designers."""
    options = [
        ("/F", f'AFNumber_Format({rng.randint(0, 2)}, 0, 0, 0, "{rng.choice(["$", "", "€"])}", true);'),
        ("/K", f'AFNumber_Keystroke({rng.randint(0, 2)}, 0, 0, 0, "", true);'),
        ("/F", f'AFDate_FormatEx("{rng.choice(["mm/dd/yyyy", "dd/mm/yyyy", "yyyy-mm-dd"])}");'),
        ("/K", 'AFDate_KeystrokeEx("mm/dd/yyyy");'),
        ("/F", f"AFSpecial_Format({rng.randint(0, 3)});"),
        ("/F", f"AFPercent_Format({rng.randint(0, 2)}, 0);"),
        ("/V", f"AFRange_Validate(true, 0, true, {rng.choice([100, 1000, 99999])});"),
        ("/U", f'this.submitForm({{cURL: "https://forms.example.com/{rng.choice(["submit", "apply", "order"])}", cSubmitAs: "PDF"}});'),
        ("/C", 'AFSimple_Calculate("{}", new Array("{}", "{}"));'.format(
            rng.choice(["SUM", "PRD", "AVG"]), _field(rng), _field(rng))),
        ("/C", f'var a = this.getField("{_field(rng)}").value;\n'
               f'var b = this.getField("{_field(rng)}").value;\nevent.value = a * b;'),
        ("/C", f'event.value = this.getField("{_field(rng)}").value * {rng.choice(["1.08", "0.2", "9.99"])};'),
        ("/V", f'if (event.value.length > {rng.randint(5, 40)}) {{\n'
               f'  app.alert("Please enter at most the allowed number of characters.");\n  event.rc = false;\n}}'),
        # Old-style forms really do use eval to build field names.
        ("/C", "var total = 0;\nfor (var i = 1; i <= {n}; i++) {{\n"
               "  total += Number(eval('this.getField(\"line' + i + '\").value'));\n}}\n"
               "event.value = total;".format(n=rng.randint(2, 9))),
    ]
    return rng.choice(options)


def benign_open_script(rng: random.Random) -> str:
    return rng.choice([
        f"this.zoom = {rng.choice([75, 100, 125])};",
        "this.pageNum = 0;",
        'app.alert("Please complete all required fields before printing.");',
        "app.alert({cMsg: 'Welcome. Fill in the highlighted fields.', cTitle: 'Form', nIcon: 3});",
        "this.print({bUI: true, bSilent: false, bShrinkToFit: true});",
        'var f = this.getField("date");\nif (f) f.value = util.printd("mm/dd/yyyy", new Date());',
        "app.fs.isFullScreen = false;",
    ])


def benign_document_script(rng: random.Random) -> str:
    """Document-level helpers and viewer checks, like those form tools embed."""
    return rng.choice([
        'if (typeof(this.FORM) == "undefined") this.FORM = new Object();\n'
        'FORM.Title = "Registration form";\n'
        'FORM.UpgradeMessage = "This form needs a newer version of the viewer. '
        'Some features, such as calculated totals and dropdown lists, may not work correctly.";\n'
        'if (app.viewerVersion < 9) app.alert(FORM.UpgradeMessage);',
        # Vendor "upgrade your viewer" prompt: legitimate code that opens a URL.
        'if (app.viewerType == "Reader" && app.viewerVersion < {}) {{\n'
        '  var answer = app.alert("A newer version of Reader is required. Download it now?", 2, 2);\n'
        '  if (answer == 4) app.launchURL("https://get.adobe.com/reader/", true);\n}}'.format(rng.randint(8, 11)),
        'function formatPhone(value) {\n  return value.replace(/[^0-9]/g, "");\n}\n'
        'function isEmpty(value) {\n  return value === null || String(value).length === 0;\n}',
        'function resetTotals() {\n  this.getField("total").value = 0;\n  this.getField("tax").value = 0;\n}',
        'var FORM_VERSION = "{}";\nfunction checkRequired() {{\n'
        '  var missing = [];\n  for (var i = 0; i < this.numFields; i++) {{\n'
        '    var f = this.getField(this.getNthFieldName(i));\n'
        '    if (f.required && f.value === "") missing.push(f.name);\n  }}\n'
        '  if (missing.length) app.alert("Missing: " + missing.join(", "));\n}}'.format(
            f"{rng.randint(1, 9)}.{rng.randint(0, 9)}"),
    ])


# --- malicious (inert) ----------------------------------------------------------

def _ident(rng: random.Random) -> str:
    if rng.random() < 0.6:
        return "_0x" + "".join(rng.choices("0123456789abcdef", k=rng.randint(4, 6)))
    return "".join(rng.choices(string.ascii_letters, k=rng.randint(1, 3)))


def _inert_core(rng: random.Random, payload: str, attachment: str | None) -> str:
    var = _ident(rng)
    if payload == "open_attachment" and attachment:
        # nLaunch 2 asks the viewer to open the attachment: how droppers run
        # an embedded executable. The attachment here is inert placeholder text.
        return f'this.exportDataObject({{ cName: "{attachment}", nLaunch: 2 }});'
    if payload == "redirect":
        path = "".join(rng.choices(string.ascii_lowercase, k=8))
        return f'app.launchURL("https://example.invalid/{path}", true);'
    return f'var {var} = "pdfshield-inert-{rng.randint(1000, 9999)}";'


def _pct_u(text: str) -> str:
    if len(text) % 2:
        text += " "
    return "".join(f"%u{ord(text[i + 1]):02x}{ord(text[i]):02x}" for i in range(0, len(text), 2))


def _obfuscate(code: str, rng: random.Random) -> str:
    layer = rng.choice(["unescape_u", "unescape_pct", "hex_x", "charcode", "reverse", "hex_decoder", "timer"])
    q = code.replace("\\", "\\\\").replace('"', '\\"')
    if layer == "unescape_u":
        return f'eval(unescape("{_pct_u(code)}"));'
    if layer == "unescape_pct":
        return 'eval(unescape("{}"));'.format("".join(f"%{ord(c):02x}" for c in code))
    if layer == "hex_x":
        return 'eval("{}");'.format("".join(f"\\x{ord(c):02x}" for c in code))
    if layer == "charcode":
        return "eval(String.fromCharCode({}));".format(",".join(str(ord(c)) for c in code))
    if layer == "reverse":
        return f'eval("{q[::-1]}".split("").reverse().join(""));'
    if layer == "hex_decoder":
        v, s, i = _ident(rng), _ident(rng), _ident(rng)
        blob = code.encode().hex()
        return (f'var {v} = "{blob}";\nvar {s} = "";\n'
                f"for (var {i} = 0; {i} < {v}.length; {i} += 2) "
                f"{s} += String.fromCharCode(parseInt({v}.substr({i}, 2), 16));\neval({s});")
    return f'app.setTimeOut("{q}", {rng.randint(100, 3000)});'


def _dense_blob(rng: random.Random) -> str:
    """A long random-looking literal, like an encrypted/packed stage-2."""
    raw = bytes(rng.getrandbits(8) for _ in range(rng.randint(600, 15000)))
    return f'var {_ident(rng)} = "{base64.b64encode(raw).decode()}";'


def malicious_script(rng: random.Random, attachment: str | None = None) -> str:
    payload = rng.choices(["marker", "open_attachment", "redirect"],
                          weights=[4, 3 if attachment else 0, 2])[0]
    style = rng.choices(["plain", "one_layer", "two_layers"], weights=[1, 4, 3])[0]
    if style == "plain" and payload == "marker":
        payload = "redirect"  # an unobfuscated inert marker would not be malicious at all
    code = _inert_core(rng, payload, attachment)
    if style != "plain":
        code = _obfuscate(code, rng)
    if style == "two_layers":
        code = _obfuscate(code, rng)
    parts = [code]
    if rng.random() < 0.4:
        parts.insert(0, _dense_blob(rng))
    if rng.random() < 0.2:
        parts.append(benign_document_script(rng))  # decoy: looks like form code
    return "\n".join(parts)
