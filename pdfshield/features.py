"""Static structural feature extraction for PDF files.

Nothing here renders the PDF or executes any of its content. We parse the
object graph with pikepdf (qpdf under the hood) and count the structures that
malware analysts look for. If the file is too malformed to parse -- common for
real malicious PDFs -- we fall back to a raw byte scan in the spirit of
Didier Stevens' pdfid.
"""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field

import pikepdf

from .jsanalysis import analyze as analyze_js

# Order matters: this is the column order the model is trained on.
FEATURE_NAMES = [
    "page_count",
    "object_count",
    "file_size_kb",
    "javascript_count",
    "open_action",
    "additional_actions",
    "launch_action",
    "embedded_file_count",
    "acroform",
    "xfa",
    "uri_count",
    "encrypted",
    "js_length",
    "js_suspicious_calls",
    "js_network_calls",
    "js_encoded_ratio",
    "js_entropy",
    "js_max_string_len",
]

FEATURE_DESCRIPTIONS = {
    "page_count": "Number of pages",
    "object_count": "Number of indirect objects",
    "file_size_kb": "File size in KB",
    "javascript_count": "Embedded JavaScript actions",
    "open_action": "Runs code automatically when the file is opened (/OpenAction or document-level JavaScript)",
    "additional_actions": "Event-triggered actions that execute something (/AA)",
    "launch_action": "Can launch an external program (/Launch)",
    "embedded_file_count": "Files embedded inside the PDF (/EmbeddedFile)",
    "acroform": "Contains an interactive form (/AcroForm)",
    "xfa": "Contains an XFA form, a frequent exploit target (/XFA)",
    "uri_count": "External links (/URI)",
    "encrypted": "The document is encrypted",
    "js_length": "Total JavaScript size in characters",
    "js_suspicious_calls": "JavaScript calls used by exploits and droppers",
    "js_network_calls": "JavaScript calls that open URLs or send data",
    "js_encoded_ratio": "Share of the JavaScript that is escape-encoded",
    "js_entropy": "Shannon entropy of the JavaScript (bits per character)",
    "js_max_string_len": "Longest string literal in the JavaScript",
}


@dataclass
class PDFFeatures:
    page_count: int = 0
    object_count: int = 0
    file_size_kb: float = 0.0
    javascript_count: int = 0
    open_action: int = 0
    additional_actions: int = 0
    launch_action: int = 0
    embedded_file_count: int = 0
    acroform: int = 0
    xfa: int = 0
    uri_count: int = 0
    encrypted: int = 0
    js_length: int = 0
    js_suspicious_calls: int = 0
    js_network_calls: int = 0
    js_encoded_ratio: float = 0.0
    js_entropy: float = 0.0
    js_max_string_len: int = 0
    # Not model inputs: context for explanations.
    js_calls: list[str] = field(default_factory=list)
    parse_error: bool = False
    password_protected: bool = False

    def to_vector(self) -> list[float]:
        return [float(getattr(self, name)) for name in FEATURE_NAMES]

    def to_dict(self) -> dict:
        return asdict(self)


def _name(obj) -> str | None:
    """Return a pikepdf Name as a plain string, or None."""
    if isinstance(obj, pikepdf.Name):
        return str(obj)
    return None


def _dictionaries(pdf: pikepdf.Pdf):
    """Yield every dictionary in the file, including direct ones nested inside
    other objects (e.g. an inline /A action inside a link annotation).

    Indirect references are not followed while descending: each indirect
    object is visited exactly once from ``pdf.objects``.
    """
    for top in pdf.objects:
        stack = [top]
        while stack:
            obj = stack.pop()
            # Streams expose their dictionary via the same mapping interface.
            if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)):
                yield obj
                children = obj.values()
            elif isinstance(obj, pikepdf.Array):
                children = obj
            else:
                continue
            stack.extend(c for c in children
                         if isinstance(c, (pikepdf.Dictionary, pikepdf.Array)) and not c.is_indirect)


# Actions that only move the view or toggle display. Word, LibreOffice and
# many generators write an /OpenAction like [page /XYZ null null 0] ("open at
# page 1"); counting that as auto-run flags ordinary office documents.
_NAVIGATION_ACTIONS = {"/GoTo", "/Named", "/Thread", "/Trans", "/SetOCGState", "/GoTo3DView", "/Hide", "/ResetForm"}
# Launch targets that run code. Real documents also launch other documents
# and (often broken) local paths, so only executables and shells count.
_EXECUTABLE_EXTENSIONS = (
    ".exe", ".com", ".bat", ".cmd", ".scr", ".pif", ".cpl", ".msi", ".msp", ".dll", ".lnk", ".reg",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".jar",
    ".sh", ".bash", ".command", ".app", ".py", ".pl", ".rb",
)
_SHELLS = {"cmd", "powershell", "pwsh", "mshta", "wscript", "cscript", "rundll32", "regsvr32",
           "certutil", "bitsadmin", "sh", "bash", "zsh", "osascript", "open", "xdg-open"}


def _text(obj) -> str:
    if isinstance(obj, pikepdf.String):
        return str(obj)
    if isinstance(obj, pikepdf.Stream):
        return obj.read_bytes().decode("latin-1")
    return ""


def _action_target(action: pikepdf.Dictionary) -> str:
    """The file or path an action points at (/F string, file spec, or /Win)."""
    for holder in (action, action.get("/Win")):
        if not isinstance(holder, pikepdf.Dictionary):
            continue
        target = holder.get("/F")
        if isinstance(target, pikepdf.Dictionary):
            target = target.get("/UF", target.get("/F"))
        if isinstance(target, pikepdf.String):
            return str(target)
    return ""


def _is_remote_path(target: str) -> bool:
    # \\host\share or //host/share: opening it makes Windows send the user's
    # NTLM credentials to that host (a known GoToR/GoToE attack).
    return target.startswith(("\\\\", "//")) or "://" in target


def is_risky_launch(action: pikepdf.Dictionary) -> bool:
    target = _action_target(action).strip().lower()
    win = action.get("/Win")
    if isinstance(win, pikepdf.Dictionary) and "/P" in win:
        return True  # passes command-line parameters
    if not target or _is_remote_path(target):
        return True
    name = re.split(r"[\\/]", target)[-1]
    return name.endswith(_EXECUTABLE_EXTENSIONS) or name.rsplit(".", 1)[0] in _SHELLS


def is_risky_action(action, _depth: int = 0) -> bool:
    """True if ``action`` executes something rather than just navigating."""
    if not isinstance(action, pikepdf.Dictionary) or _depth > 20:
        return False  # destination array or name: pure navigation
    kind = _name(action.get("/S"))
    if kind in ("/GoToR", "/GoToE"):
        risky = _is_remote_path(_action_target(action))
    elif kind == "/Launch":
        risky = is_risky_launch(action)
    else:
        risky = kind is not None and kind not in _NAVIGATION_ACTIONS
    if risky:
        return True
    following = action.get("/Next")
    chain = following if isinstance(following, pikepdf.Array) else [following]
    return any(is_risky_action(a, _depth + 1) for a in chain if a is not None)


def _has_document_js(root: pikepdf.Dictionary) -> bool:
    """Document-level JavaScript (/Names /JavaScript) runs when the file opens."""
    names = root.get("/Names")
    if not isinstance(names, pikepdf.Dictionary):
        return False
    tree = names.get("/JavaScript")
    return isinstance(tree, pikepdf.Dictionary) and ("/Names" in tree or "/Kids" in tree)


def _scan_objects(pdf: pikepdf.Pdf, feats: PDFFeatures, scripts: list[str]) -> None:
    for obj in _dictionaries(pdf):
        keys = set(obj.keys())

        action_type = _name(obj.get("/S"))
        if "/JS" in keys or action_type == "/JavaScript":
            feats.javascript_count += 1
            try:
                scripts.append(_text(obj.get("/JS")))
            except pikepdf.PdfError:
                pass
        if action_type == "/Launch" and is_risky_launch(obj):
            feats.launch_action += 1
        if action_type == "/URI" or "/URI" in keys:
            feats.uri_count += 1
        aa = obj.get("/AA")
        if isinstance(aa, pikepdf.Dictionary) and any(is_risky_action(a) for a in aa.values()):
            feats.additional_actions += 1
        if _name(obj.get("/Type")) == "/EmbeddedFile":
            feats.embedded_file_count += 1


def _count_pages(pdf: pikepdf.Pdf) -> int:
    try:
        return len(pdf.pages)
    except pikepdf.PdfError:
        # Broken page tree (loops, missing /Kids): count page objects directly
        # instead of giving up on the whole file.
        return sum(1 for o in pdf.objects
                   if isinstance(o, pikepdf.Dictionary) and _name(o.get("/Type")) == "/Page")


def _apply_js(feats: PDFFeatures, scripts: list[str]) -> None:
    report = analyze_js(scripts)
    feats.js_length = report.length
    feats.js_suspicious_calls = report.suspicious_calls
    feats.js_network_calls = report.network_calls
    feats.js_encoded_ratio = report.encoded_ratio
    feats.js_entropy = report.entropy
    feats.js_max_string_len = report.max_string_len
    feats.js_calls = report.calls_found


def _extract_structured(path: str, feats: PDFFeatures) -> None:
    # pikepdf normalises obfuscated names such as /J#61vaScript -> /JavaScript,
    # which a naive byte search would miss.
    # inherit_page_attributes=False: we never need inherited page attributes,
    # and computing them walks the page tree, which fails on looping trees.
    with pikepdf.open(path, inherit_page_attributes=False) as pdf:
        feats.encrypted = int(pdf.is_encrypted)
        feats.page_count = _count_pages(pdf)
        feats.object_count = len(pdf.objects)

        root = pdf.Root
        feats.open_action = int(is_risky_action(root.get("/OpenAction")) or _has_document_js(root))
        if "/AcroForm" in root:
            feats.acroform = 1
            feats.xfa = int("/XFA" in root.AcroForm)

        scripts: list[str] = []
        _scan_objects(pdf, feats, scripts)
        _apply_js(feats, scripts)


# Byte patterns used when the file cannot be parsed. Name escapes (#xx) are
# decoded before matching so trivial obfuscation does not hide keywords.
_FALLBACK_PATTERNS = {
    "javascript_count": rb"/JavaScript\b|/JS\b",
    "additional_actions": rb"/AA\b",
    "embedded_file_count": rb"/EmbeddedFile\b",
    "acroform": rb"/AcroForm\b",
    "xfa": rb"/XFA\b",
    "uri_count": rb"/URI\b",
    "encrypted": rb"/Encrypt\b",
}
_BINARY_FLAGS = {"acroform", "xfa", "encrypted"}


def _decode_name_escapes(data: bytes) -> bytes:
    return re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), data)


_JS_KEY = re.compile(rb"/JS\s*\(")


def _raw_js_literals(data: bytes, limit: int = 200_000) -> list[str]:
    """Read /JS (...) literal strings, honouring nested parentheses and escapes."""
    scripts = []
    for match in _JS_KEY.finditer(data):
        i, depth, out = match.end(), 1, bytearray()
        while i < len(data) and depth and len(out) < limit:
            ch = data[i]
            if ch == 0x5C and i + 1 < len(data):  # backslash escape
                out += data[i:i + 2]
                i += 2
                continue
            depth += (ch == 0x28) - (ch == 0x29)
            if depth:
                out.append(ch)
            i += 1
        scripts.append(out.decode("latin-1"))
    return scripts


def _raw_action_kind(body: bytes) -> str | None:
    kind = re.search(rb"/S\s*/(\w+)", body[:600])
    return "/" + kind.group(1).decode("latin-1") if kind else None


def _fallback_open_action(data: bytes) -> bool:
    """Is any /OpenAction an action rather than a destination or /GoTo?

    Handles inline arrays, inline dictionaries and `N G R` references.
    """
    for m in re.finditer(rb"/OpenAction\s*", data):
        rest = data[m.end():m.end() + 600]
        if rest.startswith(b"["):
            continue
        ref = re.match(rb"(\d+)\s+(\d+)\s+R", rest)
        if ref:
            obj = re.search(rb"(?<!\d)" + ref.group(1) + rb"\s+" + ref.group(2) + rb"\s+obj\s*(.{0,600})", data, re.S)
            if obj is None:
                return True  # unresolvable (e.g. inside a compressed object stream): be conservative
            rest = obj.group(1).lstrip()
            if rest.startswith(b"["):
                continue
        if _raw_action_kind(rest) not in _NAVIGATION_ACTIONS:
            return True
    return False


def _fallback_launch_count(data: bytes, encrypted: bool) -> int:
    count = 0
    for m in re.finditer(rb"/S\s*/Launch\b", data):
        window = data[max(0, m.start() - 400):m.end() + 400]
        target = re.search(rb"/F\s*\(((?:[^()\\]|\\.){1,300})\)", window)
        if encrypted or target is None:
            count += 1  # target unreadable: be conservative
            continue
        name = re.split(r"[\\/]", target.group(1).decode("latin-1").strip().lower())[-1]
        count += name.endswith(_EXECUTABLE_EXTENSIONS) or name.rsplit(".", 1)[0] in _SHELLS
    return count


def _extract_fallback(path: str, feats: PDFFeatures) -> None:
    with open(path, "rb") as fh:
        data = _decode_name_escapes(fh.read())
    feats.page_count = len(re.findall(rb"/Type\s*/Page\b", data))
    feats.object_count = len(re.findall(rb"\d+\s+\d+\s+obj\b", data))
    for name, pattern in _FALLBACK_PATTERNS.items():
        count = len(re.findall(pattern, data))
        setattr(feats, name, min(count, 1) if name in _BINARY_FLAGS else count)
    feats.open_action = int(_fallback_open_action(data))
    feats.launch_action = _fallback_launch_count(data, bool(feats.encrypted))
    # Inline JavaScript literals are readable unless the file is encrypted, in
    # which case they are ciphertext and would look like obfuscation.
    if not feats.encrypted:
        _apply_js(feats, _raw_js_literals(data))


def extract_features(path: str | os.PathLike) -> PDFFeatures:
    """Extract structural features from the PDF at ``path``."""
    path = os.fspath(path)
    feats = PDFFeatures(file_size_kb=round(os.path.getsize(path) / 1024, 2))
    try:
        _extract_structured(path, feats)
    except pikepdf.PasswordError:
        # Needs a password to open, so the contents cannot be inspected.
        # Attackers use this to get past scanners (the password is in the email).
        feats = PDFFeatures(file_size_kb=feats.file_size_kb, parse_error=True, password_protected=True)
        _extract_fallback(path, feats)
    except (pikepdf.PdfError, ValueError, RecursionError):
        feats = PDFFeatures(file_size_kb=feats.file_size_kb, parse_error=True)
        _extract_fallback(path, feats)
    return feats
