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
from dataclasses import asdict, dataclass

import pikepdf

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
]

FEATURE_DESCRIPTIONS = {
    "page_count": "Number of pages",
    "object_count": "Number of indirect objects",
    "file_size_kb": "File size in KB",
    "javascript_count": "Embedded JavaScript actions",
    "open_action": "Runs an action automatically when the file is opened (/OpenAction)",
    "additional_actions": "Event-triggered actions on pages, fields or the document (/AA)",
    "launch_action": "Can launch an external program or file (/Launch)",
    "embedded_file_count": "Files embedded inside the PDF (/EmbeddedFile)",
    "acroform": "Contains an interactive form (/AcroForm)",
    "xfa": "Contains an XFA form, a frequent exploit target (/XFA)",
    "uri_count": "External links (/URI)",
    "encrypted": "The document is encrypted",
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
    parse_error: bool = False

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


def _scan_objects(pdf: pikepdf.Pdf, feats: PDFFeatures) -> None:
    for obj in _dictionaries(pdf):
        keys = set(obj.keys())

        action_type = _name(obj.get("/S"))
        if "/JS" in keys or action_type == "/JavaScript":
            feats.javascript_count += 1
        if action_type == "/Launch":
            feats.launch_action += 1
        if action_type == "/URI" or "/URI" in keys:
            feats.uri_count += 1
        if "/AA" in keys:
            feats.additional_actions += 1
        if _name(obj.get("/Type")) == "/EmbeddedFile":
            feats.embedded_file_count += 1


# Actions that only move the view. Word, LibreOffice and many generators write
# an /OpenAction like [page /XYZ null null 0] ("open at page 1"); counting that
# as an auto-run action flags ordinary office documents.
_NAVIGATION_ACTIONS = {"/GoTo"}


def _is_executable_open_action(action) -> bool:
    if action is None or isinstance(action, pikepdf.Array):  # explicit destination
        return False
    if isinstance(action, pikepdf.Dictionary):
        return _name(action.get("/S")) not in _NAVIGATION_ACTIONS
    return False  # named destination (string/name)


def _extract_structured(path: str, feats: PDFFeatures) -> None:
    # pikepdf normalises obfuscated names such as /J#61vaScript -> /JavaScript,
    # which a naive byte search would miss.
    with pikepdf.open(path) as pdf:
        feats.encrypted = int(pdf.is_encrypted)
        feats.page_count = len(pdf.pages)
        feats.object_count = len(pdf.objects)

        root = pdf.Root
        feats.open_action = int(_is_executable_open_action(root.get("/OpenAction")))
        if "/AA" in root:
            feats.additional_actions += 1
        if "/AcroForm" in root:
            feats.acroform = 1
            feats.xfa = int("/XFA" in root.AcroForm)

        _scan_objects(pdf, feats)


# Byte patterns used when the file cannot be parsed. Name escapes (#xx) are
# decoded before matching so trivial obfuscation does not hide keywords.
_FALLBACK_PATTERNS = {
    "javascript_count": rb"/JavaScript\b|/JS\b",
    # An inline array is a "go to page" destination, not an action.
    "open_action": rb"/OpenAction\b(?!\s*\[)",
    "additional_actions": rb"/AA\b",
    "launch_action": rb"/Launch\b",
    "embedded_file_count": rb"/EmbeddedFile\b",
    "acroform": rb"/AcroForm\b",
    "xfa": rb"/XFA\b",
    "uri_count": rb"/URI\b",
    "encrypted": rb"/Encrypt\b",
}
_BINARY_FLAGS = {"open_action", "acroform", "xfa", "encrypted"}


def _decode_name_escapes(data: bytes) -> bytes:
    return re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), data)


def _extract_fallback(path: str, feats: PDFFeatures) -> None:
    with open(path, "rb") as fh:
        data = _decode_name_escapes(fh.read())
    feats.page_count = len(re.findall(rb"/Type\s*/Page\b", data))
    feats.object_count = len(re.findall(rb"\d+\s+\d+\s+obj\b", data))
    for field, pattern in _FALLBACK_PATTERNS.items():
        count = len(re.findall(pattern, data))
        setattr(feats, field, min(count, 1) if field in _BINARY_FLAGS else count)


def extract_features(path: str | os.PathLike) -> PDFFeatures:
    """Extract structural features from the PDF at ``path``."""
    path = os.fspath(path)
    feats = PDFFeatures(file_size_kb=round(os.path.getsize(path) / 1024, 2))
    try:
        _extract_structured(path, feats)
    except (pikepdf.PdfError, pikepdf.PasswordError, ValueError, RecursionError):
        feats = PDFFeatures(file_size_kb=feats.file_size_kb, parse_error=True)
        _extract_fallback(path, feats)
    return feats
