"""Static analysis of JavaScript embedded in a PDF.

The script is never executed. We measure the things that separate attack code
from the JavaScript that legitimate forms are full of:

* **Network calls** - ``launchURL``, ``submitForm`` ... (weaker: forms use them).
* **Suspicious calls** - dynamic code execution (``eval``, ``Function``),
  decoding tricks (``unescape``, ``String.fromCharCode``), and the Acrobat
  APIs that real PDF exploits have abused (``util.printf``,
  ``Collab.getIcon``, ``media.newPlayer`` ...) or that open dropped
  payloads (``exportDataObject``).
* **Encoding** - how much of the script is escape sequences (``%u4141``,
  ``\\x41``) or long hex runs: payloads are smuggled as encoded strings.
* **Entropy and longest string literal** - packed/encrypted payloads are long,
  dense, random-looking strings. Form scripts are short and wordy.

Legitimate form code (``AFSimple_Calculate("SUM", ...)``, ``event.value = ...``,
``app.alert(...)``) scores low on all of these, even though it uses the same
/AA and /OpenAction triggers as malware.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

# (label, pattern) - the label is what a user sees in the verdict.
SUSPICIOUS_CALLS = [
    ("eval", r"\beval\s*\("),
    ("Function constructor", r"\bnew\s+Function\s*\(|\bFunction\s*\(\s*['\"]"),
    ("unescape", r"\bunescape\s*\("),
    ("String.fromCharCode", r"\bString\s*\.\s*fromCharCode\b"),
    ("string-based timer", r"\b(?:app\s*\.\s*)?set(?:TimeOut|Timeout|Interval)\s*\(\s*['\"]"),
    ("reversed/split string", r"\.split\(\s*['\"]{2}\s*\)\s*\.reverse\(\)"),
    ("exportDataObject (opens attachment)", r"\.exportDataObject\s*\("),
    ("util.printf", r"\butil\s*\.\s*printf\s*\("),
    ("Collab.getIcon", r"\bCollab\s*\.\s*getIcon\b"),
    ("Collab.collectEmailInfo", r"\bCollab\s*\.\s*collectEmailInfo\b"),
    ("media.newPlayer", r"\bmedia\s*\.\s*newPlayer\b"),
    ("spell.customDictionaryOpen", r"\bspell\s*\.\s*customDictionaryOpen\b"),
    ("getAnnots", r"\.getAnnots\s*\("),
    ("syncAnnotScan", r"\.syncAnnotScan\s*\("),
]
_CALL_PATTERNS = [(label, re.compile(p)) for label, p in SUSPICIOUS_CALLS]

# Calls that reach the network. Legitimate code uses them too (Adobe's own
# "get the latest Reader" prompt calls launchURL), so they are a separate,
# weaker signal rather than part of the suspicious-call count.
NETWORK_CALLS = [
    ("launchURL", r"\blaunchURL\s*\("),
    ("getURL", r"\.getURL\s*\("),
    ("submitForm", r"\.submitForm\s*\("),
    ("mailDoc", r"\.mailDoc\s*\("),
    ("Net.HTTP", r"\bNet\s*\.\s*HTTP\b"),
    ("SOAP", r"\bSOAP\s*\.\s*(?:request|connect)\b"),
]
_NETWORK_PATTERNS = [(label, re.compile(p)) for label, p in NETWORK_CALLS]

_ENCODED = re.compile(
    r"%u[0-9A-Fa-f]{4}|\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}|%[0-9A-Fa-f]{2}|&#x?[0-9A-Fa-f]{1,6};|[0-9A-Fa-f]{40,}"
)
_STRING_LITERAL = re.compile(r"'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\"")

MAX_JS_CHARS = 2_000_000  # analysis budget per file


@dataclass
class JSReport:
    length: int = 0
    suspicious_calls: int = 0
    network_calls: int = 0
    encoded_ratio: float = 0.0
    entropy: float = 0.0
    max_string_len: int = 0
    calls_found: list[str] = field(default_factory=list)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def analyze(scripts: list[str]) -> JSReport:
    source = "\n".join(scripts)[:MAX_JS_CHARS]
    if not source.strip():
        return JSReport()

    found = Counter()
    for label, pattern in _CALL_PATTERNS:
        hits = len(pattern.findall(source))
        if hits:
            found[label] += hits

    network = 0
    for label, pattern in _NETWORK_PATTERNS:
        hits = len(pattern.findall(source))
        if hits:
            network += hits
            found[label] += hits

    encoded_chars = sum(len(m.group(0)) for m in _ENCODED.finditer(source))
    longest = max((len(m.group(0)) - 2 for m in _STRING_LITERAL.finditer(source)), default=0)

    return JSReport(
        length=len(source),
        suspicious_calls=sum(found.values()) - network,
        network_calls=network,
        encoded_ratio=round(encoded_chars / len(source), 4),
        entropy=round(shannon_entropy(source), 4),
        max_string_len=longest,
        calls_found=sorted(found),
    )
