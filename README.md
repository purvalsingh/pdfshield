<div align="center">

# 🛡️ PDFShield

**Catch malicious PDFs before anyone opens them.**

A machine-learning classifier that reads a PDF's *internal structure* and *what its JavaScript actually does*
(auto-run triggers, obfuscated code, launch commands, dropped attachments) and tells you how risky it is,
and **why**. It never renders or executes the file.

[![tests](https://github.com/purvalsingh/pdfshield/actions/workflows/tests.yml/badge.svg)](https://github.com/purvalsingh/pdfshield/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Model](https://img.shields.io/badge/model-Random%20Forest-orange)
![Real--world](https://img.shields.io/badge/real--world%20benign-97.9%25-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

<img src="docs/demo.svg" alt="PDFShield scanning a folder of PDFs" width="720">

</div>

---

## ✨ Why PDFShield?

- **🧠 A real trained model, not an LLM wrapper.** A scikit-learn Random Forest over 17 features, evaluated on held-out data, stress tests and **281 real-world PDFs**.
- **📜 Reads the JavaScript, not just its presence.** A form that calculates a total and a dropper that runs `eval(unescape("%u…"))` both "have JavaScript". PDFShield tells them apart.
- **🔍 Explains every verdict.** *"JavaScript uses eval, unescape"*, *"Can launch an external program"*, or *"looks like ordinary form code"*.
- **🔒 Safe by design.** Static analysis only. Nothing is rendered or executed, and the Docker image runs with no network, a read-only filesystem and no privileges.
- **🥷 Handles evasion tricks.** Hex-escaped names (`/J#61vaScript`), code hidden in compressed object streams, broken page trees, truncated files, and password-protected files.
- **⚙️ Scriptable.** JSON output, whole-folder scans, and exit codes you can use to block uploads in a CI pipeline.

## 🚀 Quick start

```bash
git clone https://github.com/purvalsingh/pdfshield.git
cd pdfshield
pip install -e .

pdfshield scan suspicious.pdf
```

That's it. A trained model ships with the repo, so there's nothing else to download.

### 🐳 Or run it in Docker (recommended for untrusted files)

```bash
docker build -t pdfshield .
docker run --rm --network none --read-only --cap-drop ALL \
  -v "$PWD/inbox:/scan:ro" pdfshield scan .
```

The container runs as an unprivileged user with no network and a read-only filesystem,
and your PDFs are mounted read-only, so even a file built to attack the parser has nowhere to go.

## 📖 Usage

### Scan files or whole folders

```bash
pdfshield scan invoice.pdf                 # one file
pdfshield scan report.pdf invoice.pdf      # several files
pdfshield scan ~/Downloads                 # every PDF in a folder, recursively
```

Every file gets one of three verdicts:

| Verdict | Risk score | Meaning |
|---|---|---|
| ✔ **CLEAN** | < 50% | Nothing suspicious found |
| ! **SUSPICIOUS** | 50–80% | Risky or uninspectable content; review before opening |
| ✖ **MALICIOUS** | ≥ 80% | Strong malware indicators; don't open it |

### JSON output (for scripts and dashboards)

```bash
pdfshield scan invoice.pdf --json
```

```json
[
  {
    "file": "invoice.pdf",
    "verdict": "MALICIOUS",
    "risk_score": 1.0,
    "reasons": [
      "JavaScript uses eval, unescape",
      "Runs code automatically when the file is opened (/OpenAction or document-level JavaScript)",
      "Event-triggered actions that execute something (/AA)",
      "..."
    ],
    "features": { "open_action": 1, "js_suspicious_calls": 3, "js_encoded_ratio": 0.1336, "js_max_string_len": 9580, "...": "..." }
  }
]
```

### Use it as a gate in CI or an upload pipeline

`pdfshield scan` exits with a code you can check:

| Exit code | Meaning |
|---|---|
| `0` | All files clean |
| `1` | At least one file flagged |
| `2` | No files found |

```bash
pdfshield scan uploads/ || echo "Rejecting upload: suspicious PDF detected"
```

### Use it from Python

```python
from pdfshield import scan

verdict = scan("invoice.pdf")
print(verdict.label, f"{verdict.score:.0%}")   # MALICIOUS 100%
for reason in verdict.reasons:
    print(" -", reason)
```

### Inspect the raw features

```bash
pdfshield features invoice.pdf
```

### Measure accuracy on your own PDFs

```bash
pdfshield evaluate                                   # held-out + stress tests
pdfshield evaluate --real ~/Documents --output eval.json
```

`--real` scans your own folders and reports the hit rate, next to a simple-rule baseline, plus every file it got
wrong. Files under a folder named `malicious/` count as malicious, and everything else counts as benign.
Pointing it at a folder of your everyday PDFs is the quickest way to see how it does on your kind of documents.

## ⚙️ How it works

```mermaid
flowchart LR
    A[📄 PDF file] --> B[Parse object graph<br/>with pikepdf]
    B -- unparseable or<br/>password-protected --> C[Raw byte scan<br/>fallback]
    B --> J[Static JavaScript<br/>analysis]
    B --> D[17 features]
    J --> D
    C --> D
    D --> E[🌲 Random Forest]
    E --> P{Auto-run code<br/>we can't read?}
    P -- yes --> S[Raise to<br/>SUSPICIOUS]
    P -- no --> F[Risk score +<br/>verdict + reasons]
    S --> F
```

1. **Parse, don't render.** [pikepdf](https://github.com/pikepdf/pikepdf) (built on qpdf) walks every object in the file, including actions nested inside other objects and objects packed into compressed streams.
2. **Classify each action by what it does.** "Open at page 1" and links to other PDFs are navigation. JavaScript, launching `cmd.exe`, or opening `\\host\share` (which leaks Windows credentials) are execution.
3. **Analyze the JavaScript statically.** It's never executed. PDFShield counts exploit and dropper calls, measures how much of the code is escape-encoded, and looks for long, dense, random-looking strings.
4. **Classify** with a Random Forest (200 trees, depth 8).
5. **Apply one policy rule.** If code runs automatically but can't be read (password-protected, or only ciphertext left), the file is raised to SUSPICIOUS rather than guessed clean.
6. **Explain** every red flag, and say so when JavaScript looks like ordinary form code.

### The 17 features

| Group | Features | What they catch |
|---|---|---|
| **Triggers** | `open_action`, `additional_actions` | Code that runs on open, or on page/field events, without a click |
| **Payloads** | `launch_action`, `embedded_file_count`, `javascript_count` | Programs launched, files dropped, scripts present |
| **JavaScript content** | `js_suspicious_calls` | `eval`, `unescape`, `String.fromCharCode`, string timers, `exportDataObject`, and Acrobat APIs abused by past exploits (`util.printf`, `Collab.getIcon`, `media.newPlayer`…) |
| | `js_network_calls` | `launchURL`, `submitForm`, `getURL`… (a weaker signal, since real forms use them too) |
| | `js_encoded_ratio`, `js_entropy`, `js_max_string_len`, `js_length` | Obfuscation: `%u4141`/`\x41` escapes, packed payload strings |
| **Context** | `acroform`, `xfa`, `uri_count`, `encrypted` | Common in *both* benign and malicious files |
| **Shape** | `page_count`, `object_count`, `file_size_kb` | Document size |

## 📊 Model performance

All results below are reproducible with `pdfshield train && pdfshield evaluate`. The same pipeline runs from a clean
checkout in a fresh `python:3.12-slim` container and in CI.

### Headline numbers

| Test set | Result | Simple-rule baseline¹ |
|---|---|---|
| **Real-world benign PDFs** (281 files) | **97.9%** correctly clean | 96.8% |
| Held-out synthetic (1,000 unseen files) | **100%** · ROC-AUC 1.000 | 88.8% |
| Training cross-validation (5-fold F1) | 0.992 ± 0.006 | – |

¹ *"Flag it if it has JavaScript, an automatic trigger, or a launch action."* Reported side by side so it's clear what the model adds.

### Real-world PDFs

The corpus is **281 unique benign PDFs**: every test fixture shipped in the pikepdf, PyMuPDF and pypdf source packages,
plus 2 PDFs from the build machine. They include tax forms full of calculation scripts, Adobe LiveCycle XFA forms,
password-protected files, broken page trees and patent documents.

| Version | Wrongly flagged | Accuracy |
|---|---|---|
| Structure-only model (before JavaScript analysis) | 13 / 281 | 95.4% |
| **Current model** | **6 / 281** | **97.9%** |

The 6 remaining misses are all borderline (51–54%, SUSPICIOUS, never MALICIOUS): five Adobe LiveCycle XFA forms
with Adobe's "download the latest Reader" script, and one heavily scripted government form.

> **Honest caveat:** I used this corpus for error analysis while building the JavaScript features (that's how
> the misses above were found), so it acts as a development set and 97.9% is somewhat optimistic. It also
> contains **no real malware**, so it measures false positives only. See [Limitations](#%EF%B8%8F-limitations).

### Stress tests (cases outside the training distribution)

| Case | True label | What it tests | Result |
|---|---|---|---|
| Obfuscated names | malicious | `/J#61vaScript`-style hex escapes | ✅ 50/50 |
| Object streams | malicious | Actions hidden in compressed object streams | ✅ 50/50 |
| Large malicious | malicious | 40–80 pages, far outside training size range | ✅ 50/50 |
| Click-triggered JS | malicious | Obfuscated JavaScript on a link click, no auto-trigger | ✅ 48/50 |
| Truncated file | malicious | Cut off mid-file; parts of the payload are lost | ✅ 45/50 |
| Remote GoToR² | malicious | Opens `\\host\share` on open (NTLM credential leak) | ✅ 50/50 |
| Password-protected | malicious | Contents unreadable without the password | ⚠️ 41/50 |
| Password-protected | benign | Contents unreadable without the password | ⚠️ 39/50 |
| Truncated benign | benign | Broken files must not *look* malicious | ✅ 50/50 |
| Large benign | benign | 40–80 pages | ✅ 50/50 |
| Calculating form | benign | Legitimate field-level JavaScript (was the known false positive) | ✅ 1/1 |

² Scored **0/50** when first tested. The attack was then added to the training data, so this row is no longer unseen.

Password-protected files are a deliberate trade-off. If a locked file runs code on open, PDFShield flags it for
review, because it can't read that code. Attackers lock PDFs on purpose (the password goes in the email) to get
past scanners.

Full reports: [`report.json`](pdfshield/model/report.json) (training) and
[`evaluation.json`](pdfshield/model/evaluation.json) (held-out, stress and real-world, file by file).

### Bugs the evaluation caught

Each of these was found by measuring, not by guessing. The full story is in [`docs/ENGINEERING_NOTES.md`](docs/ENGINEERING_NOTES.md).

1. **"Small file = malware."** Early malicious samples were blank pages, and the model learned file size.
2. **Encryption and links leaked the label.** pikepdf dropped encryption on re-save, and nested link actions weren't counted.
3. **"Open at page 1" counted as auto-run.** A real LibreOffice PDF scored 61% and now scores 1%.
4. **"Exactly one `/AA` = malware."** Synthetic forms always had exactly 2 scripted fields, so the model counted dictionaries instead of reading code.
5. **Real-world misses showed where the rules were too blunt:** legitimate `launchURL` in Adobe's own scripts, `/Launch` to other PDFs, relative `GoToR` links, and page-tree loops that made the parser give up on whole files.

## 🧪 The training data (and why no live malware)

The training corpus is **synthetic but structurally real**, 600 benign and 600 malicious files:

- **Benign** PDFs (reportlab): 1–12 pages of text, links, forms with 1–6 fields, attachments and encryption.
  A quarter of them carry **realistic JavaScript**: Acrobat form helpers (`AFNumber_Format`,
  `AFSimple_Calculate`), custom calculations and validation, print or zoom on open, document-level helper
  functions, viewer-upgrade prompts, and even legitimate `eval`.
- **Malicious** PDFs start as the same kind of document. Then real malware *techniques* are added:
  `/OpenAction`, page `/AA` or document-level triggers, JavaScript wrapped in the obfuscation layers real
  droppers use (escape encoding + `unescape`, `fromCharCode` chains, reversed strings, hex decoders, string
  timers, packed blobs), `/Launch` of `cmd.exe`/`powershell`, dropped attachments opened with
  `exportDataObject`, and remote `GoToR` credential leaks.

Everything is **inert**. The obfuscated code only sets a variable, opens a URL on the reserved `.invalid`
domain, or asks the viewer to open a placeholder text attachment. There is **no exploit code in this repository**,
and the vulnerable Acrobat APIs are detected but never called. Handling live malware safely needs an isolated
lab, so this project learns from technique and structure instead.

Regenerate the data and retrain in about 20 seconds:

```bash
pdfshield train                          # 600 + 600 samples, seed 42
pdfshield train --benign 2000 --malicious 2000 --seed 7
```

## ⚠️ Limitations

- **No real malware in any test set.** Real-world accuracy measures false positives on benign files. Detection
  rates on real malware are unmeasured until the model is evaluated on a labeled corpus such as
  [Contagio](https://contagiodump.blogspot.com/) or [CIC-Evasive-PDFMal2022](https://www.unb.ca/cic/datasets/pdfmal-2022.html)
  inside a sandbox.
- **Synthetic malware is only as varied as its generator.** The model has seen the obfuscation styles in
  `jsgen.py`. A novel style, or malicious code written to look like plain form code, may score low.
- **Static analysis can't see runtime behavior.** Code assembled at runtime from form-field values or
  annotations can hide from pattern matching.
- **Password-protected files can't be inspected.** If one runs code on open it is flagged for review
  (see above), which also flags some legitimate locked forms.
- **Structure and JavaScript only.** Exploits in fonts, images or other streams that need no scripting
  won't trip these features.

## 🗺️ Roadmap

- [x] Static analysis of JavaScript content (suspicious calls, encoding, entropy, packed strings)
- [x] Evaluation on real-world PDFs, with a simple-rule baseline
- [x] Docker image that scans in a locked-down, network-less container
- [x] Evaluation suite: held-out set, stress tests, rule baseline, real-world files
- [ ] Retrain and benchmark on a public real-malware dataset
- [ ] Stream-level features: filter chains, entropy, suspicious fonts and images
- [ ] De-obfuscate JavaScript statically (unwrap `unescape`/`fromCharCode` layers) before analysis
- [ ] REST API for upload scanning

## 🗂️ Project layout

```
pdfshield/
├── pdfshield/
│   ├── features.py     # structural features, action classification, byte-scan fallback
│   ├── jsanalysis.py   # static JavaScript analysis (never executes anything)
│   ├── jsgen.py        # realistic benign + inert obfuscated JavaScript for training
│   ├── samples.py      # benign / malicious PDF builders
│   ├── train.py        # dataset generation, training, training report
│   ├── evaluate.py     # held-out, stress-test and real-world evaluation
│   ├── model.py        # scoring, inspection policy, explanations
│   ├── cli.py          # `pdfshield` command
│   └── model/          # trained model + report.json + evaluation.json
├── tests/              # pytest suite (29 tests)
├── docs/
│   ├── ENGINEERING_NOTES.md
│   └── demo.svg
└── Dockerfile
```

## 🤝 Development

```bash
pip install -e ".[dev]"
pytest -v
```

If scikit-learn warns that the bundled model came from a different version, run `pdfshield train` to rebuild it locally.

## 📄 License

[MIT](LICENSE) © Purval Singh
