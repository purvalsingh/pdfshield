### Benchmark: CIC-Evasive-PDFMal2022

- **Corpus:** 13089 malicious + 9093 benign unique files (30689 duplicates removed, 0 label conflicts dropped)
- **Parser outcomes:** 0 timeouts, 2 crashes (counted as flagged)

**As shipped** (bundled model, trained only on synthetic data, never saw these files):

| Metric | Result |
|---|---|
| Detection rate (recall) | 76.2% (9973/13089, 95% CI 75.5%–76.9%) |
| False-positive rate | 1.3% (120/9093, 95% CI 1.1%–1.6%) |
| Precision | 98.8% |
| ROC-AUC | 0.963 |

Malicious files by verdict: 8460 MALICIOUS · 1511 SUSPICIOUS · 3116 missed

**Retrained on this corpus** (5-fold stratified cross-validation, n=22180):

| Metric | Mean ± std |
|---|---|
| Recall | 96.3% ± 0.5% |
| False-positive rate | 0.2% ± 0.1% |
| Precision | 99.9% ± 0.1% |

Top features: `file_size_kb` (0.21), `javascript_count` (0.17), `open_action` (0.14), `object_count` (0.10), `js_max_string_len` (0.09)
