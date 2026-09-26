# Engineering notes: what the evaluation taught me

PDFShield's accuracy numbers only mean something because of the bugs they exposed along the way.
This is the record of those bugs. Each one follows the same pattern: a number looked fine, I checked *why*
it was fine, and the reason was wrong.

---

## 1. "Small file = malware" (label leak through file size)

**Symptom.** The first model scored 100% accuracy, and `file_size_kb` was its most important feature.

**Why that's wrong.** File size is not a security signal. A perfect score driven by an irrelevant feature
means the model found a shortcut in the data.

**Root cause.** Malicious samples were generated as blank pages (~0.6 KB) with markers injected, while
benign samples contained real text (1.6–10 KB). The model learned the generator, not malware.

**Fix.** Malicious samples start from the same realistic documents as benign ones. Real malicious PDFs are
disguised as invoices and notices, so this is also more faithful to reality.

**Lesson.** Before trusting a score, look at the feature importances and ask whether each one *should* matter.

## 2. Encryption and links leaked the label

**Symptom.** After fix 1, I compared per-class feature distributions. `encrypted` appeared only in
benign files, and `uri_count` was zero everywhere, even though ~35% of files had links.

**Root causes.**
- pikepdf **drops encryption on re-save** by default. Injecting markers re-saved the file, so every
  malicious sample became unencrypted, and "encrypted ⇒ benign" was a free shortcut.
- Link actions are *direct* objects nested inside annotations. The extractor only visited top-level
  indirect objects, so it never saw them. Real malware nests actions exactly like that, so this was a
  detection bug too, not just a data bug.

**Fix.** Re-encrypt on save when the source was encrypted. Walk direct objects recursively (without
following references, so nothing is double-counted).

**Lesson.** Check that every context feature (encryption, links, forms, attachments) appears in *both*
classes. If one doesn't, it's a leak.

## 3. "Open at page 1" counted as auto-run (first real-world false positive)

**Symptom.** Every synthetic test passed at 100%. Then the first real PDF I tried, a LibreOffice document,
was flagged at 61%.

**Root cause.** Its `/OpenAction` was `[page1 /XYZ null null 0]`, a *destination* meaning "open at page 1".
Word and LibreOffice write this constantly. The extractor treated any `/OpenAction` as auto-run code.

**Fix.** Classify actions by what they do: destinations, `/GoTo` and similar are navigation. Add
navigation open actions to the benign training data. Teach the byte-scan fallback the same distinction.
The file now scores 1%.

**Lesson.** Synthetic data can only contain the mistakes you already know about. One real file found
a bug that 2,000 synthetic ones couldn't.

## 4. The model matched a one-line rule

**Finding (not a bug, but the most important result).** On the original data, the Random Forest scored
exactly the same as the rule *"flag it if it has JavaScript, an auto-trigger, or a launch action"* on
every test set. I added that rule as a baseline to `pdfshield evaluate` so the comparison is always
visible.

**Why.** The malicious class was *defined* by those features, so a perfect score was guaranteed and the
model had learned the definition. A 100% score there proved the pipeline worked, not that the model was useful.

**What changed it.** Making the benign class realistic: legitimate forms *do* run JavaScript on events,
and some run it on open. Once benign files contained JavaScript, the rule fell to 88.8% on held-out data
while the model, reading the script *content*, stayed at 100%. Only then did the ML add value.

**Lesson.** Always report a trivial baseline. If the model can't beat it, say so.

## 5. "Exactly one `/AA` = malware" (a leak introduced by the fix)

**Symptom.** After adding JavaScript analysis, the calculating-form test (a legitimate order form) was
flagged again, even though its script was plainly benign.

**Root cause.** Synthetic forms always had exactly two fields, and benign scripts were attached to both,
so benign files had `additional_actions == 2`. Malicious page triggers produced exactly 1. The model had
learned to *count* `/AA` dictionaries instead of reading the code.

**Fix.** Forms get 1–6 fields, a random subset is scripted, and malicious triggers land on 1–3 pages.

**Lesson.** A fix can introduce its own leak. Rerun the full leak checks after every change to the generator.

## 6. Real-world error analysis (281 benign PDFs)

To measure false positives on real files, I collected every test PDF shipped in the pikepdf, PyMuPDF
and pypdf source packages (281 unique files). The structure-only model wrongly flagged **13**. Each miss
had a specific cause:

| Misses | Cause | Fix |
|---|---|---|
| 5 | Adobe LiveCycle XFA forms run Adobe's "download the latest Reader" script, which calls `launchURL` | Network calls became a separate, weaker feature. Viewer-upgrade prompts were added to benign training data |
| 3 | Tax/government forms full of `AFDate_FormatEx`, `AFSimple_Calculate` | JavaScript content analysis: form helpers score low on every obfuscation measure |
| 2 | `/Launch` pointing at *other PDFs* or broken local help paths | Only executables, shells, command-line parameters and remote paths count as risky launches |
| 1 | `/GoToR` to a relative patent-document path | `GoToR`/`GoToE` count only for remote targets (`\\host\share`, URLs), which is the NTLM-leak attack |
| 2 | A looping page tree made the parser reject the whole file | Open without page-attribute inheritance and count pages directly: 4 more files now get full analysis |

Result: **13 → 6** false positives (95.4% → 97.9%). The remaining 6 are borderline (51–54%). I stopped
there on purpose. Tuning until this corpus scores 100% would overfit to it, since I'd already used it
for error analysis. That's also why the README calls it a development set rather than a test set.

## 7. Stress tests that found gaps

- **Remote GoToR: 0/50** on first run. The model had never seen the attack. After adding it to training
  data it scores 50/50, and the README footnotes that the row is no longer "unseen".
- **Password-protected malware: 22%.** The model can't read the script, so it was guessing. This isn't
  an ML problem, it's a policy question. I added one explicit, documented rule: *auto-run code that can't
  be inspected is flagged for review*. That lifted it to 82%, at the cost of flagging some legitimate
  locked forms (benign: 78% correct). Attackers do password-protect PDFs to get past scanners, so this
  is the right trade-off for a security tool.

---

## Honest status

| Claim | Status |
|---|---|
| Detects the malware *techniques* it was trained on | ✅ 100% held-out, 99% on fresh malicious samples |
| Low false-positive rate on real benign PDFs | ✅ 97.9% clean on 281 real files (development set, so somewhat optimistic) |
| Detects real-world malware | ❓ Unmeasured. No live malware was used; that needs a sandboxed evaluation on a labeled corpus |
| Beats a simple rule | ✅ Once the benign class is realistic (100% vs 88.8% held-out, 97.9% vs 96.8% real-world) |

## Talking points in one paragraph

> I built a PDF malware classifier on static features, and most of the work was proving the score was real.
> The first model hit 100% because of a file-size artifact. Later ones leaked through encryption and through
> a fixed form-field count. Each leak showed up as an implausible feature importance or a skewed per-class
> distribution. The model matched a one-line rule until I made the benign class realistic, so I report that
> baseline next to every number. Testing on 281 real PDFs found 13 false positives, each with a concrete
> cause, and fixing them took it to 97.9%. I stopped tuning there so I wouldn't overfit to that corpus. The one
> thing I can't claim is real-malware recall, because that needs a sandboxed evaluation I deliberately didn't
> run here.
