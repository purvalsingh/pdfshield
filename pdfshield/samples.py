"""Builders for the synthetic training corpus.

Benign documents are generated with reportlab and vary in length, layout,
links, forms, attachments and encryption.

"Malicious" documents start as the same kind of benign-looking document and
then get the structural markers seen in real PDF malware injected with
pikepdf: auto-run JavaScript, event-triggered actions, launch actions and
dropped attachments. The injected JavaScript is an inert placeholder and the
launch targets do not exist -- there is no exploit code anywhere in this
project. The model learns *structure*, which is what the markers share with
real malware.
"""

from __future__ import annotations

import io
import random

import pikepdf
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.pdfencrypt import StandardEncryption
from reportlab.pdfgen import canvas

INERT_JS = "/* pdfshield synthetic sample - inert */ var pdfshield_marker = 1;"

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
                c.acroForm.textfield(name="name", x=320, y=60, width=200, height=18)
                c.acroForm.checkbox(name="agree", x=320, y=85, size=14)
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


def _js_action(pdf: pikepdf.Pdf) -> pikepdf.Dictionary:
    return pdf.make_indirect(pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS=pikepdf.String(INERT_JS)))


def _attach(pdf: pikepdf.Pdf, name: str, data: bytes) -> None:
    pdf.attachments[name] = pikepdf.AttachedFileSpec(pdf, data, filename=name)


def add_attachment(pdf_bytes: bytes, name: str, data: bytes) -> bytes:
    with pikepdf.open(io.BytesIO(pdf_bytes)) as pdf:
        _attach(pdf, name, data)
        return _save(pdf)


def inject_markers(pdf_bytes: bytes, rng: random.Random) -> bytes:
    """Inject a random combination of malicious structural markers.

    Every sample gets at least one automatic trigger (OpenAction or /AA),
    because an attack that needs no user click is what defines the class.
    """
    with pikepdf.open(io.BytesIO(pdf_bytes)) as pdf:
        trigger = rng.choice(["open_action", "page_aa", "both"])
        payload = rng.choices(["js", "launch", "embedded", "js+embedded"], weights=[5, 2, 2, 2])[0]

        if "embedded" in payload:
            dropped = rng.choice(["invoice.exe", "update.scr", "doc.vbs", "readme.js", "setup.bat"])
            _attach(pdf, dropped, b"PDFSHIELD-INERT-PLACEHOLDER " * rng.randint(4, 200))

        def make_action() -> pikepdf.Dictionary:
            if payload == "launch":
                return pdf.make_indirect(pikepdf.Dictionary(
                    S=pikepdf.Name.Launch,
                    F=pikepdf.String(rng.choice(["cmd.exe", "powershell.exe", "/bin/sh"])),
                    NewWindow=False,
                ))
            return _js_action(pdf)

        if trigger in ("open_action", "both"):
            pdf.Root.OpenAction = make_action()
        if trigger in ("page_aa", "both"):
            page = pdf.pages[0].obj
            page.AA = pikepdf.Dictionary(O=make_action())

        # Some real samples pad themselves with extra JS objects.
        if payload.startswith("js") and rng.random() < 0.3:
            names = pikepdf.Array()
            for i in range(rng.randint(1, 3)):
                names.append(pikepdf.String(f"s{i}"))
                names.append(_js_action(pdf))
            pdf.Root.Names = pdf.Root.get("/Names", pikepdf.Dictionary())
            pdf.Root.Names.JavaScript = pikepdf.Dictionary(Names=names)

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


def build_benign(rng: random.Random) -> bytes:
    data = build_document(rng)
    if rng.random() < 0.3:
        data = add_navigation_open_action(data, rng)
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
        for field in pdf.Root.AcroForm.Fields:
            if str(field.get("/T")) == "name":
                field.AA = pikepdf.Dictionary(C=pdf.make_indirect(pikepdf.Dictionary(
                    S=pikepdf.Name.JavaScript,
                    JS=pikepdf.String('event.value = this.getField("qty").value * 9.99;'),
                )))
        return _save(pdf)
