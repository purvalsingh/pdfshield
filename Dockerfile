FROM python:3.12-slim

LABEL org.opencontainers.image.title="PDFShield" \
      org.opencontainers.image.description="Detect malicious PDFs from their structure with a trained ML model" \
      org.opencontainers.image.source="https://github.com/purvalsingh/pdfshield"

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY pdfshield ./pdfshield
RUN pip install --no-cache-dir . \
 && useradd --create-home scanner

# Scanning untrusted files: run unprivileged. Mount PDFs read-only at /scan.
USER scanner
WORKDIR /scan
ENTRYPOINT ["pdfshield"]
CMD ["--help"]
