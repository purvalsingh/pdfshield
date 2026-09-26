"""PDFShield: machine-learning detection of malicious PDFs from their structure."""

__version__ = "1.0.0"

from .features import FEATURE_NAMES, PDFFeatures, extract_features  # noqa: E402
from .model import Verdict, scan  # noqa: E402

__all__ = ["FEATURE_NAMES", "PDFFeatures", "Verdict", "extract_features", "scan", "__version__"]
