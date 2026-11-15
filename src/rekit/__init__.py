"""rekit - static-analysis toolkit for malware triage."""

from rekit.models import Finding, Severity, FileResult, ScanResult
from rekit.scanner import scan

__version__ = "0.1.0"
__all__ = ["Finding", "Severity", "FileResult", "ScanResult", "scan", "__version__"]
