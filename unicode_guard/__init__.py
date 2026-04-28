"""Unicode confusion attack detector for code review and CI."""

from .scanner import Finding, ScanReport, scan_path, scan_text

__all__ = ["Finding", "ScanReport", "scan_path", "scan_text"]
