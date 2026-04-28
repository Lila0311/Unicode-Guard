"""Core scanning engine for Unicode confusion attacks."""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from . import rules


IDENTIFIER_RE = re.compile(r"[^\W\d]\w*", re.UNICODE)
DEFAULT_INCLUDE_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cs", ".css", ".go", ".h", ".hpp", ".html",
    ".java", ".js", ".jsx", ".json", ".kt", ".m", ".md", ".php", ".py",
    ".rb", ".rs", ".scala", ".sh", ".sql", ".swift", ".ts", ".tsx",
    ".txt", ".xml", ".yaml", ".yml",
}
DEFAULT_EXCLUDES = {
    ".git", ".hg", ".svn", "__pycache__", "node_modules", "dist", "build",
    ".venv", "venv", ".mypy_cache", ".pytest_cache", "confusables.txt",
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    line: int
    column: int
    character: str = ""
    codepoint: str = ""
    snippet: str = ""
    suggestion: str = ""


@dataclass
class ScanReport:
    path: str
    findings: list[Finding] = field(default_factory=list)
    encoding: str = "utf-8"
    clean_text: str | None = None

    @property
    def passed(self) -> bool:
        return not any(item.severity in {"HIGH", "CRITICAL"} for item in self.findings)

    @property
    def summary(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "encoding": self.encoding,
            "passed": self.passed,
            "summary": self.summary,
            "findings": [asdict(item) for item in self.findings],
        }


def decode_bytes(data: bytes) -> tuple[str, str, list[Finding]]:
    try:
        return data.decode("utf-8-sig"), "utf-8-sig", []
    except UnicodeDecodeError as exc:
        text = data.decode("utf-8", errors="replace")
        finding = Finding(
            rule_id="ENCODING_INVALID_UTF8",
            severity="HIGH",
            message=f"File is not valid UTF-8 at byte {exc.start}. Replacement decoding was used.",
            line=1,
            column=1,
            suggestion="Store source files as valid UTF-8 so reviewers and compilers see the same text.",
        )
        return text, "utf-8-replace", [finding]


def scan_text(text: str, path: str = "<memory>") -> ScanReport:
    report = ScanReport(path=path, clean_text=build_clean_text(text))
    line_starts = _line_starts(text)
    findings: list[Finding] = []
    findings.extend(_scan_characters(text, line_starts))
    findings.extend(_scan_bidi_balance(text, line_starts))
    findings.extend(_scan_normalization(text, line_starts))
    findings.extend(_scan_identifiers(text, line_starts))
    report.findings = sorted(findings, key=lambda item: (item.line, item.column, item.rule_id))
    return report


def scan_path(path: str | Path) -> ScanReport:
    path = Path(path)
    text, encoding, decode_findings = decode_bytes(path.read_bytes())
    report = scan_text(text, str(path))
    report.encoding = encoding
    report.findings = sorted(decode_findings + report.findings, key=lambda item: (item.line, item.column, item.rule_id))
    return report


def iter_source_files(paths: Iterable[str | Path], include_exts: set[str] | None = None) -> Iterable[Path]:
    include_exts = include_exts or DEFAULT_INCLUDE_EXTENSIONS
    for raw in paths:
        path = Path(raw)
        if path.is_file():
            if not include_exts or path.suffix.lower() in include_exts:
                yield path
            continue
        if path.is_dir():
            for item in path.rglob("*"):
                if item.is_dir() or item.name in DEFAULT_EXCLUDES or any(part in DEFAULT_EXCLUDES for part in item.parts):
                    continue
                if include_exts and item.suffix.lower() not in include_exts:
                    continue
                yield item


def build_clean_text(text: str) -> str:
    cleaned = []
    for ch in text:
        if ch in rules.BIDI_CONTROLS or ch in rules.INVISIBLE_FORMATS or rules.is_variation_selector(ch):
            continue
        if ch in rules.SUSPICIOUS_WHITESPACE:
            cleaned.append(" " if ch not in {"\u2028", "\u2029"} else "\n")
            continue
        cleaned.append(ch)
    return unicodedata.normalize("NFC", "".join(cleaned))


def _scan_characters(text: str, line_starts: list[int]) -> list[Finding]:
    findings: list[Finding] = []
    for index, ch in enumerate(text):
        line, col = _line_col(index, line_starts)
        codepoint = rules.char_label(ch)
        snippet = _snippet(text, index)
        if ch in rules.BIDI_CONTROLS:
            abbr, desc = rules.BIDI_CONTROLS[ch]
            severity = "CRITICAL" if ch in {"\u202d", "\u202e", "\u202a", "\u202b"} else "HIGH"
            findings.append(Finding(
                rule_id="BIDI_CONTROL",
                severity=severity,
                message=f"Bidirectional control {abbr} ({desc}) can reorder source display.",
                line=line,
                column=col,
                character=ch,
                codepoint=codepoint,
                snippet=snippet,
                suggestion="Remove the control character or isolate it in a reviewed string/comment with visible markers.",
            ))
        elif ch in rules.INVISIBLE_FORMATS:
            findings.append(Finding(
                rule_id="INVISIBLE_FORMAT",
                severity="HIGH",
                message=f"Invisible format character detected: {rules.INVISIBLE_FORMATS[ch]}.",
                line=line,
                column=col,
                character=ch,
                codepoint=codepoint,
                snippet=snippet,
                suggestion="Remove it unless the language and script explicitly require it.",
            ))
        elif rules.is_variation_selector(ch):
            findings.append(Finding(
                rule_id="VARIATION_SELECTOR",
                severity="MEDIUM",
                message="Variation selector can alter glyph appearance without changing nearby visible text.",
                line=line,
                column=col,
                character=ch,
                codepoint=codepoint,
                snippet=snippet,
                suggestion="Avoid variation selectors in source identifiers and operators.",
            ))
        elif ch in rules.SUSPICIOUS_WHITESPACE:
            findings.append(Finding(
                rule_id="SUSPICIOUS_WHITESPACE",
                severity="MEDIUM",
                message=f"Non-standard whitespace detected: {rules.SUSPICIOUS_WHITESPACE[ch]}.",
                line=line,
                column=col,
                character=ch,
                codepoint=codepoint,
                snippet=snippet,
                suggestion="Replace with ASCII space, tab, LF, or CRLF.",
            ))
    return findings


def _scan_bidi_balance(text: str, line_starts: list[int]) -> list[Finding]:
    findings: list[Finding] = []
    stack: list[tuple[str, int]] = []
    for index, ch in enumerate(text):
        if ch in rules.BIDI_OPENERS:
            stack.append((ch, index))
        elif ch == "\u202c":
            while stack and stack[-1][0] in {"\u2066", "\u2067", "\u2068"}:
                break
            if stack and stack[-1][0] in {"\u202a", "\u202b", "\u202d", "\u202e"}:
                stack.pop()
            else:
                findings.append(_bidi_balance_finding(text, line_starts, index, "BIDI_UNPAIRED_PDF", "PDF has no matching embedding/override opener."))
        elif ch == "\u2069":
            if stack and stack[-1][0] in {"\u2066", "\u2067", "\u2068"}:
                stack.pop()
            else:
                findings.append(_bidi_balance_finding(text, line_starts, index, "BIDI_UNPAIRED_PDI", "PDI has no matching isolate opener."))
    for _, index in stack:
        findings.append(_bidi_balance_finding(text, line_starts, index, "BIDI_UNCLOSED", "Bidirectional control sequence is not closed."))
    return findings


def _bidi_balance_finding(text: str, line_starts: list[int], index: int, rule_id: str, message: str) -> Finding:
    line, col = _line_col(index, line_starts)
    return Finding(
        rule_id=rule_id,
        severity="HIGH",
        message=message,
        line=line,
        column=col,
        character=text[index],
        codepoint=rules.char_label(text[index]),
        snippet=_snippet(text, index),
        suggestion="Remove the bidi controls or use a tool that inserts balanced directional isolates.",
    )


def _scan_normalization(text: str, line_starts: list[int]) -> list[Finding]:
    findings: list[Finding] = []
    code_mask = _code_position_mask(text)
    for match in IDENTIFIER_RE.finditer(text):
        if not code_mask[match.start()]:
            continue
        value = match.group(0)
        nfc = unicodedata.normalize("NFC", value)
        nfkc = unicodedata.normalize("NFKC", value)
        if value != nfc:
            line, col = _line_col(match.start(), line_starts)
            findings.append(Finding(
                rule_id="IDENTIFIER_NOT_NFC",
                severity="MEDIUM",
                message=f"Identifier {value!r} is not NFC-normalized.",
                line=line,
                column=col,
                snippet=_snippet(text, match.start()),
                suggestion=f"Use NFC form {nfc!r}.",
            ))
        if value != nfkc and any(not ch.isascii() for ch in value):
            line, col = _line_col(match.start(), line_starts)
            findings.append(Finding(
                rule_id="IDENTIFIER_NFKC_CHANGES",
                severity="MEDIUM",
                message=f"Identifier {value!r} changes under NFKC normalization to {nfkc!r}.",
                line=line,
                column=col,
                snippet=_snippet(text, match.start()),
                suggestion="Avoid compatibility characters in identifiers.",
            ))
    return findings


def _scan_identifiers(text: str, line_starts: list[int]) -> list[Finding]:
    findings: list[Finding] = []
    seen_by_skeleton: dict[str, tuple[str, int]] = {}
    code_mask = _code_position_mask(text)
    for match in IDENTIFIER_RE.finditer(text):
        if not code_mask[match.start()]:
            continue
        value = match.group(0)
        if value.isascii():
            seen_by_skeleton.setdefault(value.casefold(), (value, match.start()))
            continue
        scripts = rules.meaningful_scripts(value)
        line, col = _line_col(match.start(), line_starts)
        if rules.is_high_risk_script_mix(scripts):
            findings.append(Finding(
                rule_id="IDENTIFIER_MIXED_SCRIPT",
                severity="HIGH",
                message=f"Identifier {value!r} mixes scripts: {', '.join(sorted(scripts))}.",
                line=line,
                column=col,
                snippet=_snippet(text, match.start()),
                suggestion="Use one script per identifier, or split words with ASCII separators and document the exception.",
            ))
        skel = rules.skeleton(value).casefold()
        if skel != value.casefold() and _looks_ascii_identifier(skel):
            severity = "HIGH" if skel in rules.SENSITIVE_ASCII_WORDS else "MEDIUM"
            findings.append(Finding(
                rule_id="IDENTIFIER_CONFUSABLE_ASCII",
                severity=severity,
                message=f"Identifier {value!r} is visually confusable with ASCII skeleton {skel!r}.",
                line=line,
                column=col,
                snippet=_snippet(text, match.start()),
                suggestion=f"Prefer the ASCII spelling {skel!r} or rename it to an unambiguous identifier.",
            ))
        if skel in seen_by_skeleton and seen_by_skeleton[skel][0] != value:
            original, original_index = seen_by_skeleton[skel]
            original_line, _ = _line_col(original_index, line_starts)
            findings.append(Finding(
                rule_id="IDENTIFIER_COLLISION",
                severity="CRITICAL",
                message=f"Identifier {value!r} has the same visual skeleton as {original!r} first seen on line {original_line}.",
                line=line,
                column=col,
                snippet=_snippet(text, match.start()),
                suggestion="Rename one identifier so their visual forms are clearly different.",
            ))
        else:
            seen_by_skeleton.setdefault(skel, (value, match.start()))
    return findings


def _looks_ascii_identifier(value: str) -> bool:
    return bool(value) and value.replace("_", "a").isalnum() and any(ch.isalpha() for ch in value) and value.isascii()


def _code_position_mask(text: str) -> list[bool]:
    """Best-effort language-agnostic mask for code outside strings/comments.

    Character-level Unicode controls are still scanned everywhere. This mask is
    only used for identifier-level rules so embedded test fixtures and rule
    tables do not look like executable identifiers.
    """

    mask = [True] * len(text)
    i = 0
    state = "code"
    quote = ""
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if state == "code":
            if ch == "#":
                i = _mask_until_newline(mask, text, i)
                continue
            if ch == "/" and nxt == "/":
                i = _mask_until_newline(mask, text, i)
                continue
            if ch == "/" and nxt == "*":
                mask[i] = mask[i + 1] = False
                i += 2
                state = "block_comment"
                continue
            if text.startswith('"""', i) or text.startswith("'''", i):
                quote = text[i:i + 3]
                for pos in range(i, i + 3):
                    mask[pos] = False
                i += 3
                state = "triple_string"
                continue
            if ch in {"'", '"', "`"}:
                quote = ch
                mask[i] = False
                i += 1
                state = "string"
                continue
            i += 1
            continue

        if state == "string":
            mask[i] = False
            if ch == "\\":
                if i + 1 < len(text):
                    mask[i + 1] = False
                i += 2
                continue
            if ch == quote:
                state = "code"
            i += 1
            continue

        if state == "triple_string":
            mask[i] = False
            if text.startswith(quote, i):
                for pos in range(i, min(i + 3, len(text))):
                    mask[pos] = False
                i += 3
                state = "code"
                continue
            i += 1
            continue

        if state == "block_comment":
            mask[i] = False
            if ch == "*" and nxt == "/":
                mask[i + 1] = False
                i += 2
                state = "code"
                continue
            i += 1
            continue

    return mask


def _mask_until_newline(mask: list[bool], text: str, start: int) -> int:
    index = start
    while index < len(text) and text[index] != "\n":
        mask[index] = False
        index += 1
    return index


def _line_starts(text: str) -> list[int]:
    starts = [0]
    for match in re.finditer("\n", text):
        starts.append(match.end())
    return starts


def _line_col(index: int, starts: list[int]) -> tuple[int, int]:
    low, high = 0, len(starts) - 1
    while low <= high:
        mid = (low + high) // 2
        if starts[mid] <= index:
            low = mid + 1
        else:
            high = mid - 1
    line_index = max(0, high)
    return line_index + 1, index - starts[line_index] + 1


def _snippet(text: str, index: int, radius: int = 36) -> str:
    start = max(0, index - radius)
    end = min(len(text), index + radius)
    return text[start:end].replace("\n", "\\n").replace("\r", "\\r")


def format_text_report(reports: list[ScanReport]) -> str:
    lines: list[str] = []
    for report in reports:
        lines.append(f"{report.path}: {'PASS' if report.passed else 'FAIL'} {report.summary}")
        for finding in report.findings:
            lines.append(
                f"  {finding.severity:8} {finding.rule_id:28} "
                f"L{finding.line}:C{finding.column} {finding.message}"
            )
            if finding.codepoint:
                lines.append(f"           {finding.codepoint}")
            if finding.suggestion:
                lines.append(f"           fix: {finding.suggestion}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect Unicode confusion attacks in source code.")
    parser.add_argument("paths", nargs="+", help="Files or directories to scan.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="HIGH")
    parser.add_argument("--write-clean", metavar="DIR", help="Write cleaned copies to a directory for review.")
    args = parser.parse_args(argv)

    severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    paths = list(iter_source_files(args.paths))
    reports = [scan_path(path) for path in paths]

    if args.write_clean:
        out_dir = Path(args.write_clean)
        out_dir.mkdir(parents=True, exist_ok=True)
        for report in reports:
            target = out_dir / Path(report.path).name
            target.write_text(report.clean_text or "", encoding="utf-8")

    if args.json:
        print(json.dumps([report.to_dict() for report in reports], ensure_ascii=False, indent=2))
    else:
        print(format_text_report(reports) if reports else "No matching source files found.")

    failed = any(
        severity_order[finding.severity] >= severity_order[args.fail_on]
        for report in reports
        for finding in report.findings
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
