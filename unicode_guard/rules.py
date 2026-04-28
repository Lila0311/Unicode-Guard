"""Rule definitions for Unicode confusion attack detection.

The rule set follows the spirit of Unicode UTS #39 and UTS #55 while staying
small enough to run without external data files in a CI job.
"""

from __future__ import annotations

import unicodedata
from functools import lru_cache
from pathlib import Path


BIDI_CONTROLS = {
    "\u061c": ("ALM", "Arabic letter mark"),
    "\u200e": ("LRM", "left-to-right mark"),
    "\u200f": ("RLM", "right-to-left mark"),
    "\u202a": ("LRE", "left-to-right embedding"),
    "\u202b": ("RLE", "right-to-left embedding"),
    "\u202c": ("PDF", "pop directional formatting"),
    "\u202d": ("LRO", "left-to-right override"),
    "\u202e": ("RLO", "right-to-left override"),
    "\u2066": ("LRI", "left-to-right isolate"),
    "\u2067": ("RLI", "right-to-left isolate"),
    "\u2068": ("FSI", "first strong isolate"),
    "\u2069": ("PDI", "pop directional isolate"),
}

BIDI_OPENERS = {"\u202a", "\u202b", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068"}
BIDI_CLOSERS = {"\u202c", "\u2069"}

INVISIBLE_FORMATS = {
    "\u00ad": "soft hyphen",
    "\u034f": "combining grapheme joiner",
    "\u180e": "mongolian vowel separator",
    "\u200b": "zero width space",
    "\u200c": "zero width non-joiner",
    "\u200d": "zero width joiner",
    "\u2060": "word joiner",
    "\u2061": "function application",
    "\u2062": "invisible times",
    "\u2063": "invisible separator",
    "\u2064": "invisible plus",
    "\ufeff": "zero width no-break space / BOM",
}

VARIATION_SELECTOR_RANGES = ((0xFE00, 0xFE0F), (0xE0100, 0xE01EF))

SUSPICIOUS_WHITESPACE = {
    "\u000b": "vertical tab",
    "\u000c": "form feed",
    "\u0085": "next line",
    "\u00a0": "no-break space",
    "\u1680": "ogham space mark",
    "\u2000": "en quad",
    "\u2001": "em quad",
    "\u2002": "en space",
    "\u2003": "em space",
    "\u2004": "three-per-em space",
    "\u2005": "four-per-em space",
    "\u2006": "six-per-em space",
    "\u2007": "figure space",
    "\u2008": "punctuation space",
    "\u2009": "thin space",
    "\u200a": "hair space",
    "\u2028": "line separator",
    "\u2029": "paragraph separator",
    "\u202f": "narrow no-break space",
    "\u205f": "medium mathematical space",
    "\u3000": "ideographic space",
}

# A compact, source-code-oriented subset of UTS #39 confusables. The map favors
# characters commonly seen in Trojan Source and dependency-name spoofing demos.
CONFUSABLES_TO_ASCII = {
    # Cyrillic letters.
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H",
    "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "а": "a",
    "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ӏ": "l", "Ӏ": "I",
    "Ь": "b", "ԛ": "q", "ѵ": "v", "ԝ": "w",
    # Greek letters.
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I",
    "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
    "Υ": "Y", "Χ": "X", "α": "a", "β": "b", "γ": "y", "ι": "i",
    "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "χ": "x",
    "ϲ": "c", "ϳ": "j", "µ": "u",
    # Fullwidth and mathematical styles.
    "０": "0", "１": "1", "２": "2", "３": "3", "４": "4",
    "５": "5", "６": "6", "７": "7", "８": "8", "９": "9",
    "Ａ": "A", "Ｂ": "B", "Ｃ": "C", "Ｄ": "D", "Ｅ": "E",
    "Ｆ": "F", "Ｇ": "G", "Ｈ": "H", "Ｉ": "I", "Ｊ": "J",
    "Ｋ": "K", "Ｌ": "L", "Ｍ": "M", "Ｎ": "N", "Ｏ": "O",
    "Ｐ": "P", "Ｑ": "Q", "Ｒ": "R", "Ｓ": "S", "Ｔ": "T",
    "Ｕ": "U", "Ｖ": "V", "Ｗ": "W", "Ｘ": "X", "Ｙ": "Y",
    "Ｚ": "Z", "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d",
    "ｅ": "e", "ｆ": "f", "ｇ": "g", "ｈ": "h", "ｉ": "i",
    "ｊ": "j", "ｋ": "k", "ｌ": "l", "ｍ": "m", "ｎ": "n",
    "ｏ": "o", "ｐ": "p", "ｑ": "q", "ｒ": "r", "ｓ": "s",
    "ｔ": "t", "ｕ": "u", "ｖ": "v", "ｗ": "w", "ｘ": "x",
    "ｙ": "y", "ｚ": "z",
    "𝟎": "0", "𝟏": "1", "𝟐": "2", "𝟑": "3", "𝟒": "4",
    "𝟓": "5", "𝟔": "6", "𝟕": "7", "𝟖": "8", "𝟗": "9",
    # Letter-like symbols that often pass casual review.
    "K": "K", "Å": "A", "ℬ": "B", "ℯ": "e", "ℴ": "o", "Ⅲ": "III",
}

SENSITIVE_ASCII_WORDS = {
    "admin", "auth", "authorize", "check", "class", "config", "eval",
    "exec", "false", "hash", "import", "input", "isadmin", "login",
    "null", "open", "os", "pass", "password", "print", "private",
    "process", "return", "secret", "shell", "subprocess", "system",
    "token", "true", "user", "verify",
}

SCRIPT_ALIASES = {
    "LATIN": "Latin",
    "GREEK": "Greek",
    "CYRILLIC": "Cyrillic",
    "ARMENIAN": "Armenian",
    "HEBREW": "Hebrew",
    "ARABIC": "Arabic",
    "DEVANAGARI": "Devanagari",
    "BENGALI": "Bengali",
    "GURMUKHI": "Gurmukhi",
    "GUJARATI": "Gujarati",
    "ORIYA": "Oriya",
    "TAMIL": "Tamil",
    "TELUGU": "Telugu",
    "KANNADA": "Kannada",
    "MALAYALAM": "Malayalam",
    "SINHALA": "Sinhala",
    "THAI": "Thai",
    "LAO": "Lao",
    "TIBETAN": "Tibetan",
    "MYANMAR": "Myanmar",
    "GEORGIAN": "Georgian",
    "HANGUL": "Hangul",
    "HIRAGANA": "Japanese",
    "KATAKANA": "Japanese",
    "CJK": "Han",
    "IDEOGRAPH": "Han",
    "BOPOMOFO": "Han",
}

CJK_COMPATIBLE = {"Han", "Japanese", "Hangul", "Latin"}
HIGH_RISK_SCRIPT_MIXES = [
    {"Latin", "Cyrillic"},
    {"Latin", "Greek"},
    {"Greek", "Cyrillic"},
]


def is_variation_selector(ch: str) -> bool:
    codepoint = ord(ch)
    return any(start <= codepoint <= end for start, end in VARIATION_SELECTOR_RANGES)


def char_label(ch: str) -> str:
    codepoint = f"U+{ord(ch):04X}"
    return f"{codepoint} {unicodedata.name(ch, 'UNNAMED')}"


def script_of(ch: str) -> str:
    if ch == "_" or ch.isdigit():
        return "Common"
    category = unicodedata.category(ch)
    if category.startswith("M"):
        return "Inherited"
    name = unicodedata.name(ch, "")
    for marker, script in SCRIPT_ALIASES.items():
        if marker in name:
            return script
    if ch.isascii() and (ch.isalpha() or ch == "_"):
        return "Latin"
    if category[0] in {"P", "S", "Z", "C", "N"}:
        return "Common"
    return "Unknown"


def meaningful_scripts(text: str) -> set[str]:
    scripts = {script_of(ch) for ch in text}
    return scripts - {"Common", "Inherited"}


def is_high_risk_script_mix(scripts: set[str]) -> bool:
    if len(scripts) < 2:
        return False
    if scripts <= CJK_COMPATIBLE:
        return False
    return any(pair <= scripts for pair in HIGH_RISK_SCRIPT_MIXES) or "Unknown" in scripts


def skeleton(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    official = official_confusables_to_ascii()
    return "".join(official.get(ch, CONFUSABLES_TO_ASCII.get(ch, ch)) for ch in normalized)


@lru_cache(maxsize=1)
def official_confusables_to_ascii() -> dict[str, str]:
    """Load a compact ASCII-facing view of Unicode's official confusables data.

    The full UTS #39 file includes mappings between many scripts. For source
    code review we keep mappings whose target skeleton is plain ASCII, because
    those are most useful for detecting identifiers that impersonate common
    programming names.
    """

    data_path = Path(__file__).with_name("data") / "confusables.txt"
    if not data_path.exists():
        return {}

    mappings: dict[str, str] = {}
    for raw_line in data_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ";" not in line:
            continue
        fields = [field.strip() for field in line.split(";")]
        if len(fields) < 2:
            continue
        source_hex, target_hex = fields[0], fields[1]
        try:
            source = "".join(chr(int(item, 16)) for item in source_hex.split())
            target = "".join(chr(int(item, 16)) for item in target_hex.split())
        except ValueError:
            continue
        if source.isascii():
            continue
        target = unicodedata.normalize("NFKC", target)
        if len(source) == 1 and target.isascii() and any(ch.isalnum() for ch in target):
            mappings[source] = target
    return mappings
