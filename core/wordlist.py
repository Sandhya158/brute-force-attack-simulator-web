from __future__ import annotations
import itertools
import string
from typing import Generator, Optional


# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — SMART DICTIONARY
# ═══════════════════════════════════════════════════════════════════════════════

# Common generic passwords (generic fallback at end of phase 1)
COMMON_PASSWORDS: list[str] = [
    "123456", "password", "123456789", "12345678", "12345",
    "111111", "1234567", "sunshine", "qwerty", "iloveyou",
    "princess", "admin", "welcome", "666666", "abc123",
    "football", "123123", "monkey", "654321", "shadow",
    "master", "dragon", "pass", "sunshine99", "Admin@1234",
    "letmein", "trustno1", "hello", "charlie", "donald",
    "password1", "qwerty123", "baseball", "superman", "batman",
    "access", "michael", "mustang", "jessica", "pepper",
    "Tr0ub4dor&3",
]

# Number / symbol suffixes attackers append to words
_NUMBER_SUFFIXES: list[str] = [
    "1", "12", "123", "1234", "12345",
    "0", "00", "007", "01", "02", "21",
    "2", "3", "4", "5", "6", "7", "8", "9",
    "10", "11", "13", "99", "100", "111",
    "2024", "2025", "2023", "2022",
    "!", "!!", "123!", "@123", "#1", "786", "@",
]

# Leet-speak substitution table
_LEET: dict[str, str] = {
    "a": "4", "e": "3", "i": "1", "o": "0",
    "s": "5", "t": "7", "g": "9", "b": "8",
}


def _leet(word: str) -> str:
    return "".join(_LEET.get(c.lower(), c) for c in word)


def _variants(word: str) -> list[str]:
    """Return capitalisation variants of a word."""
    v = [
        word,
        word.lower(),
        word.upper(),
        word.capitalize(),
    ]
    if len(word) > 1:
        v.append(word[0].upper() + word[1:].lower())
    return v


def generate(username: str) -> list[str]:
    """
    Build an ordered, deduplicated smart wordlist personalised to `username`.
    Returns a flat list — all Phase 1 entries only (no brute force here).
    """
    seen: set[str] = set()
    result: list[str] = []

    def add(*words: str):
        for w in words:
            if w and w not in seen:
                seen.add(w)
                result.append(w)

    u      = username.strip()
    u_lo   = u.lower()
    u_rev  = u_lo[::-1]
    u_leet = _leet(u_lo)

    # Tier 1 — Exact username
    for v in _variants(u):
        add(v)

    # Tier 2 — Username + suffixes
    for sfx in _NUMBER_SUFFIXES:
        add(u_lo + sfx, u.capitalize() + sfx, u.upper() + sfx)

    # Tier 3 — Reversed username
    for v in _variants(u_rev):
        add(v)

    # Tier 4 — Reversed + suffixes
    for sfx in _NUMBER_SUFFIXES:
        add(u_rev + sfx, u_rev.capitalize() + sfx)

    # Tier 5 — Leet-speak
    for v in _variants(u_leet):
        add(v)

    # Tier 6 — Leet + suffixes
    for sfx in _NUMBER_SUFFIXES:
        add(u_leet + sfx, u_leet.capitalize() + sfx)

    # Tier 7 — Reverse + leet combos
    rev_leet = _leet(u_rev)
    for v in _variants(rev_leet):
        add(v)
    for sfx in _NUMBER_SUFFIXES:
        add(rev_leet + sfx)

    # Tier 8 — Common generic fallback
    for pw in COMMON_PASSWORDS:
        add(pw)

    return result


def preview(username: str, max_lines: int = 30) -> str:
    """Return a preview string for the GUI wordlist textbox (Phase 1 only)."""
    wl = generate(username)
    lines = wl[:max_lines]
    remaining = len(wl) - max_lines
    text = "\n".join(lines)
    if remaining > 0:
        text += f"\n# ... +{remaining} more smart mutations"
    return text


# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — BRUTE FORCE (PERMUTATION / COMBINATION ENGINE)
# ═══════════════════════════════════════════════════════════════════════════════

# Character sets available for brute force
CHARSET_LOWER   = string.ascii_lowercase                        # a-z  (26)
CHARSET_UPPER   = string.ascii_uppercase                        # A-Z  (26)
CHARSET_DIGITS  = string.digits                                 # 0-9  (10)
CHARSET_SYMBOLS = "!@#$_-.@"                                   # common symbols (8)
CHARSET_FULL    = CHARSET_LOWER + CHARSET_UPPER + CHARSET_DIGITS + CHARSET_SYMBOLS  # 70

# Maximum password length to brute force (length 5 = ~1.5 billion — capped for demo)
MAX_BF_LENGTH = 4


def brute_force_generator(
    max_length: int = MAX_BF_LENGTH,
    charset: str = CHARSET_FULL,
    min_length: int = 1,
    skip_set: Optional[set] = None,
) -> Generator[str, None, None]:
    """
    Yield every possible combination of `charset` characters for
    lengths min_length → max_length (inclusive), in ascending length order.

    This is a true generator — it never builds the full list in memory.
    For length=4, full charset: ~24 million combinations yielded one at a time.

    Args:
        max_length  : Maximum password length to try (default 4).
        charset     : Characters to use in combinations.
        min_length  : Start from this length (default 1).
        skip_set    : Set of passwords already tried (Phase 1 results) — skipped.

    Educational Note:
        itertools.product(charset, repeat=n) is equivalent to n nested for-loops,
        generating the Cartesian product — all n-length strings over the charset.
        This is exactly what Hashcat's ?a mask attack does.
    """
    if skip_set is None:
        skip_set = set()

    for length in range(min_length, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = "".join(combo)
            if candidate not in skip_set:
                yield candidate


def brute_force_count(
    max_length: int = MAX_BF_LENGTH,
    charset: str = CHARSET_FULL,
    min_length: int = 1,
) -> int:
    """Return the total number of brute force candidates (for progress bar)."""
    n = len(charset)
    return sum(n ** l for l in range(min_length, max_length + 1))


def charset_for_mode(mode: str) -> str:
    """
    Map a user-facing mode name to a charset string.

    Modes:
      'digits'       — 0–9 only              (10 chars)
      'lower'        — a–z only              (26 chars)
      'lower+digits' — a–z + 0–9            (36 chars)
      'full'         — all + symbols         (70 chars)
    """
    return {
        "digits":       CHARSET_DIGITS,
        "lower":        CHARSET_LOWER,
        "lower+digits": CHARSET_LOWER + CHARSET_DIGITS,
        "full":         CHARSET_FULL,
    }.get(mode, CHARSET_FULL)
