#!/usr/bin/env python3
"""Local-only password strength assessment CLI.

The checker performs no file I/O and makes no network calls. Passwords are
accepted through a hidden terminal prompt, analyzed in memory, and never
included in the assessment result or printed by this application.
"""

from __future__ import annotations

import sys

# Do not let Python create persistent bytecode caches for this CLI.
sys.dont_write_bytecode = True

import argparse
import getpass
import json
import math
import re
import warnings
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Sequence


# A small, curated in-memory list. It is intentionally not fetched or loaded
# from disk, and is not an exhaustive breached-password corpus.
COMMON_PASSWORDS = frozenset(
    {
        "123456",
        "1234567",
        "12345678",
        "123456789",
        "1234567890",
        "123123",
        "111111",
        "000000",
        "password",
        "password1",
        "password123",
        "passw0rd",
        "qwerty",
        "qwerty123",
        "qwertyuiop",
        "letmein",
        "welcome",
        "admin",
        "admin123",
        "iloveyou",
        "monkey",
        "dragon",
        "football",
        "baseball",
        "sunshine",
        "princess",
        "master",
        "trustno1",
        "login",
        "abc123",
        "whatever",
        "secret",
        "freedom",
        "hello",
        "default",
        "changeme",
        "computer",
        "guest",
        "qazwsx",
        "asdfgh",
    }
)

COMMON_WORDS = frozenset(
    {
        "password",
        "welcome",
        "admin",
        "qwerty",
        "letmein",
        "sunshine",
        "princess",
        "football",
        "baseball",
        "iloveyou",
        "monkey",
        "dragon",
        "master",
        "secret",
        "summer",
        "winter",
        "spring",
        "autumn",
        "flower",
        "family",
        "love",
        "angel",
        "freedom",
        "trustno",
        "hello",
        "computer",
        "welcome",
    }
)

_LEET_TRANSLATION = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
        "!": "i",
    }
)
_SEQUENCES = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)
_CHARACTER_POOL_SIZES = {"lowercase": 26, "uppercase": 26, "digits": 10, "symbols": 33}
_STRONG_ENTROPY_BITS = 60.0


@dataclass(frozen=True)
class PasswordAssessment:
    """Password metrics and feedback; deliberately contains no password value."""

    length: int
    character_pool_size: int
    character_classes: dict[str, bool]
    shannon_entropy_bits_per_character: float
    empirical_shannon_entropy_bits: float
    estimated_search_space_bits: float
    strength: str
    findings: tuple[str, ...]
    recommendations: tuple[str, ...]


def _normalize_for_lookup(password: str) -> str:
    """Normalize case, common leetspeak substitutions, and separators."""
    lowered = password.lower()
    normalized: list[str] = []
    for index, character in enumerate(lowered):
        # A trailing exclamation mark is usually punctuation, not an "i".
        if character == "!" and not (
            index > 0
            and index + 1 < len(lowered)
            and lowered[index - 1].isalnum()
            and lowered[index + 1].isalnum()
        ):
            continue
        translated = character.translate(_LEET_TRANSLATION)
        if translated.isalnum():
            normalized.append(translated)
    return "".join(normalized)


def _contains_sequence(value: str) -> bool:
    """Detect ascending/descending runs and common keyboard-row walks."""
    lowered = value.lower()
    for sequence in _SEQUENCES:
        for start in range(len(sequence) - 2):
            run = sequence[start : start + 3]
            if run in lowered or run[::-1] in lowered:
                return True
    return False


def _has_repeated_pattern(password: str) -> bool:
    if re.search(r"(.)\1{2,}", password, flags=re.DOTALL):
        return True
    return re.search(r"(.{2,4})\1+", password, flags=re.DOTALL) is not None


def _character_classes(password: str) -> dict[str, bool]:
    return {
        "lowercase": any(character.islower() for character in password),
        "uppercase": any(character.isupper() for character in password),
        "digits": any(character.isdigit() for character in password),
        "symbols": any(not character.isalnum() for character in password),
    }


def _pool_size(password: str, classes: dict[str, bool]) -> int:
    pool_size = sum(
        _CHARACTER_POOL_SIZES[name]
        for name, present in classes.items()
        if present
    )
    if any(ord(character) > 127 for character in password):
        pool_size += 100
    return pool_size


def _shannon_entropy(password: str) -> float:
    """Return empirical Shannon entropy in bits per observed character."""
    if not password:
        return 0.0
    counts = Counter(password)
    length = len(password)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def _findings(password: str) -> tuple[str, ...]:
    normalized = _normalize_for_lookup(password)
    plain = "".join(
        character for character in password.lower() if character.isalnum()
    )
    leetspeak_used = any(
        character in "013457@$!"
        and index > 0
        and index + 1 < len(password)
        and password[index - 1].isalpha()
        and password[index + 1].isalpha()
        for index, character in enumerate(password)
    )
    findings: list[str] = []
    if plain in COMMON_PASSWORDS or normalized in COMMON_PASSWORDS:
        findings.append("common_password")
    if leetspeak_used and any(word in normalized for word in COMMON_WORDS):
        findings.append("leetspeak_weak_substitution")
    if any(word in normalized for word in COMMON_WORDS):
        findings.append("common_dictionary_word")
    if _contains_sequence(password) or _contains_sequence(normalized):
        findings.append("predictable_sequence")
    if _has_repeated_pattern(password):
        findings.append("repeated_characters_or_chunks")
    return tuple(findings)


def _recommendations(
    password: str,
    classes: dict[str, bool],
    pool_size: int,
    findings: tuple[str, ...],
    estimated_bits: float,
) -> tuple[str, ...]:
    recommendations: list[str] = []
    target_length = max(
        16,
        math.ceil(_STRONG_ENTROPY_BITS / math.log2(max(pool_size, 2))),
    )
    if len(password) < target_length:
        recommendations.append(
            f"Increase the length from {len(password)} to at least {target_length} "
            f"characters; at the current character pool, this reaches a "
            f"{_STRONG_ENTROPY_BITS:.0f}-bit unadjusted estimate. Replace any "
            "flagged patterns as well."
        )

    missing = [name for name, present in classes.items() if not present]
    if missing:
        names = {
            "lowercase": "lowercase letters",
            "uppercase": "uppercase letters",
            "digits": "digits",
            "symbols": "symbols",
        }
        recommendations.append(
            "Add at least one " + ", ".join(names[name] for name in missing)
            + " to widen the estimated character pool."
        )

    if "common_password" in findings or "common_dictionary_word" in findings:
        recommendations.append(
            "Replace the common word/password entirely; changing its case or "
            "adding a short suffix does not make it unpredictable."
        )
    if "leetspeak_weak_substitution" in findings:
        recommendations.append(
            "Avoid predictable substitutions such as @ for a, 0 for o, or ! "
            "for i; choose unrelated random characters instead."
        )
    if "predictable_sequence" in findings:
        recommendations.append(
            "Replace alphabet, number, or keyboard runs (for example 123 or "
            "qwe) with independently chosen random characters."
        )
    if "repeated_characters_or_chunks" in findings:
        recommendations.append(
            "Replace repeated characters or copied chunks (for example aaa "
            "or abcabc) with different random characters."
        )
    if estimated_bits < _STRONG_ENTROPY_BITS and not recommendations:
        recommendations.append(
            "Use a longer password generated randomly by a password manager; "
            "aim for at least 60 estimated bits."
        )
    return tuple(recommendations)


def analyze_password(password: str) -> PasswordAssessment:
    """Assess a password in memory without persisting or transmitting it.

    ``shannon_entropy_bits_per_character`` is calculated from the observed
    character frequencies. ``estimated_search_space_bits`` is a separate,
    heuristic estimate based on length and the character classes present.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    length = len(password)
    classes = _character_classes(password)
    pool_size = _pool_size(password, classes)
    findings = _findings(password) if password else ()
    entropy_per_character = _shannon_entropy(password)
    empirical_entropy = entropy_per_character * length
    estimated_bits = (
        length * math.log2(pool_size) if length and pool_size else 0.0
    )

    # These conservative caps model how recognizable structure reduces the
    # usefulness of the simple character-pool estimate.
    if "common_password" in findings or "common_dictionary_word" in findings:
        estimated_bits = min(estimated_bits, 10.0)
    if "predictable_sequence" in findings:
        estimated_bits = min(estimated_bits, 20.0)
    if "repeated_characters_or_chunks" in findings:
        estimated_bits = min(estimated_bits, 10.0)
    if "leetspeak_weak_substitution" in findings:
        estimated_bits = min(estimated_bits, 20.0)

    if estimated_bits < 28:
        strength = "Weak"
    elif estimated_bits < _STRONG_ENTROPY_BITS:
        strength = "Moderate"
    else:
        strength = "Strong"

    recommendations = _recommendations(
        password, classes, pool_size, findings, estimated_bits
    )
    return PasswordAssessment(
        length=length,
        character_pool_size=pool_size,
        character_classes=classes,
        shannon_entropy_bits_per_character=entropy_per_character,
        empirical_shannon_entropy_bits=empirical_entropy,
        estimated_search_space_bits=estimated_bits,
        strength=strength,
        findings=findings,
        recommendations=recommendations,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Assess a password locally. The password is requested through a "
            "hidden prompt and is never saved or sent over a network."
        )
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the assessment as JSON (the password is not included)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the interactive CLI and return a process exit status."""
    args = _build_parser().parse_args(argv)
    try:
        # Turn getpass's visible-input fallback into an error rather than ever
        # accepting a password when the terminal cannot disable echo.
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("Password to assess (input is hidden): ")
    except (EOFError, KeyboardInterrupt):
        print("\nInput cancelled.", file=sys.stderr)
        return 130
    except getpass.GetPassWarning:
        print(
            "Secure hidden input is unavailable; use an interactive terminal.",
            file=sys.stderr,
        )
        return 2

    assessment = analyze_password(password)
    if args.json:
        print(json.dumps(asdict(assessment), indent=2))
        return 0

    print(f"\nStrength: {assessment.strength}")
    print(f"Length: {assessment.length} characters")
    print(
        "Character classes: "
        + ", ".join(
            name for name, present in assessment.character_classes.items() if present
        )
    )
    print(
        "Shannon entropy: "
        f"{assessment.shannon_entropy_bits_per_character:.2f} bits/character "
        f"({assessment.empirical_shannon_entropy_bits:.2f} bits for this sample)"
    )
    print(
        "Estimated search-space entropy: "
        f"{assessment.estimated_search_space_bits:.2f} bits (heuristic)"
    )
    print("Findings: " + (", ".join(assessment.findings) or "none detected"))
    if assessment.recommendations:
        print("Recommendations:")
        for recommendation in assessment.recommendations:
            print(f"- {recommendation}")
    else:
        print("Recommendations: none; continue using a unique password.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
