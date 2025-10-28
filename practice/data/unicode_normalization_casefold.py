"""Unicode normalization and casefold — equal-looking strings that are not ``==``

A username check or a "does this file already exist" lookup is commonly
written as ``a.lower() == b.lower()``. Two problems hide behind that line.
First, "é" can be one code point (NFC, what most keyboards produce) or "e" plus
a combining accent (NFD, what macOS file APIs often hand back), and those are
different strings. Second, ``lower()`` is not full case folding: "Straße" and
"STRASSE" should match case-insensitively but ``lower()`` keeps the "ß".

Review note: for identifiers and lookups, normalize first and compare
``casefold()`` results: ``unicodedata.normalize("NFC", s).casefold()``. For
usernames where look-alikes matter, NFKC folds compatibility forms (full-width
letters, ligatures) too; it is still not a defence against every homoglyph,
so pair it with an allow-list of scripts or characters.
"""

import unicodedata


def same_user_noncompliant(a: str, b: str) -> bool:
    return a.lower() == b.lower()


def canonical(s: str, form: str = "NFC") -> str:
    return unicodedata.normalize(form, s).casefold()


def same_user_compliant(a: str, b: str) -> bool:
    return canonical(a) == canonical(b)


def code_points(s: str) -> str:
    return " ".join(f"U+{ord(c):04X}" for c in s)


def main() -> None:
    typed = "José"            # NFC: precomposed é
    from_disk = "José"       # NFD: e + COMBINING ACUTE ACCENT
    print("typed     :", typed, "->", code_points(typed))
    print("from disk :", from_disk, "->", code_points(from_disk))
    print("typed == from_disk:", typed == from_disk, " len:", len(typed), len(from_disk))

    pairs = [
        ("NFC vs NFD José", typed, from_disk),
        ("Straße vs STRASSE", "Straße", "STRASSE"),
        ("ligature fi vs fi", "\ufb01le", "file"),          # U+FB01 LATIN SMALL LIGATURE FI
        ("full-width admin", "\uff41dmin", "admin"),       # U+FF41 FULLWIDTH LATIN SMALL A
    ]
    print()
    print(f"{'pair':<19}{'lower()':<9}{'NFC+casefold':<14}NFKC+casefold")
    for label, a, b in pairs:
        print(f"{label:<19}{same_user_noncompliant(a, b)!s:<9}"
              f"{same_user_compliant(a, b)!s:<14}{canonical(a, 'NFKC') == canonical(b, 'NFKC')}")

    print()
    print("'ß'.lower() =", repr("ß".lower()), " 'ß'.casefold() =", repr("ß".casefold()))
    print("'\u0130'.lower() ->", code_points("\u0130".lower()), "(one character became two)")


if __name__ == "__main__":
    main()

# Output:
# typed     : José -> U+004A U+006F U+0073 U+00E9
# from disk : José -> U+004A U+006F U+0073 U+0065 U+0301
# typed == from_disk: False  len: 4 5
#
# pair               lower()  NFC+casefold  NFKC+casefold
# NFC vs NFD José    False    True          True
# Straße vs STRASSE  False    True          True
# ligature fi vs fi  False    True          True
# full-width admin   False    False         True
#
# 'ß'.lower() = 'ß'  'ß'.casefold() = 'ss'
# 'İ'.lower() -> U+0069 U+0307 (one character became two)
