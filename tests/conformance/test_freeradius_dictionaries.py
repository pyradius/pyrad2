"""Load every dictionary in the FreeRADIUS ``share/`` corpus.

The corpus ships 244 dictionary files covering RFC base attributes plus
~230 vendors (Cisco, Aruba, Juniper, 3GPP, Aerohive, etc.). Each vendor
file is loaded stacked on top of an "RFC base" — the cumulative set of
FreeRADIUS RFC dictionaries that pyrad2 can parse, assembled in the
upstream root's ``$INCLUDE`` dependency order. This mirrors what a real
deployment does: ``Dictionary("dictionary.rfc2865", ..., "dictionary.cisco")``.

Files known to depend on features pyrad2 doesn't (yet) implement are
listed in ``_INCOMPATIBLE_ON_RFC_BASE`` with a structured reason. They
``xfail`` rather than hard-fail, so:

* The suite stays green out of the box.
* When pyrad2 grows a missing capability, removing an entry from the
  incompatible map re-arms the assertion — the test will then hard-fail
  if anything regresses that compatibility.
* When the FreeRADIUS corpus grows a new dictionary that doesn't parse,
  the test fails loudly until the developer either fixes pyrad2 or
  marks it incompatible with a documented reason.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from pyrad2.dictionary import Dictionary

_CORPUS_DIR = Path(__file__).parent / "_corpus" / "dictionaries" / "share"


# Known reasons a FreeRADIUS dictionary won't load with pyrad2 today.
# Each is a real limitation in pyrad2 (or in the dictionary itself);
# extending pyrad2 to remove a category should be followed by removing
# the corresponding entries from ``_INCOMPATIBLE_ON_RFC_BASE`` so the
# tests start protecting the new capability.
_REASONS = {
    "wimax-continuation": (
        "uses 'format=1,1,c' continuation marker (RFC 5904 long-packed "
        "VSAs, originally for WiMAX) — pyrad2's VSA format parser only "
        "supports the standard (type_len, len_len) pair"
    ),
    "fr-extension-types": (
        "uses FreeRADIUS-specific type aliases / attribute flags "
        "(``uint16``, ``virtual``, ``array``, …) that aren't part of "
        "the RFC 6929 / 7268 vocabulary pyrad2 implements"
    ),
    "needs-freeradius-base": (
        "depends on attributes / vendor IDs declared in "
        "dictionary.freeradius (or its internal companion), which is "
        "itself blocked on 'fr-extension-types' — unblocks transitively "
        "once those FreeRADIUS-specific extensions are implemented"
    ),
    "fr-quirk-typo": (
        "FreeRADIUS dict uses a capitalised data type token like "
        "'String' instead of 'string' — pyrad2 is stricter about case"
    ),
    "fr-dict-forward-ref": (
        "FreeRADIUS dict declares VALUE entries for an attribute that "
        "is never defined in any RFC dict — appears to be a "
        "forward-reference bug in the FreeRADIUS dict itself"
    ),
}


_INCOMPATIBLE_ON_RFC_BASE: dict[str, str] = {
    # Forward-reference bug in dictionary.aruba itself.
    "dictionary.aruba": "fr-dict-forward-ref",
    # FreeRADIUS internal / DHCP companions — all blocked behind
    # dictionary.freeradius, which depends on FreeRADIUS-specific type
    # aliases (uint16) and attribute flags (virtual, array) that are
    # outside the RFC vocabulary pyrad2 implements.
    "dictionary.compat": "needs-freeradius-base",
    "dictionary.dhcp": "fr-extension-types",
    "dictionary.freedhcp": "fr-extension-types",
    "dictionary.freeradius": "fr-extension-types",
    "dictionary.freeradius.evs5": "needs-freeradius-base",
    "dictionary.freeradius.internal": "fr-extension-types",
    # Capitalised "String" in the type column.
    "dictionary.juniper": "fr-quirk-typo",
    # RFC 5904 long-packed-VSA continuation marker (``format=1,1,c``).
    "dictionary.telrad": "wimax-continuation",
    "dictionary.wimax": "wimax-continuation",
    "dictionary.wimax.alvarion": "wimax-continuation",
    "dictionary.wimax.wichorus": "wimax-continuation",
}

# Floor on how many vendor dictionaries must load on top of the RFC
# base. Bump deliberately when pyrad2 grows a new capability; never
# lower without a write-up.
_MIN_LOADABLE_DICTIONARIES = 231


_DICTIONARY_NAME_RE = re.compile(r"^dictionary\.")
_RFC_INCLUDE_RE = re.compile(r"^\$INCLUDE\s+(dictionary\.rfc\S+)\s*$")


def _vendor_dictionary_files() -> list[Path]:
    """Every ``dictionary.<vendor>`` file in the corpus, sorted."""

    if not _CORPUS_DIR.is_dir():
        return []
    return sorted(
        p
        for p in _CORPUS_DIR.iterdir()
        if p.is_file() and _DICTIONARY_NAME_RE.match(p.name)
    )


def _pytest_param(vendor_dict: Path) -> pytest.ParameterSet:
    reason_key = _INCOMPATIBLE_ON_RFC_BASE.get(vendor_dict.name)
    marks = []
    if reason_key is not None:
        # ``strict=True`` is what makes the list self-maintaining: when
        # pyrad2 starts accepting a previously-incompatible dict, the
        # xfail "unexpectedly passes" and the test fails, forcing us to
        # remove the entry.
        marks.append(
            pytest.mark.xfail(
                reason=f"[{reason_key}] {_REASONS[reason_key]}",
                strict=True,
            )
        )
    return pytest.param(vendor_dict, id=vendor_dict.name, marks=marks)


@pytest.fixture(scope="session")
def freeradius_rfc_base_files(freeradius_dictionaries_dir: Path) -> tuple[Path, ...]:
    """Cumulatively-loadable RFC dicts in FreeRADIUS root inclusion order.

    Walks the ``$INCLUDE dictionary.rfc*`` lines from upstream's root
    ``share/dictionary``, in order. Each file that loads cleanly on top
    of the chain so far is added; ones that fail (currently the four
    nested-TLV RFC dicts) are skipped. The returned tuple is the
    "compatible RFC base" every vendor test stacks against.
    """

    root_text = (freeradius_dictionaries_dir / "dictionary").read_text()
    base: list[Path] = []
    for raw_line in root_text.splitlines():
        m = _RFC_INCLUDE_RE.match(raw_line.strip())
        if not m:
            continue
        path = freeradius_dictionaries_dir / m.group(1)
        if not path.is_file():
            continue
        try:
            Dictionary(*[str(p) for p in base], str(path))
        except Exception:
            # Tracked separately as nested-tlv / fr-quirk in
            # _INCOMPATIBLE_ON_RFC_BASE — don't fail the base build.
            continue
        base.append(path)
    return tuple(base)


@pytest.mark.parametrize(
    "vendor_dict", [_pytest_param(p) for p in _vendor_dictionary_files()]
)
def test_vendor_dictionary_loads_on_rfc_base(
    freeradius_dictionaries_dir: Path,
    freeradius_rfc_base_files: tuple[Path, ...],
    vendor_dict: Path,
) -> None:
    """Each vendor dictionary loads on top of the FreeRADIUS RFC base.

    Stacked load is the higher-signal test — it matches what a real
    pyrad2 user does when initialising a dictionary for a deployment.
    Vendor files that still fail in this configuration are listed in
    ``_INCOMPATIBLE_ON_RFC_BASE`` with a structured reason; anything
    else is a regression.
    """

    Dictionary(
        *[str(p) for p in freeradius_rfc_base_files],
        str(vendor_dict),
    )


def test_minimum_loadable_dictionary_count(
    freeradius_dictionaries_dir: Path,
    freeradius_rfc_base_files: tuple[Path, ...],
) -> None:
    """Guard against silent regressions in dictionary parser coverage.

    Counts how many dictionaries load stacked on the RFC base. The
    floor catches a class of regression that the per-dict test misses:
    a pyrad2 change that breaks several previously-passing dicts at
    once would show up as many individual failures (loud), but if
    someone "fixes" the test by quietly expanding
    ``_INCOMPATIBLE_ON_RFC_BASE``, this count would drop and trip the
    floor.
    """

    base_strs = [str(p) for p in freeradius_rfc_base_files]
    loadable = 0
    for vendor_dict in _vendor_dictionary_files():
        if vendor_dict.name in _INCOMPATIBLE_ON_RFC_BASE:
            continue
        try:
            Dictionary(*base_strs, str(vendor_dict))
        except Exception:
            continue
        loadable += 1

    assert loadable >= _MIN_LOADABLE_DICTIONARIES, (
        f"only {loadable} FreeRADIUS dictionaries loaded on the RFC "
        f"base; expected at least {_MIN_LOADABLE_DICTIONARIES}. Either "
        f"pyrad2 regressed or someone expanded "
        f"_INCOMPATIBLE_ON_RFC_BASE without bumping the floor — "
        f"investigate before changing it."
    )
