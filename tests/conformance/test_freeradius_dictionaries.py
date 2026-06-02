"""Load every dictionary in the FreeRADIUS ``share/`` corpus.

The corpus ships 244 dictionary files covering RFC base attributes plus
~230 vendors (Cisco, Aruba, Juniper, 3GPP, Aerohive, etc.). Each one is
a real-world artifact: if pyrad2 can parse it standalone, pyrad2 is
compatible with that vendor's RADIUS deployment.

Files known to depend on features pyrad2 doesn't (yet) implement are
listed in ``_INCOMPATIBLE_STANDALONE`` with a structured reason. They
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
# the corresponding entries from ``_INCOMPATIBLE_STANDALONE`` so the
# tests start protecting the new capability.
_REASONS = {
    "wimax-continuation": (
        "uses WiMAX 'format=1,1,c' continuation marker (RFC 5904 "
        "long-packed VSAs) — pyrad2's VSA format parser only supports "
        "the standard (type_len, len_len) pair"
    ),
    "nested-tlv": (
        "uses 3+ level nested TLV codes (e.g. '241.x.y' for RFC 6929 "
        "extended attributes) — pyrad2's dictionary parser only "
        "supports 2-level codes today"
    ),
    "needs-parent": (
        "redefines VALUE constants for, or references vendors declared "
        "by, attributes defined in another dictionary — only loadable "
        "stacked on a parent (typically the RFC base)"
    ),
    "fr-quirk-typo": (
        "FreeRADIUS dict uses a capitalised data type token like "
        "'String' instead of 'string' — pyrad2 is stricter about case"
    ),
}


_INCOMPATIBLE_STANDALONE: dict[str, str] = {
    "dictionary.aruba": "needs-parent",
    "dictionary.ascend": "needs-parent",
    "dictionary.bay": "needs-parent",
    "dictionary.bintec": "needs-parent",
    "dictionary.chillispot": "needs-parent",
    "dictionary.columbia_university": "needs-parent",
    "dictionary.compat": "needs-parent",
    "dictionary.dhcp": "needs-parent",
    "dictionary.freedhcp": "needs-parent",
    "dictionary.freeradius": "nested-tlv",
    "dictionary.freeradius.evs5": "needs-parent",
    "dictionary.freeradius.internal": "needs-parent",
    "dictionary.hp": "needs-parent",
    "dictionary.iana": "needs-parent",
    "dictionary.juniper": "fr-quirk-typo",
    "dictionary.manzara": "needs-parent",
    "dictionary.openser": "needs-parent",
    "dictionary.rfc2867": "needs-parent",
    "dictionary.rfc3576": "needs-parent",
    "dictionary.rfc3580": "needs-parent",
    "dictionary.rfc4603": "needs-parent",
    "dictionary.rfc5176": "needs-parent",
    "dictionary.rfc5607": "needs-parent",
    "dictionary.rfc7499": "nested-tlv",
    "dictionary.rfc7930": "nested-tlv",
    "dictionary.rfc8045": "nested-tlv",
    "dictionary.rfc8559": "nested-tlv",
    "dictionary.sg": "needs-parent",
    "dictionary.telrad": "nested-tlv",
    "dictionary.usr.illegal": "needs-parent",
    "dictionary.walabi": "needs-parent",
    "dictionary.wimax": "wimax-continuation",
    "dictionary.wimax.alvarion": "wimax-continuation",
    "dictionary.wimax.wichorus": "wimax-continuation",
}

# Floor on how many vendor dictionaries must load. Bump deliberately
# when pyrad2 grows a new capability; never lower without a write-up.
_MIN_LOADABLE_DICTIONARIES = 209


_DICTIONARY_NAME_RE = re.compile(r"^dictionary\.")


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
    reason_key = _INCOMPATIBLE_STANDALONE.get(vendor_dict.name)
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


@pytest.mark.parametrize(
    "vendor_dict", [_pytest_param(p) for p in _vendor_dictionary_files()]
)
def test_vendor_dictionary_loads_standalone(
    freeradius_dictionaries_dir: Path, vendor_dict: Path
) -> None:
    """Each vendor dictionary loads standalone without raising.

    Standalone load is a strict test — vendor dictionaries that depend
    on a parent context are expected to fail and are listed in
    ``_INCOMPATIBLE_STANDALONE``. Anything else is a regression.
    """

    Dictionary(str(vendor_dict))


def test_minimum_loadable_dictionary_count(
    freeradius_dictionaries_dir: Path,
) -> None:
    """Guard against silent regressions in dictionary parser coverage.

    Counts how many vendor dictionaries load standalone. The floor
    catches a class of regression that the per-dict test misses: a
    pyrad2 change that breaks several previously-passing dicts at once
    would show up as many individual failures (loud), but if someone
    "fixes" the test by quietly expanding ``_INCOMPATIBLE_STANDALONE``,
    this count would drop and trip the floor.
    """

    loadable = 0
    for vendor_dict in _vendor_dictionary_files():
        if vendor_dict.name in _INCOMPATIBLE_STANDALONE:
            continue
        try:
            Dictionary(str(vendor_dict))
        except Exception:
            continue
        loadable += 1

    assert loadable >= _MIN_LOADABLE_DICTIONARIES, (
        f"only {loadable} FreeRADIUS dictionaries loaded standalone; "
        f"expected at least {_MIN_LOADABLE_DICTIONARIES}. Either pyrad2 "
        f"regressed or someone expanded _INCOMPATIBLE_STANDALONE "
        f"without bumping the floor — investigate before changing it."
    )
