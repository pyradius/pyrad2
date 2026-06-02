"""Fetch the FreeRADIUS test corpus used by the conformance suite.

Pulls two slices of the upstream FreeRADIUS source tree at pinned SHAs into
``tests/conformance/_corpus/`` (gitignored). The conformance tests skip
themselves if the corpus is missing, so this script is what makes them
actually run — locally or in CI.

Two pins because each FreeRADIUS line has something the other doesn't:

* ``release_3_2_x`` — flat ``share/dictionary.<vendor>`` corpus that real
  deployments still load today. The richest real-world dictionary test set.
* ``master`` (v4) — ``src/tests/unit/protocols/radius/*.txt`` carries
  packet-level hex vectors in ``decode-proto`` / ``match`` form, which maps
  directly onto pyrad2's public Packet API.

Run via ``make conformance-fetch`` or directly:

    uv run python scripts/fetch_freeradius_corpus.py

The corpus directory is fully owned by this script — anything inside
``_corpus/`` may be deleted and re-fetched at any time.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_ROOT = REPO_ROOT / "tests" / "conformance" / "_corpus"
FREERADIUS_REMOTE = "https://github.com/FreeRADIUS/freeradius-server.git"


@dataclass(frozen=True)
class CorpusSlice:
    """A subset of the FreeRADIUS tree to fetch at a pinned ref."""

    name: str
    ref: str
    sparse_paths: tuple[str, ...]
    destination: Path

    @property
    def workdir(self) -> Path:
        return CORPUS_ROOT / f"_clone_{self.name}"


SLICES: tuple[CorpusSlice, ...] = (
    CorpusSlice(
        name="dictionaries",
        # 3.2.5 — the most recent flat-layout release at the time this
        # script was written. Bump deliberately, not on every release.
        ref="release_3_2_5",
        sparse_paths=("share",),
        destination=CORPUS_ROOT / "dictionaries",
    ),
    CorpusSlice(
        name="packet_vectors",
        # v4 master is the only line that ships the rich decode-proto /
        # match packet test vectors. Pinned to a SHA for determinism;
        # refresh by editing this line and re-running the script.
        ref="3f615eb121a1f6604e1b0be05b6a268483b2a6f0",
        sparse_paths=("src/tests/unit/protocols/radius",),
        destination=CORPUS_ROOT / "packet_vectors",
    ),
)


def _run(cmd: list[str], cwd: Path | None = None) -> None:
    print(f"  $ {' '.join(cmd)}")
    subprocess.run(cmd, cwd=cwd, check=True)


def _fetch_slice(slice_: CorpusSlice) -> None:
    print(f"\n[{slice_.name}] fetching @ {slice_.ref}")
    if slice_.workdir.exists():
        shutil.rmtree(slice_.workdir)
    slice_.workdir.parent.mkdir(parents=True, exist_ok=True)

    # ``--filter=blob:none --sparse --no-checkout`` is the cheapest possible
    # clone: no working tree, no blobs, just enough to materialise the
    # subset we then ``sparse-checkout set``.
    _run(
        [
            "git",
            "clone",
            "--filter=blob:none",
            "--sparse",
            "--no-checkout",
            FREERADIUS_REMOTE,
            str(slice_.workdir),
        ]
    )
    _run(["git", "fetch", "--depth", "1", "origin", slice_.ref], cwd=slice_.workdir)
    _run(["git", "checkout", "FETCH_HEAD"], cwd=slice_.workdir)
    _run(["git", "sparse-checkout", "init", "--cone"], cwd=slice_.workdir)
    _run(
        ["git", "sparse-checkout", "set", *slice_.sparse_paths],
        cwd=slice_.workdir,
    )

    if slice_.destination.exists():
        shutil.rmtree(slice_.destination)
    slice_.destination.mkdir(parents=True)

    for sparse in slice_.sparse_paths:
        src = slice_.workdir / sparse
        # Flatten: a slice with sparse path ``share`` lands at
        # ``destination/share``; a slice with sparse path
        # ``src/tests/unit/protocols/radius`` lands at
        # ``destination/radius`` (last segment), keeping the conformance
        # tests' filesystem references short.
        dst = slice_.destination / Path(sparse).name
        shutil.copytree(src, dst)

    # Record the resolved SHA next to the corpus so a debugging human can
    # tell, months later, exactly which FreeRADIUS revision the fixtures
    # came from.
    head_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=slice_.workdir, text=True
    ).strip()
    (slice_.destination / "MANIFEST.txt").write_text(
        f"source: {FREERADIUS_REMOTE}\n"
        f"requested-ref: {slice_.ref}\n"
        f"resolved-sha: {head_sha}\n"
        f"sparse-paths:\n" + "".join(f"  - {p}\n" for p in slice_.sparse_paths)
    )

    shutil.rmtree(slice_.workdir)
    print(f"[{slice_.name}] done -> {slice_.destination.relative_to(REPO_ROOT)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove the entire corpus directory before fetching.",
    )
    args = parser.parse_args()

    if args.clean and CORPUS_ROOT.exists():
        print(f"removing {CORPUS_ROOT.relative_to(REPO_ROOT)}")
        shutil.rmtree(CORPUS_ROOT)

    CORPUS_ROOT.mkdir(parents=True, exist_ok=True)

    for slice_ in SLICES:
        _fetch_slice(slice_)

    print("\nFreeRADIUS corpus ready.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
