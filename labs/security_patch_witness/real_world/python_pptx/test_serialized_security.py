"""Regression tests for python-pptx expanded-package reader containment.

Apply directory-containment.patch to python-pptx 1.0.2, then place this test
under its tests/opc directory and run pytest. All files are disposable.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from pptx import Presentation
from pptx.opc.packuri import PackURI
from pptx.opc.serialized import PackageReader


def test_directory_reader_blocks_parent_escape(tmp_path: Path):
    root = tmp_path / "package"
    root.mkdir()
    (tmp_path / "private.txt").write_bytes(b"SYNTHETIC_ONLY")
    reader = PackageReader(str(root))
    member = PackURI("/../private.txt")

    assert member not in reader
    with pytest.raises(KeyError):
        reader[member]


def test_directory_reader_blocks_sibling_prefix_escape(tmp_path: Path):
    root = tmp_path / "package"
    root.mkdir()
    (tmp_path / "package-other.txt").write_bytes(b"SYNTHETIC_ONLY")
    reader = PackageReader(str(root))
    member = PackURI("/../package-other.txt")

    assert member not in reader
    with pytest.raises(KeyError):
        reader[member]


def test_directory_reader_blocks_outside_symlink(tmp_path: Path):
    root = tmp_path / "package"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"SYNTHETIC_ONLY")
    link = root / "link.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Cannot create symlinks in this environment")
    reader = PackageReader(str(root))
    member = PackURI("/link.txt")

    assert member not in reader
    with pytest.raises(KeyError):
        reader[member]


def test_directory_reader_preserves_contained_data(tmp_path: Path):
    root = tmp_path / "package"
    nested = root / "ppt" / "slides"
    nested.mkdir(parents=True)
    (nested / "slide.xml").write_bytes(b"<test />")
    reader = PackageReader(str(root))
    member = PackURI("/ppt/slides/slide.xml")

    assert member in reader
    assert reader[member] == b"<test />"


def test_presentations_still_roundtrip(tmp_path: Path):
    path = tmp_path / "presentation.pptx"
    presentation = Presentation()
    presentation.slides.add_slide(presentation.slide_layouts[6])
    presentation.save(str(path))

    assert len(Presentation(str(path)).slides) == 1


def test_expanded_presentation_cannot_follow_external_part_symlink(tmp_path: Path):
    path = tmp_path / "presentation.pptx"
    presentation = Presentation()
    presentation.slides.add_slide(presentation.slide_layouts[6])
    presentation.save(str(path))
    root = tmp_path / "expanded"
    root.mkdir()
    with zipfile.ZipFile(path) as archive:
        archive.extractall(root)
    assert len(Presentation(str(root)).slides) == 1

    part = root / "ppt" / "presentation.xml"
    outside = tmp_path / "outside-presentation.xml"
    outside.write_bytes(part.read_bytes())
    part.unlink()
    try:
        part.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Cannot create symlinks in this environment")

    with pytest.raises(KeyError):
        Presentation(str(root))
