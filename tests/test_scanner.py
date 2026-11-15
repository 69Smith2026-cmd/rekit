from __future__ import annotations

from pathlib import Path

from rekit.scanner import scan


def test_scan_single_file(tmp_path: Path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"A" * 100 + b"http://test.local")
    result = scan([f])
    assert len(result.files) == 1
    assert result.files[0].findings


def test_scan_directory(tmp_path: Path):
    (tmp_path / "a.bin").write_bytes(b"hello")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.bin").write_bytes(b"world")
    assert len(scan([tmp_path]).files) == 2


def test_dedupe_overlapping_targets(tmp_path: Path):
    (tmp_path / "a.bin").write_bytes(b"hello")
    assert len(scan([tmp_path, tmp_path / "a.bin"]).files) == 1


def test_oversized_still_hashes(tmp_path: Path):
    f = tmp_path / "big.bin"
    f.write_bytes(b"B" * 5000)
    result = scan([f], max_size=1000)
    assert result.files[0].findings
    assert "skipped" in (result.files[0].error or "").lower()
