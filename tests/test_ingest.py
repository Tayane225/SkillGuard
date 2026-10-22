from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from skillguard.ingest import (
    _name_from_url,
    _safe_extract,
    _single_root,
    _validate_url,
    prepare_target,
)
from skillguard.models import ScanError, ScanOptions


class IngestTests(unittest.TestCase):
    def test_name_from_url(self) -> None:
        self.assertEqual(_name_from_url("https://example.com/acme/skill.git"), "skill")
        self.assertEqual(_name_from_url("https://example.com/skill.zip"), "skill")
        self.assertEqual(_name_from_url("https://example.com/"), "remote-skill")

    def test_validate_url(self) -> None:
        self.assertEqual(_validate_url("https://example.com/x", ScanOptions()), "example.com")
        with self.assertRaises(ScanError):
            _validate_url("https:///nohost", ScanOptions())
        self.assertEqual(
            _validate_url("https://127.0.0.1/x", ScanOptions(allow_private_targets=True)),
            "127.0.0.1",
        )

    def test_empty_target_is_rejected(self) -> None:
        with self.assertRaises(ScanError), prepare_target("   ", ScanOptions()):
            pass

    def test_bad_zip_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "bad.zip"
            archive.write_bytes(b"not a zip")
            with self.assertRaises(ScanError), prepare_target(str(archive), ScanOptions()):
                pass

    def test_archive_member_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "many.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("a.txt", "a")
                bundle.writestr("b.txt", "b")
            with self.assertRaises(ScanError):
                _safe_extract(archive, Path(temp) / "out", ScanOptions(max_members=1))

    def test_archive_expansion_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "large.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("a.txt", "a" * 100)
            with self.assertRaises(ScanError):
                _safe_extract(archive, Path(temp) / "out", ScanOptions(max_total_bytes=50))

    def test_archive_symlink_and_absolute_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            symlink_archive = Path(temp) / "link.zip"
            info = zipfile.ZipInfo("link")
            info.external_attr = (0o120777 << 16)
            with zipfile.ZipFile(symlink_archive, "w") as bundle:
                bundle.writestr(info, "target")
            with self.assertRaises(ScanError):
                _safe_extract(symlink_archive, Path(temp) / "out", ScanOptions())

            absolute_archive = Path(temp) / "absolute.zip"
            with zipfile.ZipFile(absolute_archive, "w") as bundle:
                bundle.writestr("/etc/passwd", "x")
            with self.assertRaises(ScanError):
                _safe_extract(absolute_archive, Path(temp) / "out2", ScanOptions())

    def test_single_root_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "wrapper").mkdir()
            self.assertEqual(_single_root(root), root / "wrapper")
            (root / "other").mkdir()
            self.assertEqual(_single_root(root), root)

    def test_zip_with_wrapper_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "wrapped.zip"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("wrapper/SKILL.md", "---\nname: wrapped\n---\n# Wrapped\n")
            with prepare_target(str(archive), ScanOptions()) as target:
                self.assertEqual(target.root, target.root.parent / "wrapper")
                self.assertTrue((target.root / "SKILL.md").exists())


if __name__ == "__main__":
    unittest.main()
