from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from .models import ScanError, ScanOptions
from .utils import is_private_host


@dataclass
class Target:
    input: str
    type: str
    root: Path
    name: str
    revision: str | None = None
    warnings: list[str] = field(default_factory=list)


def _name_from_url(url: str) -> str:
    path = urllib.parse.urlsplit(url).path.rstrip("/")
    name = Path(path).name
    name = name.removesuffix(".git")
    name = name.removesuffix(".zip")
    return name or "remote-skill"


def _validate_url(url: str, options: ScanOptions) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() != "https":
        raise ScanError("Only HTTPS URLs are supported.")
    if not parsed.hostname:
        raise ScanError("URL has no host.")
    if is_private_host(parsed.hostname) and not options.allow_private_targets:
        raise ScanError("Refusing to access a private, loopback, or link-local host.")
    return parsed.hostname


def _download(url: str, destination: Path, options: ScanOptions) -> None:
    _validate_url(url, options)
    request = urllib.request.Request(url, headers={"User-Agent": "skillguard/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=options.timeout) as response:
            final_url = response.geturl()
            final_host = urllib.parse.urlsplit(final_url).hostname
            if is_private_host(final_host) and not options.allow_private_targets:
                raise ScanError("URL redirected to a private or loopback host.")
            total = 0
            with destination.open("wb") as handle:
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > options.max_download_bytes:
                        raise ScanError("Download exceeded the configured size limit.")
                    handle.write(chunk)
    except ScanError:
        raise
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ScanError(f"Could not download target: {exc}") from exc


def _zip_is_symlink(info: zipfile.ZipInfo) -> bool:
    return (info.external_attr >> 16) & 0o170000 == 0o120000


def _safe_extract(archive: Path, destination: Path, options: ScanOptions) -> None:
    try:
        with zipfile.ZipFile(archive) as bundle:
            infos = bundle.infolist()
            if len(infos) > options.max_members:
                raise ScanError("Archive contains too many entries.")
            total = 0
            for info in infos:
                if info.flag_bits & 0x1:
                    raise ScanError("Encrypted archives are not supported.")
                if _zip_is_symlink(info):
                    raise ScanError("Archives containing symbolic links are not supported.")
                total += info.file_size
                if total > options.max_total_bytes:
                    raise ScanError("Archive expands beyond the configured size limit.")
                name = info.filename.replace("\\", "/")
                if name.startswith("/") or ".." in name.split("/") or ":" in name.split("/")[0]:
                    raise ScanError("Archive contains an unsafe path.")
                target = (destination / name).resolve()
                if destination.resolve() not in target.parents and target != destination.resolve():
                    raise ScanError("Archive contains a path outside the extraction directory.")
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(info) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output, length=65536)
    except zipfile.BadZipFile as exc:
        raise ScanError("Target is not a valid ZIP archive.") from exc


def _single_root(path: Path) -> Path:
    entries = [entry for entry in path.iterdir() if entry.name != "__MACOSX"]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return path


def _git_clone(url: str, destination: Path, options: ScanOptions, warnings: list[str]) -> str | None:
    _validate_url(url, options)
    env = os.environ.copy()
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_ASKPASS": "",
        }
    )
    command = [
        "git",
        "-c", "core.symlinks=false",
        "clone",
        "--depth", "1",
        "--single-branch",
        "--no-tags",
        url,
        str(destination),
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=options.timeout,
            env=env,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScanError(f"Git clone failed: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()[:400]
        raise ScanError(f"Git clone failed: {detail}")
    revision = None
    try:
        revision_result = subprocess.run(
            ["git", "-C", str(destination), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
            check=False,
        )
        if revision_result.returncode == 0:
            revision = revision_result.stdout.strip() or None
    except (OSError, subprocess.TimeoutExpired) as exc:
        warnings.append(f"Could not determine Git revision: {exc}")
    return revision


@contextmanager
def prepare_target(target: str, options: ScanOptions) -> Iterator[Target]:
    raw = target.strip()
    if not raw:
        raise ScanError("Target is empty.")
    lowered = raw.lower()

    if lowered.startswith(("http://", "https://")):
        _validate_url(raw, options)
        with tempfile.TemporaryDirectory(prefix="skillguard-") as temp:
            work = Path(temp)
            parsed = urllib.parse.urlsplit(raw)
            path_lower = parsed.path.lower()
            is_git = path_lower.endswith(".git") or (
                parsed.hostname in {"github.com", "gitlab.com", "bitbucket.org"}
                and not path_lower.endswith((".zip", ".md", ".markdown"))
            )
            if is_git:
                root = work / "repo"
                revision = _git_clone(raw, root, options, [])
                yield Target(
                    input=raw,
                    type="git",
                    root=root,
                    name=_name_from_url(raw),
                    revision=revision,
                )
                return
            if path_lower.endswith((".md", ".markdown")):
                destination = work / "SKILL.md"
                _download(raw, destination, options)
                yield Target(input=raw, type="url", root=work, name=_name_from_url(raw))
                return
            archive = work / "download.zip"
            _download(raw, archive, options)
            extracted = work / "extracted"
            extracted.mkdir()
            _safe_extract(archive, extracted, options)
            yield Target(
                input=raw,
                type="zip",
                root=_single_root(extracted),
                name=_name_from_url(raw),
            )
            return

    path = Path(raw).expanduser()
    if not path.exists():
        raise ScanError(f"Target does not exist: {path}")
    if path.is_file():
        if path.suffix.lower() == ".zip":
            with tempfile.TemporaryDirectory(prefix="skillguard-") as temp:
                work = Path(temp)
                extracted = work / "extracted"
                extracted.mkdir()
                _safe_extract(path, extracted, options)
                yield Target(
                    input=str(path),
                    type="zip",
                    root=_single_root(extracted),
                    name=path.stem,
                )
                return
        with tempfile.TemporaryDirectory(prefix="skillguard-") as temp:
            work = Path(temp)
            destination = work / path.name
            shutil.copy2(path, destination)
            yield Target(input=str(path), type="file", root=work, name=path.stem)
            return

    if not path.is_dir():
        raise ScanError(f"Target is not a regular file or directory: {path}")
    yield Target(input=str(path), type="directory", root=path.resolve(), name=path.name)
