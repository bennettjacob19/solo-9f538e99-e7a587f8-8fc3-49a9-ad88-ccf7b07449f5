"""Minimal, dependency-light ``.deb`` inspection.

The repository accepts uploads from users, so a package must be validated
before it can become part of a publication.  We only need the control
metadata and enough structural checks to reject corrupt files, therefore we
parse the ``ar`` container and ``control.tar`` ourselves instead of trusting
the uploaded filename or executing package maintainer scripts.

Supported control compression: none, gzip, xz, bzip2 and zstd.  zstd support
uses the optional :mod:`zstandard` module; when it is unavailable we fall back
to ``dpkg-deb`` if present, and otherwise reject the package with a clear
error.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import re
import shutil
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path

try:  # pragma: no cover - exercised indirectly when wheels are installed
    import zstandard
except ImportError:  # pragma: no cover
    zstandard = None  # type: ignore[assignment]

#: Debian package names: lower case, at least two characters.
PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]+$")
#: Debian versions must not contain whitespace or slashes and normally start
#: with a digit (possibly an epoch).
VERSION_RE = re.compile(r"^[0-9][A-Za-z0-9.+~:-]*$")
ARCH_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")

MAX_FIELD_LENGTH = 4096
MAX_VERSION_LENGTH = 128
#: Upper bound for the uncompressed data archive, matching the upload limit.
_MAX_PAYLOAD_BYTES = 2 * 1024 * 1024 * 1024

#: Fields copied verbatim from the control file into the Packages index.
COPIED_FIELDS = (
    "Package",
    "Version",
    "Architecture",
    "Maintainer",
    "Installed-Size",
    "Section",
    "Priority",
    "Essential",
    "Multi-Arch",
    "Homepage",
    "Depends",
    "Pre-Depends",
    "Recommends",
    "Suggests",
    "Enhances",
    "Provides",
    "Conflicts",
    "Breaks",
    "Replaces",
    "Description",
)


class DebError(ValueError):
    """Raised when an uploaded file is not a usable ``.deb`` package."""


@dataclass(frozen=True)
class DebInfo:
    package: str
    version: str
    architecture: str
    fields: tuple[tuple[str, str], ...]

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.package, self.version, self.architecture)

    def field_map(self) -> dict[str, str]:
        return dict(self.fields)


_AR_GLOBAL_MAGIC = b"!<arch>\n"
_AR_HEADER_SIZE = 60


def _read_ar_index(fh: io.BufferedIOBase, size: int) -> list[tuple[str, int, int]]:
    """Return ``(name, offset, member_size)`` without loading member bodies."""

    fh.seek(0)
    if fh.read(len(_AR_GLOBAL_MAGIC)) != _AR_GLOBAL_MAGIC:
        raise DebError("not a Debian package: missing ar archive header")
    entries: list[tuple[str, int, int]] = []
    long_names = b""
    while True:
        header = fh.read(_AR_HEADER_SIZE)
        if not header:
            break
        if len(header) != _AR_HEADER_SIZE:
            raise DebError("not a Debian package: truncated ar member header")
        if header[58:60] != b"`\n":
            raise DebError("not a Debian package: invalid ar member header")
        raw_name = header[:16].decode("ascii", "replace").strip()
        try:
            member_size = int(header[48:58].decode("ascii").strip() or "0")
        except ValueError as exc:
            raise DebError("not a Debian package: invalid ar member size") from exc
        if member_size < 0:
            raise DebError("not a Debian package: invalid ar member size")
        data_offset = fh.tell()
        if data_offset + member_size > size:
            raise DebError("not a Debian package: truncated ar member")
        fh.seek(member_size + (member_size & 1), io.SEEK_CUR)

        if raw_name == "//":
            fh.seek(data_offset)
            long_names = fh.read(member_size)
            fh.seek(member_size + (member_size & 1), io.SEEK_CUR)
            continue
        if raw_name.startswith("#1/") and raw_name[3:].isdigit():
            # BSD variant: the name is stored at the start of the body.
            name_len = int(raw_name[3:])
            if name_len > member_size:
                raise DebError("not a Debian package: invalid BSD ar name")
            fh.seek(data_offset)
            name = fh.read(name_len).decode("utf-8", "replace").rstrip("\x00")
            entries.append((name, data_offset + name_len, member_size - name_len))
            continue
        if raw_name.startswith("/") and raw_name[1:].isdigit():
            start = int(raw_name[1:])
            end = long_names.find(b"/\n", start)
            if end < 0:
                raise DebError("not a Debian package: invalid ar long name")
            name = long_names[start:end].decode("utf-8", "replace")
        else:
            name = raw_name.rstrip("/")
        entries.append((name, data_offset, member_size))
    return entries


def _read_member(fh: io.BufferedIOBase, offset: int, size: int, limit: int, what: str) -> bytes:
    if size > limit:
        raise DebError(f"{what} is unreasonably large in the package")
    fh.seek(offset)
    data = fh.read(size)
    if len(data) != size:
        raise DebError(f"not a Debian package: truncated {what}")
    return data


class _SliceReader(io.RawIOBase):
    """Read at most *size* bytes from *fh*, starting at its current position."""

    def __init__(self, fh: io.BufferedIOBase, size: int) -> None:
        self._fh = fh
        self._remaining = size

    def readable(self) -> bool:  # pragma: no cover - trivial
        return True

    def read(self, amount: int = -1) -> bytes:  # type: ignore[override]
        if self._remaining <= 0:
            return b""
        if amount is None or amount < 0:
            amount = self._remaining
        data = self._fh.read(min(amount, self._remaining))
        self._remaining -= len(data)
        return data

    def readinto(self, buffer) -> int:  # type: ignore[no-untyped-def]
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)


class _LimitReader(io.RawIOBase):
    """Raise once more than *limit* bytes have been read from *fh*."""

    def __init__(self, fh, limit: int) -> None:  # type: ignore[no-untyped-def]
        self._fh = fh
        self._limit = limit
        self._count = 0

    def readable(self) -> bool:  # pragma: no cover - trivial
        return True

    def read(self, amount: int = -1) -> bytes:  # type: ignore[override]
        data = self._fh.read(amount)
        self._count += len(data)
        if self._count > self._limit:
            raise DebError("package payload is unreasonably large")
        return data

    def readinto(self, buffer) -> int:  # type: ignore[no-untyped-def]
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)


def _decompress_stream(stream, name: str, limit: int):
    """Wrap *stream* in the decompressor matching the member *name*."""

    lowered = name.lower()
    if lowered.endswith(".gz"):
        return _LimitReader(gzip.GzipFile(fileobj=stream, mode="rb"), limit)
    if lowered.endswith(".xz"):
        return _LimitReader(lzma.LZMAFile(stream, mode="rb"), limit)
    if lowered.endswith(".bz2"):
        return _LimitReader(bz2.BZ2File(stream, mode="rb"), limit)
    if lowered.endswith(".zst"):
        if zstandard is None:
            raise DebError(
                "zstd-compressed package data is not supported by this server "
                "build (install the 'zstandard' package or the zstd binary)"
            )
        return _LimitReader(zstandard.ZstdDecompressor().stream_reader(stream), limit)
    if lowered.endswith(".tar"):
        return _LimitReader(stream, limit)
    raise DebError(f"unsupported package data compression: {name}")


def _validate_payload(
    path: Path, offset: int, size: int, member_name: str, limit: int
) -> None:
    """Stream the data archive to prove it is complete and well formed.

    This catches truncated uploads and corrupt gzip/xz/bzip2/zstd streams.
    Nothing is extracted: we only walk the tar headers and checksums.
    """

    try:
        with path.open("rb") as fh:
            fh.seek(offset)
            raw = io.BufferedReader(_SliceReader(fh, size))
            stream = io.BufferedReader(
                _decompress_stream(raw, member_name, limit), buffer_size=256 * 1024
            )
            with tarfile.open(fileobj=stream, mode="r|") as archive:
                for _member in archive:
                    pass
            # Drain the stream so the compression layer verifies its trailer.
            while stream.read(1024 * 1024):
                pass
    except DebError:
        raise
    except (tarfile.TarError, OSError, EOFError, ValueError) as exc:
        raise DebError(f"package data archive is corrupt or truncated: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - decoder-specific errors
        raise DebError(f"package data archive is corrupt: {exc}") from exc


def _decompress(data: bytes, name: str, limit: int) -> bytes:
    lowered = name.lower()
    try:
        if lowered.endswith(".gz"):
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                out = stream.read(limit + 1)
        elif lowered.endswith(".xz"):
            with lzma.LZMAFile(io.BytesIO(data)) as stream:
                out = stream.read(limit + 1)
        elif lowered.endswith(".bz2"):
            with bz2.BZ2File(io.BytesIO(data)) as stream:
                out = stream.read(limit + 1)
        elif lowered.endswith(".zst"):
            if zstandard is None:
                raise DebError(
                    "zstd-compressed package control data is not supported by "
                    "this server build (install the 'zstandard' package)"
                )
            reader = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data))
            out = reader.read(limit + 1)
        elif lowered.endswith(".tar"):
            out = data
        else:
            raise DebError(f"unsupported control archive compression: {name}")
    except DebError:
        raise
    except Exception as exc:  # noqa: BLE001 - any decoder failure means bad input
        raise DebError(f"cannot decompress package control archive: {exc}") from exc
    if len(out) > limit:
        raise DebError("package control archive is unreasonably large")
    return out


def _extract_control_bytes(control_tar: bytes, member_name: str) -> bytes:
    try:
        with tarfile.open(fileobj=io.BytesIO(control_tar), mode="r:") as archive:
            target = None
            for member in archive:
                normalised = member.name.lstrip("./")
                if normalised == "control" and member.isfile():
                    target = member
                    break
            if target is None:
                raise DebError("not a Debian package: control file is missing")
            stream = archive.extractfile(target)
            if stream is None:
                raise DebError("not a Debian package: control file is unreadable")
            return stream.read(MAX_FIELD_LENGTH * 1024)
    except DebError:
        raise
    except (tarfile.TarError, OSError) as exc:
        raise DebError(f"not a Debian package: invalid {member_name}: {exc}") from exc


def parse_control_text(text: str) -> tuple[tuple[str, str], ...]:
    """Parse one deb822 stanza, keeping continuation lines intact."""

    if "\x00" in text:
        raise DebError("package control data contains NUL bytes")
    fields: list[tuple[str, str]] = []
    seen: set[str] = set()
    current: list[str] | None = None
    current_key = ""

    def flush() -> None:
        nonlocal current, current_key
        if current is None:
            return
        value = "\n".join(current).rstrip()
        fields.append((current_key, value))
        current = None
        current_key = ""

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        if line.startswith((" ", "\t")):
            if current is None:
                raise DebError("package control data has an orphan continuation line")
            current.append(line)
            continue
        if not line.strip():
            flush()
            if fields:
                break
            continue
        if ":" not in line:
            raise DebError(f"package control data has a malformed line: {line[:80]!r}")
        flush()
        key, value = line.split(":", 1)
        key = key.strip()
        if not key or not re.match(r"^[A-Za-z0-9][A-Za-z0-9-]*$", key):
            raise DebError(f"package control data has an invalid field name: {key!r}")
        folded = key.casefold()
        if folded in seen:
            raise DebError(f"package control data repeats field {key!r}")
        seen.add(folded)
        current_key = key
        current = [value.strip()]
    flush()
    if not fields:
        raise DebError("package control data is empty")
    return tuple(fields)


def _lookup(fields: tuple[tuple[str, str], ...], name: str) -> str | None:
    wanted = name.casefold()
    for key, value in fields:
        if key.casefold() == wanted:
            return value
    return None


def _validate_fields(fields: tuple[tuple[str, str], ...], expected_arch: str) -> DebInfo:
    package = _lookup(fields, "Package")
    version = _lookup(fields, "Version")
    architecture = _lookup(fields, "Architecture")
    if not package or not version or not architecture:
        raise DebError(
            "package control file must provide Package, Version and Architecture"
        )
    if not PACKAGE_RE.match(package):
        raise DebError(f"invalid Debian package name: {package!r}")
    if len(version) > MAX_VERSION_LENGTH or not VERSION_RE.match(version):
        raise DebError(f"invalid Debian package version: {version!r}")
    if not ARCH_RE.match(architecture):
        raise DebError(f"invalid Debian package architecture: {architecture!r}")
    if architecture != expected_arch:
        raise DebError(
            f"package {package} {version} is built for {architecture!r}; "
            f"this repository only accepts {expected_arch!r}"
        )
    for key, value in fields:
        if len(value) > MAX_FIELD_LENGTH * 64:
            raise DebError(f"control field {key!r} is unreasonably large")
    return DebInfo(
        package=package,
        version=version,
        architecture=architecture,
        fields=fields,
    )


def _inspect_via_dpkg_deb(path: Path, expected_arch: str) -> DebInfo | None:
    """Fallback for exotic control compression when zstandard is unavailable."""

    binary = shutil.which("dpkg-deb")
    if binary is None:
        return None
    try:
        proc = subprocess.run(
            [binary, "-f", str(path)],
            check=True,
            capture_output=True,
            timeout=30,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    try:
        text = proc.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None
    fields = parse_control_text(text)
    return _validate_fields(fields, expected_arch)


def inspect_deb(path: Path, expected_arch: str) -> DebInfo:
    """Validate *path* as an ``.deb`` for *expected_arch* and return metadata."""

    try:
        size = path.stat().st_size
    except OSError as exc:
        raise DebError(f"cannot read uploaded file: {exc}") from exc
    if size <= 0:
        raise DebError("uploaded package is empty")
    try:
        with path.open("rb") as fh:
            entries = _read_ar_index(fh, size)
            by_name = {name: (offset, member_size) for name, offset, member_size in entries}
            if "debian-binary" not in by_name:
                raise DebError("not a Debian package: debian-binary member is missing")
            debian_binary = _read_member(
                fh, *by_name["debian-binary"], 64, "debian-binary"
            )
            if not debian_binary.strip().startswith(b"2.0"):
                raise DebError("unsupported Debian package format version")
            data_member = next(
                (name for name in by_name if name.startswith("data.tar")), None
            )
            if data_member is None:
                raise DebError("not a Debian package: data archive is missing")
            control_member = next(
                (name for name in by_name if name.startswith("control.tar")), None
            )
            if control_member is None:
                raise DebError("not a Debian package: control archive is missing")
            raw_control = _read_member(
                fh, *by_name[control_member], 64 * 1024 * 1024, "control archive"
            )
            data_offset, data_size = by_name[data_member]
    except DebError:
        raise
    except OSError as exc:
        raise DebError(f"cannot read uploaded package: {exc}") from exc

    try:
        info = _inspect_control(raw_control, control_member, expected_arch)
    except DebError as exc:
        if "zstd-compressed" in str(exc):
            fallback = _inspect_via_dpkg_deb(path, expected_arch)
            if fallback is None:
                raise
            info = fallback
        else:
            raise

    _validate_payload(path, data_offset, data_size, data_member, _MAX_PAYLOAD_BYTES)
    return info


def _inspect_control(raw_control: bytes, control_member: str, expected_arch: str) -> DebInfo:
    control_tar = _decompress(raw_control, control_member, MAX_FIELD_LENGTH * 1024)
    control_text = _extract_control_bytes(control_tar, control_member)
    try:
        control_str = control_text.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DebError("package control file is not valid UTF-8") from exc
    return _validate_fields(parse_control_text(control_str), expected_arch)
