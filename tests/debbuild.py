"""Build real Debian packages for tests without extra dependencies."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

DEFAULT_CONTROL = {
    "Package": "demo",
    "Version": "1.0.0",
    "Architecture": "amd64",
    "Maintainer": "Test <test@example.com>",
    "Section": "misc",
    "Priority": "optional",
    "Description": "demo package",
}


def _tar_gz(members: dict[str, bytes], mtime: int = 0) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.GNU_FORMAT) as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = mtime
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _ar(members: list[tuple[str, bytes]]) -> bytes:
    out = bytearray(b"!<arch>\n")
    for name, data in members:
        header = (
            f"{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(data):<10}`\n".encode()
        )
        assert len(header) == 60, header
        out += header + data
        if len(data) % 2:
            out += b"\n"
    return bytes(out)


def build_deb(
    path: Path,
    *,
    control: dict[str, str] | None = None,
    payload: bytes = b"payload\n",
    arch: str = "amd64",
) -> Path:
    fields = dict(DEFAULT_CONTROL)
    fields["Architecture"] = arch
    if control:
        fields.update(control)
    control_text = "".join(f"{key}: {value}\n" for key, value in fields.items())
    control_tar = _tar_gz(
        {"control": control_text.encode(), "md5sums": b""}
    )
    data_tar = _tar_gz(
        {"usr/share/doc/demo/README": payload},
    )
    blob = _ar(
        [
            ("debian-binary", b"2.0\n"),
            ("control.tar.gz", control_tar),
            ("data.tar.gz", data_tar),
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)
    return path
