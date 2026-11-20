"""Runtime configuration for the single-distribution APT repository."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_ARCH_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:  # pragma: no cover - defensive
        raise RuntimeError(f"{name} must be an integer") from exc
    if value <= 0:
        raise RuntimeError(f"{name} must be positive")
    return value


@dataclass(frozen=True)
class Settings:
    """All tunables of the repository.

    The repository is deliberately restricted to one distribution, one
    component and one architecture, as required by the deployment.
    """

    data_dir: Path = field(
        default_factory=lambda: Path(os.environ.get("APT_REPO_DATA_DIR", "./data"))
    )
    distribution: str = field(
        default_factory=lambda: os.environ.get("APT_REPO_DISTRIBUTION", "stable")
    )
    component: str = field(
        default_factory=lambda: os.environ.get("APT_REPO_COMPONENT", "main")
    )
    architecture: str = field(
        default_factory=lambda: os.environ.get("APT_REPO_ARCHITECTURE", "amd64")
    )
    origin: str = field(
        default_factory=lambda: os.environ.get(
            "APT_REPO_ORIGIN", "Internal APT Repository"
        )
    )
    label: str = field(
        default_factory=lambda: os.environ.get(
            "APT_REPO_LABEL", "Internal APT Repository"
        )
    )
    description: str = field(
        default_factory=lambda: os.environ.get(
            "APT_REPO_DESCRIPTION", "Internal single-component APT repository"
        )
    )
    #: Number of successful publications whose indexes and packages stay
    #: reachable.  The task requires exactly the two most recent ones.
    retention: int = field(
        default_factory=lambda: _env_int("APT_REPO_RETENTION", 2)
    )
    max_file_bytes: int = field(
        default_factory=lambda: _env_int(
            "APT_REPO_MAX_FILE_BYTES", 512 * 1024 * 1024
        )
    )
    max_batch_files: int = field(
        default_factory=lambda: _env_int("APT_REPO_MAX_BATCH_FILES", 500)
    )
    max_batch_bytes: int = field(
        default_factory=lambda: _env_int(
            "APT_REPO_MAX_BATCH_BYTES", 4 * 1024 * 1024 * 1024
        )
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "data_dir", Path(self.data_dir).resolve())
        for attr in ("distribution", "component"):
            value = getattr(self, attr)
            if not _NAME_RE.match(value):
                raise RuntimeError(f"invalid {attr!r}: {value!r}")
        if not _ARCH_RE.match(self.architecture):
            raise RuntimeError(f"invalid architecture: {self.architecture!r}")
        if self.retention < 1:
            raise RuntimeError("retention must be at least 1")

    @property
    def index_dir(self) -> str:
        return f"{self.component}/binary-{self.architecture}"

    @property
    def index_relpath(self) -> str:
        return f"{self.index_dir}/Packages.gz"

    @property
    def plain_index_relpath(self) -> str:
        return f"{self.index_dir}/Packages"

    @property
    def release_path(self) -> str:
        return f"dists/{self.distribution}/Release"

    @property
    def index_path(self) -> str:
        return f"dists/{self.distribution}/{self.index_relpath}"

    @property
    def plain_index_path(self) -> str:
        return f"dists/{self.distribution}/{self.plain_index_relpath}"

    @property
    def index_by_hash_prefix(self) -> str:
        return f"dists/{self.distribution}/{self.index_dir}/by-hash/SHA256"

    @property
    def release_by_hash_prefix(self) -> str:
        return f"dists/{self.distribution}/by-hash/SHA256"

    @property
    def sources_line(self) -> str:
        return (
            f"deb [trusted=yes arch={self.architecture}] "
            "http://127.0.0.1:8080/ "
            f"{self.distribution} {self.component}"
        )
