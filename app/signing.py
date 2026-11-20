"""GnuPG-backed Release signing (standard clearsigned ``InRelease``).

The service never generates or owns key material: the operator pre-provisions
one or two secret keys into a GnuPG home directory (see
``scripts/generate-signing-keys.sh``) and references their fingerprints
through the API.  This module only:

* enumerates the secret keys actually available in that home directory,
* validates a requested fingerprint set against them, and
* produces an :rfc:`4880` clearsigned ``InRelease`` with ``gpg --clearsign``.

Passing several ``--local-user`` fingerprints to a single ``--clearsign``
invocation yields *one* armored block carrying one signature per key, which is
the standard Debian multi-signature ``InRelease`` form.  APT accepts the file
when at least one signature chains to a key the client trusts via
``signed-by=``, which is exactly the semantics a key rotation needs:

    old key only  -> old-only clients pass, new-only clients fail
    old + new     -> both pass
    new key only  -> old-only clients fail, new-only clients pass
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess

_FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}$")
#: At most two keys may be effective at any time: the one being retired and
#: the one replacing it.  A transition window therefore has exactly two.
MAX_SIGNING_KEYS = 2
#: Bound the time a detached gpg process may take (it only hashes a small file).
_SIGN_TIMEOUT_SECONDS = 30


class GpgError(Exception):
    """GnuPG is unavailable, misconfigured, or rejected a signing request."""


def normalize_fingerprint(value: str) -> str:
    """Accept ``AAAA ...`` / ``AAAA:BBBB`` style input; return 40 hex digits."""

    cleaned = re.sub(r"[\s:]", "", (value or "")).upper()
    if not _FINGERPRINT_RE.match(cleaned):
        raise GpgError(
            f"{value!r} is not a 40-character OpenPGP fingerprint"
        )
    return cleaned


class GpgSigner:
    """Thin wrapper around the ``gpg`` executable for a fixed home directory."""

    def __init__(self, gpg_home: os.PathLike[str] | str) -> None:
        self.gpg_home = os.fspath(gpg_home)
        self._binary = shutil.which("gpg")
        if self._binary is None:  # pragma: no cover - image always installs gnupg
            raise GpgError("the gpg executable was not found on PATH")

    # ------------------------------------------------------------- invocation
    def _base_command(self) -> list[str]:
        return [
            self._binary,
            "--batch",
            "--no-tty",
            "--no-auto-check-trustdb",
            "--homedir",
            self.gpg_home,
        ]

    def _run(self, arguments: list[str], *, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(
                self._base_command() + arguments,
                input=input_bytes,
                capture_output=True,
                timeout=_SIGN_TIMEOUT_SECONDS,
                check=False,
            )
        except OSError as exc:
            raise GpgError(f"cannot execute gpg: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise GpgError("gpg signing timed out") from exc

    # ----------------------------------------------------------------- queries
    def available_fingerprints(self) -> list[str]:
        """Return the primary fingerprints of every secret key in the home."""

        if not os.path.isdir(self.gpg_home):
            return []
        proc = self._run(
            ["--with-colons", "--with-fingerprint", "--list-secret-keys"]
        )
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", "replace").strip()
            raise GpgError(f"cannot list signing keys: {detail or 'gpg error'}")
        fingerprints: list[str] = []
        # The colon format emits a record header then its ``fpr`` line(s).
        # Only the fingerprint directly following a ``sec`` header is the
        # primary key; an ``ssb`` header introduces encryption subkeys whose
        # fingerprints must never be used as signing identities.
        last_header = ""
        for line in proc.stdout.decode("utf-8", "replace").splitlines():
            record = line.split(":")
            if line.startswith("fpr:"):
                if last_header == "sec":
                    candidate = record[9].strip()
                    if _FINGERPRINT_RE.match(candidate) and candidate not in fingerprints:
                        fingerprints.append(candidate)
            elif record and record[0]:
                last_header = record[0]
        return fingerprints

    def validate(self, fingerprints: list[str]) -> list[str]:
        """Normalize *fingerprints* and ensure matching secret keys exist.

        The order given by the caller is preserved (the retired key is usually
        listed first during a transition); duplicates are rejected.
        """

        if not fingerprints:
            raise GpgError("at least one signing fingerprint is required")
        if len(fingerprints) > MAX_SIGNING_KEYS:
            raise GpgError(
                f"at most {MAX_SIGNING_KEYS} signing keys are supported "
                f"(got {len(fingerprints)})"
            )
        normalized = [normalize_fingerprint(value) for value in fingerprints]
        if len(set(normalized)) != len(normalized):
            raise GpgError("duplicate fingerprints in the signing request")
        available = set(self.available_fingerprints())
        if not available:
            raise GpgError(
                f"no secret signing keys are provisioned in {self.gpg_home}; "
                "import one before enabling signing"
            )
        missing = [fpr for fpr in normalized if fpr not in available]
        if missing:
            raise GpgError(
                "no local secret key matches fingerprint(s): "
                + ", ".join(missing)
            )
        return normalized

    def export_public_key(self, fingerprint: str) -> str:
        """Return the ASCII-armored public key for *fingerprint*.

        Clients import this blob into a keyring referenced by their
        ``signed-by=`` source option.  Only keys whose secret half lives in
        this GnuPG home are exportable.
        """

        normalized = normalize_fingerprint(fingerprint)
        if normalized not in self.available_fingerprints():
            raise GpgError(
                f"no local key matches fingerprint {normalized}"
            )
        proc = self._run(["--armor", "--export", normalized])
        if proc.returncode != 0 or not proc.stdout:
            detail = proc.stderr.decode("utf-8", "replace").strip()
            raise GpgError(f"cannot export public key: {detail or 'gpg error'}")
        if b"-----BEGIN PGP PUBLIC KEY BLOCK-----" not in proc.stdout:
            raise GpgError("gpg did not return an armored public key")
        return proc.stdout.decode("ascii")

    # ------------------------------------------------------------------ signer
    def sign_release(self, release: bytes, fingerprints: list[str]) -> bytes:
        """Clearsign *release* with every key in *fingerprints*.

        Returns the armored ``InRelease`` bytes.  The provisioned keys are
        passphrase-less by design; loopback pinning with an empty passphrase
        keeps the process non-interactive inside the read-root container.
        """

        normalized = self.validate(fingerprints)
        arguments = [
            "--yes",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--digest-algo",
            "SHA256",
        ]
        for fingerprint in normalized:
            arguments.extend(["--local-user", fingerprint])
        arguments.extend(["--clearsign", "--output", "-"])
        proc = self._run(arguments, input_bytes=release)
        if proc.returncode != 0 or not proc.stdout:
            detail = proc.stderr.decode("utf-8", "replace").strip()
            raise GpgError(f"failed to sign Release: {detail or 'gpg error'}")
        marker = b"-----BEGIN PGP SIGNED MESSAGE-----"
        if not proc.stdout.startswith(marker):
            raise GpgError("gpg did not return a clearsigned message")
        return proc.stdout
