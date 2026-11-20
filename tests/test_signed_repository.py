"""Integration tests for GPG-signed releases and key rotation.

These exercise the real ``gpg`` executable with two freshly generated,
passphrase-less keys.  They are skipped when GnuPG is not installed.  The
matrix under test mirrors the operational rollout:

    old key only  -> clients trusting the old key update, new-only clients fail
    old + new     -> both clients update
    new key only  -> old-only clients fail, new-only clients update
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent))
from debbuild import build_deb  # noqa: E402

sys.path.insert(0, str(Path(__file__).parent.parent))
from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402
from app.signing import GpgError, GpgSigner, normalize_fingerprint  # noqa: E402
from app.storage import PublicationError, Repository, StagedUpload  # noqa: E402

pytestmark = pytest.mark.skipif(
    shutil.which("gpg") is None, reason="gnupg is required for signing tests"
)


def _gpg(gpg_home: Path, *args: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "gpg",
            "--batch",
            "--no-tty",
            "--no-auto-check-trustdb",
            "--homedir",
            str(gpg_home),
            *args,
        ],
        input=input_bytes,
        capture_output=True,
        check=False,
        timeout=60,
    )


def _make_key(gpg_home: Path, uid: str) -> str:
    gpg_home.mkdir(parents=True, exist_ok=True)
    os.chmod(gpg_home, 0o700)
    proc = _gpg(
        gpg_home,
        "--quick-gen-key",
        "--passphrase",
        "",
        uid,
        "future-default",
        "default",
        "0",
    )
    assert proc.returncode == 0, proc.stderr.decode()
    listed = _gpg(gpg_home, "--with-colons", "--list-secret-keys", "--with-fingerprint")
    # Collect the primary fingerprint of every sec block; return the newest.
    primaries: list[str] = []
    last_header = ""
    for line in listed.stdout.decode().splitlines():
        record = line.split(":")
        if line.startswith("fpr:") and last_header == "sec":
            primaries.append(record[9])
        elif record and record[0]:
            last_header = record[0]
    assert primaries, listed.stderr.decode()
    return primaries[-1]


@pytest.fixture()
def keys(tmp_path: Path) -> dict[str, str]:
    gpg_home = tmp_path / "gnupg"
    old = _make_key(gpg_home, "Old Rotation Key <old@internal.example>")
    new = _make_key(gpg_home, "New Rotation Key <new@internal.example>")
    return {"home": str(gpg_home), "old": old, "new": new}


@pytest.fixture()
def signed_client(tmp_path: Path, keys: dict[str, str]):
    settings = Settings(data_dir=tmp_path / "data", gpg_home=keys["home"])
    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client, settings, app.state.repository, keys


def _publish(test_client: TestClient, tmp_root: Path, version: str = "1.0.0") -> None:
    src = tmp_root / f"src-{version}"
    src.mkdir(parents=True, exist_ok=True)
    paths = []
    for name in ("alpha", "beta"):
        path = src / f"{name}_{version}_amd64.deb"
        build_deb(path, control={"Package": name, "Version": version})
        paths.append(path)
    files = [
        ("files", (path.name, path.read_bytes(), "application/vnd.debian.binary-package"))
        for path in paths
    ]
    response = test_client.post("/api/publish", files=files)
    assert response.status_code == 201, response.text


def _export_public_key(gpg_home: str, fingerprint: str, target: Path) -> Path:
    proc = _gpg(Path(gpg_home), "--yes", "--export", fingerprint)
    assert proc.returncode == 0
    target.write_bytes(proc.stdout)
    assert target.stat().st_size > 0
    return target


def _gpgv_verify(public_key: Path, inrelease: Path) -> bool:
    """Return True when gpgv reports at least one ``Good signature``.

    gpgv exits non-zero as soon as *any* signature in a multi-signature block
    lacks a public key, even while another signature verifies cleanly.  APT's
    own rule is "at least one signature chains to a trusted key", which maps
    to the presence of a Good signature line here.
    """

    proc = subprocess.run(
        ["gpgv", "--keyring", str(public_key), str(inrelease)],
        capture_output=True,
        check=False,
    )
    return b"Good signature" in proc.stderr


def _inrelease_bytes(test_client: TestClient) -> bytes:
    response = test_client.get("/dists/stable/InRelease")
    assert response.status_code == 200
    return response.content


def test_normalize_fingerprint_accepts_common_formats(keys):
    fpr = keys["old"]
    spaced = " ".join(fpr[i : i + 4] for i in range(0, 40, 4))
    assert normalize_fingerprint(spaced) == fpr
    assert normalize_fingerprint(fpr.lower()) == fpr
    with pytest.raises(GpgError):
        normalize_fingerprint("not-a-fingerprint")


def test_available_keys_are_listed(signed_client):
    test_client, _settings, repository, keys = signed_client
    assert set(repository.available_signing_keys()) == {keys["old"], keys["new"]}
    body = test_client.get("/api/signing/keys").json()
    assert set(body["available_fingerprints"]) == {keys["old"], keys["new"]}
    assert body["max_keys"] == 2


def test_signing_before_any_publication_is_rejected(signed_client):
    test_client, _settings, _repository, keys = signed_client
    response = test_client.post(
        "/api/signing", json={"fingerprints": [keys["old"]]}
    )
    assert response.status_code == 400
    assert "publish" in response.text.lower()


def test_unknown_fingerprint_rejected_without_state_change(signed_client, tmp_path):
    test_client, _settings, repository, keys = signed_client
    _publish(test_client, tmp_path)
    bogus = "0" * 40
    response = test_client.post("/api/signing", json={"fingerprints": [bogus]})
    assert response.status_code == 400
    assert "fingerprint" in response.text.lower()
    assert repository.effective_signing() is None
    # No InRelease was exposed and the Release stayed in place.
    assert test_client.get("/dists/stable/InRelease").status_code == 404
    events = test_client.get("/api/signing/events").json()["events"]
    assert events[0]["result"] == "rejected"


def test_too_many_fingerprints_rejected(signed_client, tmp_path):
    test_client, _settings, _repository, keys = signed_client
    _publish(test_client, tmp_path)
    response = test_client.post(
        "/api/signing",
        json={"fingerprints": [keys["old"], keys["new"], keys["old"]]},
    )
    assert response.status_code == 422


def test_enable_signing_reuses_publication_and_serves_inrelease(signed_client, tmp_path):
    test_client, _settings, repository, keys = signed_client
    _publish(test_client, tmp_path)
    release_before = test_client.get("/dists/stable/Release").content
    publications_before = len(test_client.get("/api/publications").json()["publications"])

    response = test_client.post(
        "/api/signing", json={"fingerprints": [keys["old"]]}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    # The original publication number is returned; no new publication exists.
    assert body["publication_id"] == 1
    assert body["effective_fingerprints"] == [keys["old"]]
    publications_after = len(test_client.get("/api/publications").json()["publications"])
    assert publications_after == publications_before

    # The Release blob itself is untouched.
    assert test_client.get("/dists/stable/Release").content == release_before
    inrelease = _inrelease_bytes(test_client)
    assert inrelease.startswith(b"-----BEGIN PGP SIGNED MESSAGE-----")
    assert release_before.decode() in inrelease.decode()

    status = test_client.get("/api/status").json()
    assert status["signing"]["enabled"] is True
    assert status["signing"]["effective_fingerprints"] == [keys["old"]]
    assert status["signing"]["publication_id"] == 1


def test_full_rotation_matrix_with_gpgv(signed_client, tmp_path):
    test_client, _settings, repository, keys = signed_client
    keyring_dir = tmp_path / "keyrings"
    keyring_dir.mkdir()
    old_kr = _export_public_key(keys["home"], keys["old"], keyring_dir / "old.gpg")
    new_kr = _export_public_key(keys["home"], keys["new"], keyring_dir / "new.gpg")
    _publish(test_client, tmp_path, "1.0.0")

    def rotate(*fingerprints: str) -> bytes:
        response = test_client.post(
            "/api/signing", json={"fingerprints": list(fingerprints)}
        )
        assert response.status_code == 200, response.text
        inrelease_path = tmp_path / "current-InRelease"
        inrelease_path.write_bytes(_inrelease_bytes(test_client))
        return inrelease_path

    # Stage 1: old key only.
    inr = rotate(keys["old"])
    assert _gpgv_verify(old_kr, inr)
    assert not _gpgv_verify(new_kr, inr)

    # Stage 2: dual signing - both single-key keyrings verify the one block.
    inr = rotate(keys["old"], keys["new"])
    assert _gpgv_verify(old_kr, inr)
    assert _gpgv_verify(new_kr, inr)
    # A single armored block carrying two signatures.
    text = inr.read_text()
    assert text.count("BEGIN PGP SIGNATURE") == 1
    assert text.count("END PGP SIGNATURE") == 1

    # Stage 3: new key only - the old key can no longer verify.
    inr = rotate(keys["new"])
    assert not _gpgv_verify(old_kr, inr)
    assert _gpgv_verify(new_kr, inr)


def test_publish_after_signing_uses_effective_keys(signed_client, tmp_path):
    test_client, _settings, repository, keys = signed_client
    _publish(test_client, tmp_path, "1.0.0")
    response = test_client.post(
        "/api/signing", json={"fingerprints": [keys["old"], keys["new"]]}
    )
    assert response.status_code == 200

    # A routine publication after signing must carry the effective key set.
    _publish(test_client, tmp_path, "2.0.0")
    current = repository.current_publication()
    assert current is not None
    assert list(current.signing_fingerprints) == [keys["old"], keys["new"]]
    assert current.inrelease_sha256 is not None

    # The served InRelease signs the currently served Release (same content).
    release = test_client.get("/dists/stable/Release").content
    inrelease = _inrelease_bytes(test_client)
    assert release.decode() in inrelease.decode()

    keyring_dir = tmp_path / "keyrings"
    keyring_dir.mkdir(exist_ok=True)
    old_kr = _export_public_key(keys["home"], keys["old"], keyring_dir / "old.gpg")
    new_kr = _export_public_key(keys["home"], keys["new"], keyring_dir / "new.gpg")
    inr_file = tmp_path / "inr2"
    inr_file.write_bytes(inrelease)
    assert _gpgv_verify(old_kr, inr_file)
    assert _gpgv_verify(new_kr, inr_file)

    # The effective state now points at the new publication id.
    status = test_client.get("/api/status").json()
    assert status["signing"]["publication_id"] == current.id


def test_interleaved_rotation_and_publish_keeps_release_and_signature_consistent(
    signed_client, tmp_path
):
    """Whatever interleaving happens, InRelease must sign the live Release."""

    test_client, _settings, repository, keys = signed_client
    _publish(test_client, tmp_path, "1.0.0")
    test_client.post("/api/signing", json={"fingerprints": [keys["old"]]})
    _publish(test_client, tmp_path, "2.0.0")
    test_client.post(
        "/api/signing", json={"fingerprints": [keys["old"], keys["new"]]}
    )
    _publish(test_client, tmp_path, "3.0.0")
    test_client.post("/api/signing", json={"fingerprints": [keys["new"]]})

    release = test_client.get("/dists/stable/Release").content
    inrelease = _inrelease_bytes(test_client)
    # The exact live Release bytes are embedded in the clearsigned document.
    assert release.decode() in inrelease.decode()
    state = repository.effective_signing()
    assert state is not None
    current = repository.current_publication()
    assert state["release_sha256"] == current.release_sha256
    assert state["publication_id"] == current.id

    new_kr = _export_public_key(
        keys["home"], keys["new"], tmp_path / "new.gpg"
    )
    old_kr = _export_public_key(
        keys["home"], keys["old"], tmp_path / "old.gpg"
    )
    inr_file = tmp_path / "final-inr"
    inr_file.write_bytes(inrelease)
    assert _gpgv_verify(new_kr, inr_file)
    assert not _gpgv_verify(old_kr, inr_file)


def test_signing_failure_keeps_previous_inrelease_usable(signed_client, tmp_path, monkeypatch):
    test_client, _settings, repository, keys = signed_client
    _publish(test_client, tmp_path, "1.0.0")
    ok = test_client.post(
        "/api/signing", json={"fingerprints": [keys["old"]]}
    )
    assert ok.status_code == 200
    good_inrelease = _inrelease_bytes(test_client)
    good_state = repository.effective_signing()

    def exploding(release: bytes, fingerprints: list[str]) -> bytes:
        raise GpgError("simulated gpg failure")

    monkeypatch.setattr(repository.signer, "sign_release", exploding)
    response = test_client.post(
        "/api/signing", json={"fingerprints": [keys["new"]]}
    )
    assert response.status_code == 400
    # The previous effective signature is still served and recorded.
    assert _inrelease_bytes(test_client) == good_inrelease
    assert repository.effective_signing() == good_state


def test_publish_failure_keeps_previous_release_and_signature(signed_client, tmp_path, monkeypatch):
    test_client, _settings, repository, keys = signed_client
    _publish(test_client, tmp_path, "1.0.0")
    test_client.post("/api/signing", json={"fingerprints": [keys["old"]]})
    release_before = test_client.get("/dists/stable/Release").content
    inrelease_before = _inrelease_bytes(test_client)

    def exploding(release: bytes, fingerprints: list[str]) -> bytes:
        raise GpgError("gpg unavailable during publish")

    monkeypatch.setattr(repository.signer, "sign_release", exploding)
    src = tmp_path / "src-fail"
    src.mkdir()
    build_deb(src / "gamma_9.9.9_amd64.deb", control={"Package": "gamma", "Version": "9.9.9"})
    response = test_client.post(
        "/api/publish",
        files=[
            (
                "files",
                (
                    "gamma_9.9.9_amd64.deb",
                    (src / "gamma_9.9.9_amd64.deb").read_bytes(),
                    "application/vnd.debian.binary-package",
                ),
            )
        ],
    )
    assert response.status_code == 400
    assert test_client.get("/dists/stable/Release").content == release_before
    assert _inrelease_bytes(test_client) == inrelease_before
    assert repository.current_publication().id == 1


def test_signing_state_survives_restart(signed_client, tmp_path, keys):
    test_client, settings, repository, _keys = signed_client
    _publish(test_client, tmp_path, "1.0.0")
    test_client.post(
        "/api/signing", json={"fingerprints": [keys["old"], keys["new"]]}
    )
    inrelease_before = _inrelease_bytes(test_client)
    state_before = repository.effective_signing()

    # A brand-new instance over the same data volume reconciles on startup.
    resumed = Repository(settings)
    assert resumed.effective_signing() == state_before
    with TestClient(create_app(settings)) as resumed_client:
        assert (
            resumed_client.get("/dists/stable/InRelease").content
            == inrelease_before
        )


def test_restart_relinks_inrelease_when_fixed_path_was_lost(signed_client, tmp_path, keys):
    test_client, settings, repository, _keys = signed_client
    _publish(test_client, tmp_path, "1.0.0")
    test_client.post("/api/signing", json={"fingerprints": [keys["old"]]})
    inrelease_before = _inrelease_bytes(test_client)

    # Simulate loss of the mutable fixed path but the content-addressed copy
    # (and the journal) surviving.
    fixed = repository.export / settings.inrelease_path
    fixed.unlink()
    resumed = Repository(settings)
    assert fixed.read_bytes() == inrelease_before


def test_unsigned_publication_has_no_inrelease(signed_client, tmp_path):
    test_client, _settings, _repository, _keys = signed_client
    _publish(test_client, tmp_path)
    assert test_client.get("/dists/stable/InRelease").status_code == 404
    status = test_client.get("/api/status").json()
    assert status["signing"]["enabled"] is False
    assert status["signing"]["effective_fingerprints"] == []


def test_missing_gpg_home_reports_no_keys(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "data", gpg_home=tmp_path / "does-not-exist"
    )
    repository = Repository(settings)
    assert repository.available_signing_keys() == []
    with pytest.raises(PublicationError):
        repository.rotate_signing(["0" * 40])


def test_duplicate_fingerprint_rejected(signed_client, tmp_path):
    test_client, _settings, _repository, keys = signed_client
    _publish(test_client, tmp_path)
    response = test_client.post(
        "/api/signing", json={"fingerprints": [keys["old"], keys["old"]]}
    )
    assert response.status_code == 400
    assert "duplicate" in response.text.lower()
