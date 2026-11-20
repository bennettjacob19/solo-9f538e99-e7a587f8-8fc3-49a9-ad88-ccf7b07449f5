#!/bin/sh
# End-to-end key-rotation test against a RUNNING repository, using real
# apt-get update with signed-by= clients.
#
# Usage: ./scripts/e2e-signed-apt.sh [repo-url]
#
# Requirements on this host: gpg (or gpgv), curl, apt-get, dpkg-deb.
#
# The server must already have exactly two secret keys provisioned in its
# GnuPG home (scripts/generate-signing-keys.sh).  The script discovers their
# fingerprints via GET /api/signing/keys, downloads the corresponding public
# keys, and drives the whole rotation lifecycle with a publication interleaved:
#
#   stage 1 (old only)   old client OK, new client FAIL
#   interleaved publish  both still governed by the old-only signature
#   stage 2 (old+new)    both clients OK (one InRelease block, two signatures)
#   stage 3 (new only)   old client FAIL, new client OK
#
# Nothing is installed system-wide: every APT state directory lives under a
# private temporary working directory.
set -eu

REPO_URL="${1:-http://127.0.0.1:8080}"
REPO_URL="${REPO_URL%/}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log() { echo "== $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

command -v apt-get  >/dev/null || fail "apt-get is required"
command -v dpkg-deb >/dev/null || fail "dpkg-deb is required"
command -v curl     >/dev/null || fail "curl is required"
command -v gpgv     >/dev/null || fail "gpgv is required"

# ------------------------------------------------- discover provisioned keys
KEYS_JSON="$(curl -fsS "$REPO_URL/api/signing/keys")"
OLD_FPR=$(printf '%s' "$KEYS_JSON" | sed -n 's/.*\[\s*"\([0-9A-F]\{40\}\)"\s*,\s*"\([0-9A-F]\{40\}\)".*/\1/p')
NEW_FPR=$(printf '%s' "$KEYS_JSON" | sed -n 's/.*\[\s*"\([0-9A-F]\{40\}\)"\s*,\s*"\([0-9A-F]\{40\}\)".*/\2/p')
[ -n "$OLD_FPR" ] && [ -n "$NEW_FPR" ] \
    || fail "expected two provisioned keys on the server, got: $KEYS_JSON"
log "using server keys old=$OLD_FPR new=$NEW_FPR"

mkdir "$WORK/keyrings"
curl -fsS "$REPO_URL/api/signing/keys/$OLD_FPR/public" | gpg --dearmor \
    > "$WORK/keyrings/old.gpg"
curl -fsS "$REPO_URL/api/signing/keys/$NEW_FPR/public" | gpg --dearmor \
    > "$WORK/keyrings/new.gpg"

# --------------------------------------------------------------- apt clients
make_client() {
    name="$1"; keyring="$2"
    base="$WORK/clients/$name"
    mkdir -p "$base/lists/partial" "$base/cache/archives/partial" "$base/dpkg"
    : > "$base/dpkg/status"
    echo "deb [arch=amd64 signed-by=$keyring] $REPO_URL stable main" \
        > "$base/sources.list"
}
make_client old "$WORK/keyrings/old.gpg"
make_client new "$WORK/keyrings/new.gpg"

apt_update() {
    base="$WORK/clients/$1"
    find "$base/lists" -mindepth 1 -delete 2>/dev/null || true
    apt-get \
        -o Dir::Etc::sourcelist="$base/sources.list" \
        -o Dir::Etc::sourceparts=- \
        -o Dir::State::lists="$base/lists" \
        -o Dir::State::status="$base/dpkg/status" \
        -o Dir::Cache="$base/cache" \
        -o APT::Sandbox::User="$(id -un)" \
        -o Debug::NoLocking=1 \
        update >"$base/update.log" 2>&1
}

expect_update() { # client expected(0|1) label
    client="$1"; expected="$2"; label="$3"
    if apt_update "$client"; then actual=0; else actual=1; fi
    if [ "$actual" != "$expected" ]; then
        echo "--- apt output for $client ---" >&2
        cat "$WORK/clients/$client/update.log" >&2
        fail "$label: client '$client' exit=$actual expected=$expected"
    fi
    log "$label: client '$client' $( [ "$actual" = 0 ] && echo OK || echo "rejected (expected)" )"
}

# ------------------------------------------------------------------ packages
build() {
    name="$1"; version="$2"; payload="$3"
    root="$WORK/build/$name-$version"
    mkdir -p "$root/DEBIAN" "$root/usr/share/doc/$name"
    cat > "$root/DEBIAN/control" <<EOF
Package: $name
Version: $version
Architecture: amd64
Maintainer: Test <test@internal.example>
Section: misc
Priority: optional
Description: $name rotation test
 $payload
EOF
    printf '%s\n' "$payload" > "$root/usr/share/doc/$name/README"
    out="$WORK/${name}_${version}_amd64.deb"
    dpkg-deb --build --root-owner-group "$root" "$out" >/dev/null
    echo "$out"
}

publish() {
    args=""
    for f in "$@"; do args="$args -F files=@$f"; done
    # shellcheck disable=SC2086
    curl -fsS -X POST "$REPO_URL/api/publish" $args
}

rotate() {
    body="{\"fingerprints\":["
    sep=""
    for fpr in "$@"; do body="$body$sep\"$fpr\""; sep=","; done
    body="$body]}"
    curl -fsS -X POST "$REPO_URL/api/signing" \
        -H 'Content-Type: application/json' -d "$body"
}

# ------------------------------------------------------------- scenario run
P1A=$(build smoke-one 1.0.0 "release one")
P1B=$(build smoke-two 1.0.0 "release one")
log "publishing release 1"
publish "$P1A" "$P1B" >/dev/null
PUB_BEFORE=$(curl -fsS "$REPO_URL/api/publications" | grep -c '"id"')

log "stage 1: signing with OLD key only"
RESP=$(rotate "$OLD_FPR")
echo "$RESP" | grep -q "\"effective_fingerprints\":\[\"$OLD_FPR\"\]" \
    || fail "stage 1 did not confirm the old fingerprint: $RESP"
# Rotation must reuse the original publication number and not create one.
PUB_AFTER=$(curl -fsS "$REPO_URL/api/publications" | grep -c '"id"')
[ "$PUB_BEFORE" = "$PUB_AFTER" ] || fail "rotation created a new publication"
expect_update old 0 "stage1 old-only sign"
expect_update new 1 "stage1 old-only sign"

log "publishing release 2 after signing (inherits the effective key set)"
P2=$(build smoke-one 2.0.0 "release two")
publish "$P2" >/dev/null
# Interleaved publish: the live Release must be exactly what InRelease signs.
curl -fsS "$REPO_URL/dists/stable/Release" > "$WORK/live-release"
curl -fsS "$REPO_URL/dists/stable/InRelease" > "$WORK/live-inrelease"
grep -Fq "$(cat "$WORK/live-release")" "$WORK/live-inrelease" \
    || fail "InRelease does not embed the live Release after interleaved publish"
expect_update old 0 "interleaved publish"
expect_update new 1 "interleaved publish"

log "stage 2: dual signing (OLD + NEW)"
RESP=$(rotate "$OLD_FPR" "$NEW_FPR")
echo "$RESP" | grep -q "$OLD_FPR" || fail "stage 2 missing old fingerprint"
echo "$RESP" | grep -q "$NEW_FPR" || fail "stage 2 missing new fingerprint"
curl -fsS "$REPO_URL/dists/stable/InRelease" > "$WORK/dual-inrelease"
[ "$(grep -c 'BEGIN PGP SIGNATURE' "$WORK/dual-inrelease")" = 1 ] \
    || fail "dual InRelease must be a single armored block"
gpgv --keyring "$WORK/keyrings/old.gpg" "$WORK/dual-inrelease" 2>&1 \
    | grep -q "Good signature" || fail "old key does not validate dual InRelease"
gpgv --keyring "$WORK/keyrings/new.gpg" "$WORK/dual-inrelease" 2>&1 \
    | grep -q "Good signature" || fail "new key does not validate dual InRelease"
expect_update old 0 "stage2 dual sign"
expect_update new 0 "stage2 dual sign"

log "stage 3: signing with NEW key only"
RESP=$(rotate "$NEW_FPR")
echo "$RESP" | grep -q "\"effective_fingerprints\":\[\"$NEW_FPR\"\]" \
    || fail "stage 3 did not confirm the new fingerprint: $RESP"
expect_update old 1 "stage3 new-only sign"
expect_update new 0 "stage3 new-only sign"

log "all rotation stages behaved as expected with real apt-get update"
log "OK"
