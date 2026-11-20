#!/bin/sh
# End-to-end smoke test against a running repository.
#
# Usage: ./scripts/e2e-apt.sh [repo-url]
#
# Requires: curl, apt-get, dpkg-deb, python3 (to build and inspect samples).
set -eu

REPO_URL="${1:-http://127.0.0.1:8080}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
BASE="$WORK/apt"
mkdir -p "$BASE/lists/partial" "$BASE/dpkg" "$BASE/cache/archives/partial"
echo "deb [trusted=yes arch=amd64] ${REPO_URL%/}/ stable main" > "$WORK/sources.list"

APT="apt-get -o Dir::Etc::sourcelist=$WORK/sources.list \
 -o Dir::Etc::sourceparts=- \
 -o Dir::State::lists=$BASE/lists \
 -o Dir::State::status=$BASE/dpkg/status \
 -o Dir::Cache=$BASE/cache \
 -o APT::Sandbox::User=$(id -un) \
 -o Debug::NoLocking=1"

build() {
    name="$1"; version="$2"; payload="$3"
    root="$WORK/build-$name-$version-$(printf '%s' "$payload" | cksum | cut -d' ' -f1)"
    mkdir -p "$root/DEBIAN" "$root/usr/share/doc/$name"
    printf 'Package: %s\nVersion: %s\nArchitecture: amd64\nMaintainer: Test <test@example.com>\nSection: misc\nPriority: optional\nDescription: %s test package\n' \
        "$name" "$version" "$name" > "$root/DEBIAN/control"
    printf '%s\n' "$payload" > "$root/usr/share/doc/$name/README"
    out="$WORK/$name-$version-$(printf '%s' "$payload" | cksum | cut -d' ' -f1).deb"
    dpkg-deb --build --root-owner-group "$root" "$out" >/dev/null
    echo "$out"
}

upload() {
    set -- "$@"
    args=""
    for f in "$@"; do args="$args -F files=@$f"; done
    # shellcheck disable=SC2086
    curl -fsS -X POST "$REPO_URL/api/publish" $args >/dev/null
}

release_index() {
    curl -fsS "$REPO_URL/dists/stable/Release" \
        | sed -n 's/^ \([0-9a-f]\{64\}\) [0-9]* main\/binary-amd64\/Packages.gz$/\1/p'
}

ONE_A=$(build smoke-one 1.0.0 "release one")
TWO_A=$(build smoke-two 1.0.0 "release one")
upload "$ONE_A" "$TWO_A"
IDX1=$(release_index)
echo "== release 1 published (index $IDX1)"

$APT update >/dev/null 2>&1
mkdir -p "$WORK/dl1" && (cd "$WORK/dl1" && $APT download smoke-one >/dev/null 2>&1)
echo "== apt-get download smoke-one -> $(ls "$WORK/dl1")"

# Same package name and version, different bytes, plus a new version.
ONE_B=$(build smoke-one 1.0.0 "release two rebuilt")
TWO_B=$(build smoke-two 2.0.0 "release two")
upload "$ONE_B" "$TWO_B"
IDX2=$(release_index)
test "$IDX1" != "$IDX2"
echo "== release 2 published (index $IDX2)"

$APT update >/dev/null 2>&1
mkdir -p "$WORK/dl2" && (cd "$WORK/dl2" && $APT download smoke-two >/dev/null 2>&1)
echo "== apt-get download smoke-two -> $(ls "$WORK/dl2")"

# A client holding release 1 can still resolve its index by hash and download
# the packages that index references.
curl -fsS "$REPO_URL/dists/stable/main/binary-amd64/by-hash/SHA256/$IDX1" \
    | gzip -dc > "$WORK/Packages.1"
test -s "$WORK/Packages.1"
old_pkg=$(sed -n 's/^Filename: //p' "$WORK/Packages.1" | head -1)
old_sha=$(sed -n 's/^SHA256: //p' "$WORK/Packages.1" | head -1)
curl -fsS "$REPO_URL/$old_pkg" -o "$WORK/old.deb"
echo "$old_sha  $WORK/old.deb" | sha256sum -c - >/dev/null
echo "== previous release index and packages verified via by-hash"

# A third publication must evict release 1 but keep releases 2 and 3.
THREE_A=$(build smoke-one 3.0.0 "release three")
upload "$THREE_A"
IDX3=$(release_index)
if curl -fs -o /dev/null "$REPO_URL/dists/stable/main/binary-amd64/by-hash/SHA256/$IDX1"; then
    echo "FAIL: release 1 index still present after a third publication" >&2
    exit 1
fi
curl -fsS -o /dev/null "$REPO_URL/dists/stable/main/binary-amd64/by-hash/SHA256/$IDX2"
curl -fsS -o /dev/null "$REPO_URL/dists/stable/main/binary-amd64/by-hash/SHA256/$IDX3"
echo "== retention keeps exactly the two most recent releases"

echo "== OK"
