#!/bin/sh
# Configure the host's APT client to use the internal repository.
#
# Usage: ./clients/setup-client.sh [repo-url] [suite] [component]
#   repo-url defaults to http://127.0.0.1:8080
#
# The repository is unsigned, so the `trusted=yes` option is used. For a
# production deployment, sign the Release file with `apt-ftparchive`/`gpg` and
# replace `trusted=yes` with `signed-by=/usr/share/keyrings/internal.gpg`.
set -eu

REPO_URL="${1:-http://127.0.0.1:8080}"
SUITE="${2:-stable}"
COMPONENT="${3:-main}"
LIST_FILE="${APT_LIST_FILE:-/etc/apt/sources.list.d/internal.list}"

echo "deb [trusted=yes arch=amd64] ${REPO_URL%/} ${SUITE} ${COMPONENT}" > "$LIST_FILE"
echo "Wrote $LIST_FILE:"
cat "$LIST_FILE"
echo
echo "Next:"
echo "  sudo apt-get update"
echo "  apt-get download <package>     # or: sudo apt-get install <package>"
