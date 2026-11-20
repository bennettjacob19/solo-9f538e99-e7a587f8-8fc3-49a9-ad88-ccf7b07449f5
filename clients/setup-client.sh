#!/bin/sh
# Configure the host's APT client to use the internal repository.
#
# Usage:
#   Unsigned (legacy):
#     ./clients/setup-client.sh [repo-url] [suite] [component]
#
#   Signed (recommended), trusting one keyring file:
#     ./clients/setup-client.sh [repo-url] [suite] [component] /path/to/key.gpg
#
#   During a key rotation a client may trust both the old and the new key:
#     cat old.gpg new.gpg > /usr/share/keyrings/internal-rotation.gpg
#     ./clients/setup-client.sh http://host:8080 stable main \
#         /usr/share/keyrings/internal-rotation.gpg
#
# The keyring must contain the public key(s) matching the fingerprints the
# server currently signs with (GET /api/status -> signing.effective_fingerprints).
set -eu

REPO_URL="${1:-http://127.0.0.1:8080}"
SUITE="${2:-stable}"
COMPONENT="${3:-main}"
KEYRING="${4:-}"
LIST_FILE="${APT_LIST_FILE:-/etc/apt/sources.list.d/internal.list}"
REPO_URL="${REPO_URL%/}"

if [ -n "$KEYRING" ]; then
    if [ ! -r "$KEYRING" ]; then
        echo "keyring $KEYRING is not readable" >&2
        exit 2
    fi
    echo "deb [arch=amd64 signed-by=$KEYRING] $REPO_URL $SUITE $COMPONENT" > "$LIST_FILE"
else
    echo "deb [trusted=yes arch=amd64] $REPO_URL $SUITE $COMPONENT" > "$LIST_FILE"
fi

echo "Wrote $LIST_FILE:"
cat "$LIST_FILE"
echo
echo "Next:"
echo "  sudo apt-get update"
echo "  apt-get download <package>     # or: sudo apt-get install <package>"
