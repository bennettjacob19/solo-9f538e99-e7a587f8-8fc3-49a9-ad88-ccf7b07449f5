#!/bin/sh
# Provision the GPG signing keys used by the internal APT repository.
#
# Usage:
#   scripts/generate-signing-keys.sh [GNUPG_HOME] [COUNT]
#
#   GNUPG_HOME  GnuPG home directory (default: ./data/gnupg, i.e. the
#               APT_REPO_GPG_HOME default used inside the container volume)
#   COUNT       1 or 2 keys to create (default: 2, the old+new rotation pair)
#
# The keys are generated without a passphrase so the service can sign
# non-interactively.  Fingerprints are printed at the end and the public keys
# are exported next to the homedir as old.gpg / new.gpg, ready to be copied
# to the clients' /usr/share/keyrings/ directories.
set -eu

GNUPG_HOME="${1:-$(pwd)/data/gnupg}"
COUNT="${2:-2}"

if [ "$COUNT" -lt 1 ] || [ "$COUNT" -gt 2 ]; then
    echo "COUNT must be 1 or 2" >&2
    exit 2
fi
if ! command -v gpg >/dev/null 2>&1; then
    echo "gpg (gnupg) is required" >&2
    exit 2
fi

mkdir -p "$GNUPG_HOME"
chmod 700 "$GNUPG_HOME"
# Must be exported before the very first gpg invocation, otherwise gpg creates
# and uses its default ~/.gnupg home instead of the requested directory.
export GNUPGHOME="$GNUPG_HOME"

gen_key() {
    uid="$1"
    # future-default selects the current best algorithm (ed25519/cv25519 on
    # modern GnuPG); expiry 0 means the key does not expire, which matches an
    # isolated internal deployment.
    gpg --batch --no-tty --quick-gen-key --passphrase '' \
        "$uid" future-default default 0 >/dev/null
}

echo "== generating key 1 (the 'old' key)"
gen_key "Internal APT Repository Old <aptrepo-old@internal.example>"
OLD_FPR=$(gpg --batch --with-colons --list-secret-keys --with-fingerprint \
    | awk -F: '$1=="sec"{seen=1} seen && $1=="fpr"{print $10; seen=0; exit}')

NEW_FPR=""
if [ "$COUNT" -eq 2 ]; then
    echo "== generating key 2 (the 'new' key)"
    gen_key "Internal APT Repository New <aptrepo-new@internal.example>"
    # The newest primary fingerprint is the last sec->fpr pair in the listing.
    NEW_FPR=$(gpg --batch --with-colons --list-secret-keys --with-fingerprint \
        | awk -F: '$1=="sec"{seen=1} seen && $1=="fpr"{fpr=$10; seen=0} END{print fpr}')
fi

OUT_DIR="$(dirname "$GNUPG_HOME")/public-keys"
mkdir -p "$OUT_DIR"
gpg --batch --yes --export "$OLD_FPR" > "$OUT_DIR/old.gpg"
echo "== exported old public key -> $OUT_DIR/old.gpg"
if [ -n "$NEW_FPR" ]; then
    gpg --batch --yes --export "$NEW_FPR" > "$OUT_DIR/new.gpg"
    echo "== exported new public key -> $OUT_DIR/new.gpg"
fi

echo
echo "GnuPG home:        $GNUPG_HOME"
echo "OLD key fingerprint: $OLD_FPR"
if [ -n "$NEW_FPR" ]; then
    echo "NEW key fingerprint: $NEW_FPR"
fi
echo
echo "Next steps:"
echo "  1. Start the service (the homedir defaults to <data>/gnupg)."
echo "  2. Publish at least one release, then POST /api/signing with one or"
echo "     two of the fingerprints above."
echo "  3. Install old.gpg / new.gpg on clients and configure signed-by=."
