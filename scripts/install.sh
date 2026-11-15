#!/usr/bin/env bash
# Builds the release version of kring and installs the binary in
# ~/.local/bin/.
#
# Usage: scripts/install.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# Name of the binary built by the workspace.
BIN_NAME="kring"
# Directory the binary is installed to.
INSTALL_DIR="$HOME/.local/bin"

# Prints an error and exits.
die() {
    echo "install: $*" >&2
    exit 1
}

command -v cargo >/dev/null 2>&1 || die "cargo not found in PATH"

echo "install: building release binary"
cargo build --release -p "$BIN_NAME"

# Honour CARGO_TARGET_DIR when set.
src="${CARGO_TARGET_DIR:-target}/release/$BIN_NAME"
[ -x "$src" ] || die "built binary not found: $src"

mkdir -p "$INSTALL_DIR"
install -m 755 "$src" "$INSTALL_DIR/$BIN_NAME"
echo "install: installed $INSTALL_DIR/$BIN_NAME"

case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) echo "install: warning: $INSTALL_DIR is not in PATH" >&2 ;;
esac
