#!/usr/bin/env bash
# Fails (exit 1) if the normal dependency tree contains GTK/Qt/GNOME toolkit crates.
# Exit 0 means clean.
set -euo pipefail

cd "$(dirname "$0")/.."

# Forbidden crate name prefixes followed by a version/sep ("gtk v0.18", "gtk-sys v..", "glib_sys").
FORBIDDEN='^(gtk|gdk|glib|gio|qt|cairo|pango|atk)([-_][A-Za-z0-9_-]*)? v'

tree="$(cargo tree -e normal --workspace --prefix none)"
matches="$(printf '%s\n' "$tree" | awk '{print $1" "$2}' | grep -iE "$FORBIDDEN" | sort -u || true)"

if [ -n "$matches" ]; then
    echo "Forbidden GUI toolkit crates found:" >&2
    printf '%s\n' "$matches"
    exit 1
fi
echo "OK: no forbidden GUI toolkit crates"
