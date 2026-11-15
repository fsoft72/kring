#!/usr/bin/env bash
# Runs kring against a throwaway gnome-keyring for manual testing.
#
# Usage: scripts/dev-session.sh
#
# Same isolation as scripts/it-session.sh: private D-Bus session, HOME and XDG_*
# in a temp dir, gnome-keyring unlocked with password `test`. The display
# variables are kept so the window can open. The keyring is seeded with:
#   login      3 items (default alias), password `test`
#   Work       4 items, locked, password `work`; it shares "GitHub token"
#              (newer, other secret: a conflict) and "Mail account" (same
#              secret: a duplicate) with login. With
#              KRING_DEV_DIALOG=transfer-preview it stays unlocked and the app
#              previews copying the login items into it.
#   Default_1  empty, password `d1` (locked with
#              KRING_DEV_DIALOG=consolidate-preview, which also keeps Work
#              unlocked so the consolidation preview shows a conflict)
#   Default_2  1 item duplicating login's "Mail account", password `d2`
#   Default_3  empty, password `d3`
# With KRING_DEV_SHARED_LABELS=1 Default_1 and Default_3 are both labelled
# "Default" (like real gnome-keyring orphans), to show the disambiguated names.
# and, before the daemon starts, the synthetic fixtures of
# crates/kring-core/tests/fixtures/keyrings are copied into the TEMP keyrings
# dir (never from the real one), so the Offline files area has binary,
# plaintext, unreadable (multi-line secret), empty and garbage files. The seed
# also writes two backups of those temp fixtures into the temp backups dir
# (passphrase `backup`) for the Backups area.
# The temp dir is deleted on exit unless KRING_DEV_KEEP=1.
set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_ROOT="$(mktemp -d /tmp/kring-dev.XXXXXX)"
export TMP_ROOT

# Capture everything that depends on the real HOME / runtime dir before overriding them.
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
REAL_KEYRINGS="${XDG_DATA_HOME:-$HOME/.local/share}/keyrings"
REAL_XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}"
if [ -f "$REAL_XAUTHORITY" ]; then
  export XAUTHORITY="$REAL_XAUTHORITY"
fi
# WAYLAND_DISPLAY is relative to XDG_RUNTIME_DIR: make it absolute.
if [ -n "${WAYLAND_DISPLAY:-}" ] && [ "${WAYLAND_DISPLAY#/}" = "$WAYLAND_DISPLAY" ]; then
  export WAYLAND_DISPLAY="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/$WAYLAND_DISPLAY"
fi

# Prints the modification time of the real keyrings dir (or `missing`).
_real_mtime() {
  stat -c %Y "$REAL_KEYRINGS" 2>/dev/null || echo missing
}
MTIME_BEFORE="$(_real_mtime)"

# Removes the temp dir (unless kept) and reports whether the real keyrings changed.
_cleanup() {
  if [ "${KRING_DEV_KEEP:-0}" = "1" ]; then
    echo "dev-session: kept $TMP_ROOT" >&2
  else
    rm -rf "$TMP_ROOT"
  fi
  MTIME_AFTER="$(_real_mtime)"
  echo "dev-session: real keyrings mtime before=$MTIME_BEFORE after=$MTIME_AFTER" >&2
  if [ "$MTIME_BEFORE" != "$MTIME_AFTER" ]; then
    echo "dev-session: WARNING the real keyrings directory changed" >&2
  fi
}
trap _cleanup EXIT

mkdir -p "$TMP_ROOT/home" "$TMP_ROOT/data" "$TMP_ROOT/config" "$TMP_ROOT/cache" "$TMP_ROOT/run"
chmod 700 "$TMP_ROOT/run"

export HOME="$TMP_ROOT/home"
export XDG_DATA_HOME="$TMP_ROOT/data"
export XDG_CONFIG_HOME="$TMP_ROOT/config"
export XDG_CACHE_HOME="$TMP_ROOT/cache"
export XDG_RUNTIME_DIR="$TMP_ROOT/run"
# Lets the seed example verify it runs inside this private session.
export KRING_IT_RUNTIME="$XDG_RUNTIME_DIR"
unset GNOME_KEYRING_CONTROL SSH_AUTH_SOCK DBUS_SESSION_BUS_ADDRESS
echo "dev-session: temp root $TMP_ROOT (backups in $XDG_DATA_HOME/kring/backups)" >&2

# Seed the temp keyrings dir with the synthetic fixtures (repo files only).
FIXTURES_DIR="$REPO_ROOT/crates/kring-core/tests/fixtures/keyrings"
TEMP_KEYRINGS="$XDG_DATA_HOME/keyrings"
case "$TEMP_KEYRINGS" in
  "$TMP_ROOT"/*) ;;
  *) echo "dev-session: refusing to seed outside $TMP_ROOT" >&2; exit 1 ;;
esac
if [ "$TEMP_KEYRINGS" = "$REAL_KEYRINGS" ]; then
  echo "dev-session: refusing to seed the real keyrings dir" >&2
  exit 1
fi
mkdir -p "$TEMP_KEYRINGS"
chmod 700 "$TEMP_KEYRINGS"
for f in "$FIXTURES_DIR"/*.keyring; do
  [ -e "$f" ] || continue
  install -m 600 "$f" "$TEMP_KEYRINGS/"
done

cd "$REPO_ROOT" || exit 1
dbus-run-session -- bash -c '
  unset GNOME_KEYRING_CONTROL SSH_AUTH_SOCK
  DAEMON_PID=""
  # Stops the private daemon (if started).
  stop_daemon() { [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null; }
  trap stop_daemon EXIT

  OUT="$(echo -n test | gnome-keyring-daemon --unlock --components=secrets --daemonize 2>&1)"
  DAEMON_PID="$(printf "%s\n" "$OUT" | sed -n "s/^GNOME_KEYRING_PID=//p" | head -n1)"
  unset GNOME_KEYRING_CONTROL SSH_AUTH_SOCK

  for _ in $(seq 1 50); do
    busctl --user status org.freedesktop.secrets >/dev/null 2>&1 && break
    sleep 0.1
  done
  if ! busctl --user status org.freedesktop.secrets >/dev/null 2>&1; then
    echo "dev-session: org.freedesktop.secrets not available on the private bus" >&2
    printf "%s\n" "$OUT" >&2
    exit 1
  fi

  # Fall back to the bus owner PID when the daemon did not print it.
  if [ -z "$DAEMON_PID" ]; then
    DAEMON_PID="$(busctl --user call org.freedesktop.DBus /org/freedesktop/DBus \
      org.freedesktop.DBus GetConnectionUnixProcessID s org.freedesktop.secrets 2>/dev/null | awk "{print \$2}")"
  fi

  # Make sure the default alias points to the login collection.
  ALIAS="$(busctl --user call org.freedesktop.secrets /org/freedesktop/secrets \
    org.freedesktop.Secret.Service ReadAlias s default 2>/dev/null)"
  if [ "$ALIAS" != "o \"/org/freedesktop/secrets/collection/login\"" ]; then
    busctl --user call org.freedesktop.secrets /org/freedesktop/secrets \
      org.freedesktop.Secret.Service SetAlias so default /org/freedesktop/secrets/collection/login >/dev/null
  fi

  cargo run -q -p kring-core --example seed_dev || exit 1
  cargo run -p kring
'
exit $?
