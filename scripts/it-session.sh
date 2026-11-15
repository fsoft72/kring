#!/usr/bin/env bash
# Runs a command inside a private D-Bus session with a throwaway gnome-keyring.
#
# Usage: scripts/it-session.sh <command...>
#
# Everything (HOME, XDG_*) lives in a temp dir that is deleted on exit, so the
# user's real keyring is never touched. Inside the session the `login`
# collection exists, is unlocked (password `test`) and is the `default` alias.
# The command's exit code is propagated.
set -u

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <command...>" >&2
  exit 2
fi

TMP_ROOT="$(mktemp -d /tmp/kring-it.XXXXXX)"
export TMP_ROOT

# Preserve the cargo/rustup locations before HOME is overridden.
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"

# Removes the temp dir; the inner script already stops the daemon.
_cleanup() {
  rm -rf "$TMP_ROOT"
}
trap _cleanup EXIT

mkdir -p "$TMP_ROOT/home" "$TMP_ROOT/data" "$TMP_ROOT/config" "$TMP_ROOT/cache" "$TMP_ROOT/run"
chmod 700 "$TMP_ROOT/run"

export HOME="$TMP_ROOT/home"
export XDG_DATA_HOME="$TMP_ROOT/data"
export XDG_CONFIG_HOME="$TMP_ROOT/config"
export XDG_CACHE_HOME="$TMP_ROOT/cache"
export XDG_RUNTIME_DIR="$TMP_ROOT/run"
# Lets the integration tests verify they run inside this private session.
export KRING_IT_RUNTIME="$XDG_RUNTIME_DIR"
unset GNOME_KEYRING_CONTROL SSH_AUTH_SOCK DBUS_SESSION_BUS_ADDRESS

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
    echo "it-session: org.freedesktop.secrets not available on the private bus" >&2
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

  KRING_IT=1 "$@"
' it-session-inner "$@"
exit $?
