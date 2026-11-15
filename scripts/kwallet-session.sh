#!/usr/bin/env bash
# Runs a command inside a private D-Bus session with a throwaway KWallet daemon.
#
# Usage: scripts/kwallet-session.sh <command...>
#
# In current KDE Frameworks 6 (verified on kwallet 6.20) `kwalletd6` is only a
# KWallet-API shim on top of the Secret Service; the daemon that owns the
# `.kwl` wallet files is `ksecretd` (bus names `org.kde.ksecretd`,
# `org.freedesktop.secrets`, `org.kde.secretservicecompat`). This script
# starts `ksecretd` headless (`QT_QPA_PLATFORM=offscreen`, no DISPLAY) on a
# private bus.
#
# Everything (HOME, XDG_*, including XDG_CONFIG_DIRS) lives in a temp dir that
# is deleted on exit, so the user's real wallet (~/.local/share/kwalletd) and
# config (~/.config/kwalletrc) are never read or written. Wallets end up in
# `$XDG_DATA_HOME/kwalletd`. The command's exit code is propagated.
set -u

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <command...>" >&2
  exit 2
fi
if ! command -v ksecretd >/dev/null 2>&1; then
  echo "kwallet-session: ksecretd not found (package kwallet6)" >&2
  exit 1
fi

TMP_ROOT="$(mktemp -d /tmp/kring-kw.XXXXXX)"
export TMP_ROOT

# Preserve the cargo/rustup locations before HOME is overridden.
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"

# Removes the temp dir; the inner script already stops the daemon.
_cleanup() {
  rm -rf "$TMP_ROOT"
}
trap _cleanup EXIT

mkdir -p "$TMP_ROOT/home" "$TMP_ROOT/data" "$TMP_ROOT/config" "$TMP_ROOT/config-dirs" \
  "$TMP_ROOT/cache" "$TMP_ROOT/run"
chmod 700 "$TMP_ROOT/run"

export HOME="$TMP_ROOT/home"
export XDG_DATA_HOME="$TMP_ROOT/data"
export XDG_CONFIG_HOME="$TMP_ROOT/config"
export XDG_CONFIG_DIRS="$TMP_ROOT/config-dirs"
export XDG_CACHE_HOME="$TMP_ROOT/cache"
export XDG_RUNTIME_DIR="$TMP_ROOT/run"
# Lets the tools verify they run inside this private session.
export KRING_IT_RUNTIME="$XDG_RUNTIME_DIR"
# Headless Qt: no window system is needed by the calls kring makes.
export QT_QPA_PLATFORM=offscreen
unset DISPLAY WAYLAND_DISPLAY SESSION_MANAGER DBUS_SESSION_BUS_ADDRESS
unset GNOME_KEYRING_CONTROL SSH_AUTH_SOCK PAM_KWALLET5_LOGIN

# Explicit daemon settings: enabled, no first-use handling, no access prompts.
cat > "$XDG_CONFIG_HOME/kwalletrc" <<'RC'
[Wallet]
Enabled=true
First Use=false
Prompt on Open=false
Close When Idle=false

[KSecretD]
Enabled=true
RC

dbus-run-session -- bash -c '
  DAEMON_PID=""
  # Stops the private daemon (if started) and waits for it to exit.
  stop_daemon() {
    [ -n "$DAEMON_PID" ] || return 0
    kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
  }
  trap stop_daemon EXIT

  # Only a private bus is accepted: its socket lives under TMP_ROOT or is the
  # fresh /tmp/dbus-* socket that dbus-run-session creates.
  case "${DBUS_SESSION_BUS_ADDRESS:-}" in
    *"$TMP_ROOT"*|unix:path=/tmp/dbus-*) ;;
    *)
      echo "kwallet-session: refusing to run on bus ${DBUS_SESSION_BUS_ADDRESS:-<unset>}" >&2
      exit 1 ;;
  esac

  ksecretd >"$TMP_ROOT/ksecretd.log" 2>&1 &
  DAEMON_PID=$!

  for _ in $(seq 1 50); do
    busctl --user status org.kde.ksecretd >/dev/null 2>&1 \
      && busctl --user status org.freedesktop.secrets >/dev/null 2>&1 && break
    sleep 0.1
  done
  OWNER="$(busctl --user call org.freedesktop.DBus /org/freedesktop/DBus \
    org.freedesktop.DBus GetConnectionUnixProcessID s org.kde.ksecretd 2>/dev/null | awk "{print \$2}")"
  if [ "$OWNER" != "$DAEMON_PID" ]; then
    echo "kwallet-session: org.kde.ksecretd not owned by the private ksecretd ($OWNER != $DAEMON_PID)" >&2
    cat "$TMP_ROOT/ksecretd.log" >&2
    exit 1
  fi

  KRING_IT=1 "$@"
' kwallet-session-inner "$@"
exit $?
