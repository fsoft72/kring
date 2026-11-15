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
# The KWallet fixture wallet of crates/kring-core/tests/fixtures/kwallet
# (`fixture.kwl`, `.salt`, `_attributes.json`, password `fixture-pw`) is
# copied as wallets `kdewallet` and `fixture` into the TEMP
# `$XDG_DATA_HOME/kwalletd` for the KWallet area (never from or to the real one).
# The SSH key fixtures of crates/kring-core/tests/fixtures/ssh (keys and the
# authorized_keys / known_hosts / config decoys; passphrase of id_ed25519_enc:
# `fixture-pw`) are copied into the TEMP `$HOME/.ssh` for the SSH keys area, and
# a private ssh-agent listening under the temp dir (killed on exit) is given to
# the app as SSH_AUTH_SOCK, holding id_ecdsa. The real ~/.ssh and the user's
# agent are never used.
# For the GPG keys area a temp GnuPG home ($TMP_ROOT/gnupg, mode 0700) is seeded
# at start: a secret key "Fixture User <fixture@example.invalid>" (ed25519 +
# cv25519, expires in 2 years, passphrase `fixture-pw`) and the public key of
# "Public Contact <contact@example.invalid>", generated in a second temp home
# and imported (its export is left in the temp HOME as contact.asc for the
# import dialog). Only the app gets it, as GNUPGHOME; the agents of both temp
# homes are killed and their socket dirs removed on exit. The real ~/.gnupg
# (or GNUPGHOME) and the user's gpg-agent are never used.
# The temp dir is deleted on exit unless KRING_DEV_KEEP=1.
set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP_ROOT="$(mktemp -d /tmp/kring-dev.XXXXXX)"
export TMP_ROOT

# Capture everything that depends on the real HOME / runtime dir before overriding them.
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
REAL_KEYRINGS="${XDG_DATA_HOME:-$HOME/.local/share}/keyrings"
REAL_KWALLET="${XDG_DATA_HOME:-$HOME/.local/share}/kwalletd"
REAL_SSH="$HOME/.ssh"
REAL_AGENT_SOCK="${SSH_AUTH_SOCK:-}"
REAL_GNUPG="${GNUPGHOME:-$HOME/.gnupg}"
AGENT_PID=""
# Temp GnuPG homes (set once created, for the cleanup).
GPG_HOME=""
GPG_SRC=""
REAL_XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}"
if [ -f "$REAL_XAUTHORITY" ]; then
  export XAUTHORITY="$REAL_XAUTHORITY"
fi
# WAYLAND_DISPLAY is relative to XDG_RUNTIME_DIR: make it absolute.
if [ -n "${WAYLAND_DISPLAY:-}" ] && [ "${WAYLAND_DISPLAY#/}" = "$WAYLAND_DISPLAY" ]; then
  export WAYLAND_DISPLAY="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/$WAYLAND_DISPLAY"
fi

# Prints the modification times of the real keyrings, KWallet, SSH and GnuPG
# dirs (or `missing`).
_real_mtime() {
  echo "$(stat -c %Y "$REAL_KEYRINGS" 2>/dev/null || echo missing)/$(stat -c %Y "$REAL_KWALLET" 2>/dev/null || echo missing)/$(stat -c %Y "$REAL_SSH" 2>/dev/null || echo missing)/$(stat -c %Y "$REAL_GNUPG" 2>/dev/null || echo missing)"
}

# Runs gpg on the temp home $1 only (--homedir and GNUPGHOME), batch mode.
_gpg() {
  local home="$1"
  shift
  GNUPGHOME="$home" gpg --homedir "$home" --batch --no-tty "$@"
}

# Stops the daemons of the temp GnuPG home $1 and removes its socket dir.
_stop_gpg_home() {
  local home="$1"
  [ -n "$home" ] && [ -d "$home" ] || return 0
  GNUPGHOME="$home" gpgconf --homedir "$home" --kill all >/dev/null 2>&1
  GNUPGHOME="$home" gpgconf --homedir "$home" --remove-socketdir >/dev/null 2>&1
}
MTIME_BEFORE="$(_real_mtime)"

# Stops the private agents (ssh and gpg), removes the temp dir (unless kept)
# and reports whether the real keyrings, kwalletd, ~/.ssh or ~/.gnupg changed.
_cleanup() {
  if [ -n "$AGENT_PID" ]; then
    kill "$AGENT_PID" 2>/dev/null
    wait "$AGENT_PID" 2>/dev/null
  fi
  _stop_gpg_home "$GPG_HOME"
  _stop_gpg_home "$GPG_SRC"
  if [ "${KRING_DEV_KEEP:-0}" = "1" ]; then
    echo "dev-session: kept $TMP_ROOT" >&2
  else
    rm -rf "$TMP_ROOT"
  fi
  MTIME_AFTER="$(_real_mtime)"
  echo "dev-session: real keyrings/kwalletd/ssh/gnupg mtimes before=$MTIME_BEFORE after=$MTIME_AFTER" >&2
  if [ "$MTIME_BEFORE" != "$MTIME_AFTER" ]; then
    echo "dev-session: WARNING the real keyrings, kwalletd, ~/.ssh or ~/.gnupg directory changed" >&2
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
unset GNOME_KEYRING_CONTROL SSH_AUTH_SOCK DBUS_SESSION_BUS_ADDRESS GNUPGHOME GPG_AGENT_INFO
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

# Seed the temp KWallet dir with the fixture wallet (repo files only).
KWALLET_FIXTURES="$REPO_ROOT/crates/kring-core/tests/fixtures/kwallet"
TEMP_KWALLET="$XDG_DATA_HOME/kwalletd"
case "$TEMP_KWALLET" in
  "$TMP_ROOT"/*) ;;
  *) echo "dev-session: refusing to seed outside $TMP_ROOT" >&2; exit 1 ;;
esac
if [ "$TEMP_KWALLET" = "$REAL_KWALLET" ]; then
  echo "dev-session: refusing to seed the real kwalletd dir" >&2
  exit 1
fi
mkdir -p "$TEMP_KWALLET"
chmod 700 "$TEMP_KWALLET"
# Seeded as `kdewallet` (no keyring has that label: Import offers to create
# it) and as `fixture` (the binary fixture keyring is labelled `fixture`).
for wallet in kdewallet fixture; do
  install -m 600 "$KWALLET_FIXTURES/fixture.kwl" "$TEMP_KWALLET/$wallet.kwl"
  install -m 600 "$KWALLET_FIXTURES/fixture.salt" "$TEMP_KWALLET/$wallet.salt"
  install -m 600 "$KWALLET_FIXTURES/fixture_attributes.json" "$TEMP_KWALLET/${wallet}_attributes.json"
done

# Seed the temp ~/.ssh with the SSH key fixtures (repo files only).
SSH_FIXTURES="$REPO_ROOT/crates/kring-core/tests/fixtures/ssh"
TEMP_SSH="$HOME/.ssh"
case "$TEMP_SSH" in
  "$TMP_ROOT"/*) ;;
  *) echo "dev-session: refusing to seed outside $TMP_ROOT" >&2; exit 1 ;;
esac
if [ "$TEMP_SSH" = "$REAL_SSH" ]; then
  echo "dev-session: refusing to seed the real ~/.ssh" >&2
  exit 1
fi
mkdir -p "$TEMP_SSH"
chmod 700 "$TEMP_SSH"
for f in id_ed25519 id_ed25519_enc id_rsa id_ecdsa id_legacy; do
  install -m 600 "$SSH_FIXTURES/$f" "$TEMP_SSH/$f"
  install -m 644 "$SSH_FIXTURES/$f.pub" "$TEMP_SSH/$f.pub"
done
install -m 644 "$SSH_FIXTURES/orphan.pub" "$TEMP_SSH/orphan.pub"
for f in authorized_keys known_hosts config; do
  install -m 600 "$SSH_FIXTURES/$f" "$TEMP_SSH/$f"
done

# Start a private ssh-agent under the temp dir (never the user's agent).
AGENT_SOCK="$TMP_ROOT/agent.sock"
case "$AGENT_SOCK" in
  "$TMP_ROOT"/*) ;;
  *) echo "dev-session: refusing an agent socket outside $TMP_ROOT" >&2; exit 1 ;;
esac
if [ -n "$REAL_AGENT_SOCK" ] && [ "$AGENT_SOCK" = "$REAL_AGENT_SOCK" ]; then
  echo "dev-session: refusing to use the real ssh-agent socket" >&2
  exit 1
fi
KRING_DEV_AGENT_SOCK=""
if command -v ssh-agent >/dev/null 2>&1; then
  ssh-agent -D -a "$AGENT_SOCK" >/dev/null 2>&1 &
  AGENT_PID=$!
  for _ in $(seq 1 50); do
    [ -S "$AGENT_SOCK" ] && break
    sleep 0.1
  done
  if [ -S "$AGENT_SOCK" ]; then
    KRING_DEV_AGENT_SOCK="$AGENT_SOCK"
    SSH_AUTH_SOCK="$AGENT_SOCK" ssh-add -q "$TEMP_SSH/id_ecdsa" </dev/null >/dev/null 2>&1 ||
      echo "dev-session: could not preload id_ecdsa into the private agent" >&2
  else
    echo "dev-session: private ssh-agent did not start, the agent is unavailable" >&2
  fi
else
  echo "dev-session: ssh-agent not installed, the agent is unavailable" >&2
fi
export KRING_DEV_AGENT_SOCK

# Seed a temp GnuPG home (never the real one): a secret fixture key and an
# imported public-only key generated in a second temp home.
KRING_DEV_GNUPGHOME=""
if command -v gpg >/dev/null 2>&1 && command -v gpgconf >/dev/null 2>&1; then
  GPG_HOME="$TMP_ROOT/gnupg"
  GPG_SRC="$TMP_ROOT/gnupg-src"
  for home in "$GPG_HOME" "$GPG_SRC"; do
    case "$home" in
      "$TMP_ROOT"/*) ;;
      *) echo "dev-session: refusing a GnuPG home outside $TMP_ROOT" >&2; exit 1 ;;
    esac
    if [ "$home" = "$REAL_GNUPG" ]; then
      echo "dev-session: refusing to use the real GnuPG home" >&2
      exit 1
    fi
    mkdir -p "$home"
    chmod 700 "$home"
    echo "allow-loopback-pinentry" >"$home/gpg-agent.conf"
  done
  if printf '%s\n' fixture-pw | _gpg "$GPG_HOME" --pinentry-mode loopback --passphrase-fd 0 \
      --quick-gen-key "Fixture User <fixture@example.invalid>" default default 2y >/dev/null 2>&1 &&
    printf '\n' | _gpg "$GPG_SRC" --pinentry-mode loopback --passphrase-fd 0 \
      --quick-gen-key "Public Contact <contact@example.invalid>" default default 1y >/dev/null 2>&1 &&
    _gpg "$GPG_SRC" --armor --export contact@example.invalid >"$HOME/contact.asc" 2>/dev/null &&
    _gpg "$GPG_HOME" --import "$HOME/contact.asc" >/dev/null 2>&1; then
    KRING_DEV_GNUPGHOME="$GPG_HOME"
  else
    echo "dev-session: could not seed the temp GnuPG home, the GPG area is empty" >&2
  fi
  _stop_gpg_home "$GPG_SRC"
  rm -rf "$GPG_SRC"
  GPG_SRC=""
else
  echo "dev-session: gpg not installed, the GPG keys area is unavailable" >&2
fi
# Without a seeded home the app gets an empty temp one (never ~/.gnupg).
if [ -z "$KRING_DEV_GNUPGHOME" ]; then
  GPG_HOME="$TMP_ROOT/gnupg"
  mkdir -p "$GPG_HOME"
  chmod 700 "$GPG_HOME"
  KRING_DEV_GNUPGHOME="$GPG_HOME"
fi
export KRING_DEV_GNUPGHOME

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
  # The app talks only to the private agent (empty: no agent) and to the
  # temp GnuPG home.
  if [ -n "$KRING_DEV_AGENT_SOCK" ]; then
    SSH_AUTH_SOCK="$KRING_DEV_AGENT_SOCK" GNUPGHOME="$KRING_DEV_GNUPGHOME" cargo run -p kring
  else
    GNUPGHOME="$KRING_DEV_GNUPGHOME" cargo run -p kring
  fi
'
exit $?
