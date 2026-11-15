# GnuPG colon listing fixtures

Captured with GnuPG 2.4.8 from a throwaway home directory (mode 0700, never `~/.gnupg`),
whose agent was killed with `gpgconf --homedir <dir> --kill all` afterwards. The keys
only ever existed there; the passphrase was `fixture-pw`.

```sh
H=$(mktemp -d); chmod 700 "$H"; export GNUPGHOME="$H"
G="gpg --homedir $H --batch --no-tty --pinentry-mode loopback --passphrase-file <file holding fixture-pw>"
$G --quick-gen-key 'Fixture User <fixture@example.invalid>' default default never
$G --quick-gen-key 'Colon: Tester (rsa) <colon@example.invalid>' rsa2048 default 2030-01-01
# The RSA key becomes public only.
gpg --homedir "$H" --batch --yes --delete-secret-keys 33D3B2A8F4F45A6EC3F9B1093DFE5E9430B05224
O="--batch --no-tty --with-colons --fixed-list-mode --with-fingerprint --with-subkey-fingerprint"
gpg --homedir "$H" $O --list-keys > list-keys.txt
gpg --homedir "$H" $O --list-secret-keys > list-secret-keys.txt
gpgconf --homedir "$H" --kill all; rm -rf "$H"
```

- `list-keys.txt`: Ed25519 primary (`scESC`, no expiry) with a cv25519 encryption subkey, and an
  RSA 2048 key (`scSC`, expires 2030-01-01) whose uid contains an escaped colon (`\x3a`).
- `list-secret-keys.txt`: only the Ed25519 key and its subkey (secret available, `+` in field 15).
