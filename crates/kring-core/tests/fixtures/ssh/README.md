# SSH key fixtures

Real key files made by OpenSSH `ssh-keygen`, in a temp dir (never in `~/.ssh`),
then copied here. The keys are throwaway test keys: they protect nothing.

| File | Content |
| --- | --- |
| `id_ed25519`, `.pub` | Ed25519, no passphrase, comment `fixture@kring` |
| `id_ed25519_enc`, `.pub` | Ed25519, passphrase `fixture-pw`, comment `fixture-enc@kring` |
| `id_rsa`, `.pub` | RSA 3072, no passphrase, comment `fixture-rsa@kring` |
| `id_ecdsa`, `.pub` | ECDSA P-256, no passphrase, comment `fixture-ecdsa@kring` |
| `id_legacy`, `.pub` | RSA 2048 in legacy PEM (`-----BEGIN RSA PRIVATE KEY-----`), no passphrase, comment `fixture-legacy@kring` |
| `orphan.pub` | Ed25519 public key without a private file, comment `fixture-orphan@kring` |
| `authorized_keys`, `known_hosts`, `config` | Decoys: must never be listed as keys |

Passphrase of the encrypted key: `fixture-pw`.

## Regenerate

```sh
T=$(mktemp -d) && cd "$T"
ssh-keygen -q -t ed25519 -N "" -C fixture@kring -f id_ed25519
ssh-keygen -q -t ed25519 -N fixture-pw -C fixture-enc@kring -f id_ed25519_enc
ssh-keygen -q -t rsa -b 3072 -N "" -C fixture-rsa@kring -f id_rsa
ssh-keygen -q -t ecdsa -b 256 -N "" -C fixture-ecdsa@kring -f id_ecdsa
ssh-keygen -q -t rsa -b 2048 -m PEM -N "" -C fixture-legacy@kring -f id_legacy
ssh-keygen -q -t ed25519 -N "" -C fixture-orphan@kring -f orphan && rm orphan
chmod 600 id_*; chmod 644 *.pub
```

The decoys are small hand-written text files. Regenerating changes every
fingerprint: update the expected values in `tests/ssh_scan.rs`
(`ssh-keygen -lf <name>.pub`).

## Scanner rules (`kring_core::ssh::scan_keys`)

- Only regular files (no symlinks) of at most 64 KiB are read.
- A private file counts if it starts with `-----BEGIN OPENSSH PRIVATE KEY-----`
  and parses, or with a PEM `-----BEGIN ... PRIVATE KEY-----` line (legacy).
  A `.pub` file counts if it parses as an OpenSSH public key.
- Encrypted OpenSSH private keys keep their public key in clear, so algorithm,
  bits and fingerprint need no passphrase.
- Legacy PEM / PKCS#8 keys: `legacy_format = true`; algorithm, bits and
  fingerprint come from the paired `.pub`, else the algorithm is
  `Other("legacy")` with an empty fingerprint; `encrypted` is `Some(true)` when
  the PEM has `Proc-Type: 4,ENCRYPTED` or is `ENCRYPTED PRIVATE KEY`, else
  `Some(false)`.
