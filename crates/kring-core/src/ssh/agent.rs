//! Minimal ssh-agent client (draft-miller-ssh-agent) over a Unix socket.
//!
//! Messages are `u32` big-endian length + type byte + payload. Every call
//! opens a fresh blocking connection with 5 second timeouts per read or
//! write and a 10 second deadline for the whole roundtrip, and replies are
//! capped at [`MAX_MESSAGE_BYTES`], so a hostile or broken peer cannot hang
//! the caller or force a huge allocation. Replies are parsed with bounds
//! checks and never panic. Private key bytes are only held in `Zeroizing`
//! buffers. The socket path is always passed in by the caller; this module
//! never reads `SSH_AUTH_SOCK`.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use sha2::{Digest, Sha256};
use ssh_encoding::Encode;
use ssh_key::{HashAlg, PublicKey};
use zeroize::Zeroizing;

use super::ops::load_private_key;
use super::scan::{SshAlgorithm, SshKeyInfo, algorithm_of};
use crate::backup::io_err;
use crate::error::{KringError, Result};
use crate::model::SecretValue;

/// Read and write timeout of each call on an agent connection.
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Total time one request and its reply may take.
const ROUNDTRIP_DEADLINE: Duration = Duration::from_secs(10);
/// Largest agent message accepted (256 KiB).
const MAX_MESSAGE_BYTES: usize = 256 * 1024;
/// SSH_AGENT_FAILURE.
const MSG_FAILURE: u8 = 5;
/// SSH_AGENT_SUCCESS.
const MSG_SUCCESS: u8 = 6;
/// SSH2_AGENTC_REQUEST_IDENTITIES.
const MSG_REQUEST_IDENTITIES: u8 = 11;
/// SSH2_AGENT_IDENTITIES_ANSWER.
const MSG_IDENTITIES_ANSWER: u8 = 12;
/// SSH2_AGENTC_ADD_IDENTITY.
const MSG_ADD_IDENTITY: u8 = 17;
/// SSH2_AGENTC_REMOVE_IDENTITY.
const MSG_REMOVE_IDENTITY: u8 = 18;
/// SSH2_AGENTC_REMOVE_ALL_IDENTITIES.
const MSG_REMOVE_ALL: u8 = 19;
/// SSH2_AGENTC_ADD_ID_CONSTRAINED.
const MSG_ADD_ID_CONSTRAINED: u8 = 25;
/// SSH_AGENT_CONSTRAIN_LIFETIME.
const CONSTRAIN_LIFETIME: u8 = 1;
/// Smallest encoding of one identity (two empty strings).
const MIN_IDENTITY_BYTES: usize = 8;

/// A public key loaded in an ssh-agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentity {
    /// `SHA256:...` fingerprint, as shown by `ssh-add -l`.
    pub fingerprint: String,
    /// Comment stored with the key in the agent.
    pub comment: String,
    /// Key algorithm (`Other` for kinds this app does not know, e.g. certificates).
    pub algorithm: SshAlgorithm,
}

/// An identity as sent by the agent: public key blob plus comment.
struct RawIdentity {
    blob: Vec<u8>,
    comment: String,
}

/// Lists the identities loaded in the agent listening on `sock`.
pub fn list_identities(sock: &Path) -> Result<Vec<AgentIdentity>> {
    let raw = list_raw(sock)?;
    Ok(raw.into_iter().map(identity_of).collect())
}

/// Adds the private key of `info` to the agent on `sock`.
///
/// An encrypted key is decrypted in memory with `passphrase` (missing:
/// `MSG_KEY_PASSPHRASE_REQUIRED`, wrong: `MSG_WRONG_KEY_PASSPHRASE`); legacy
/// keys are refused. With `lifetime_secs` the agent drops the key after that
/// many seconds (must be greater than zero).
pub fn add_identity(
    sock: &Path,
    info: &SshKeyInfo,
    passphrase: Option<&SecretValue>,
    lifetime_secs: Option<u32>,
) -> Result<()> {
    if lifetime_secs == Some(0) {
        return Err(KringError::InvalidInput(
            "The key lifetime must be greater than zero".into(),
        ));
    }
    let key = load_private_key(info, passphrase)?;
    let request = add_request(key.key_data(), key.comment(), lifetime_secs)
        .map_err(|e| KringError::InvalidInput(format!("Cannot encode the key: {e}")))?;
    expect_success(sock, &request)
}

/// Removes the identity with `fingerprint` (`SHA256:...`) from the agent on `sock`.
///
/// Fails with `NotFound` when the agent holds no such identity.
pub fn remove_identity(sock: &Path, fingerprint: &str) -> Result<()> {
    let raw = list_raw(sock)?;
    let found = raw
        .iter()
        .find(|id| fingerprint_of(&id.blob) == fingerprint)
        .ok_or_else(|| KringError::NotFound(format!("identity {fingerprint} in the agent")))?;
    let mut request = vec![MSG_REMOVE_IDENTITY];
    put_string(&mut request, &found.blob);
    expect_success(sock, &request)
}

/// Removes every identity from the agent on `sock`.
pub fn remove_all(sock: &Path) -> Result<()> {
    expect_success(sock, &[MSG_REMOVE_ALL])
}

/// Builds an ADD_IDENTITY (or constrained) request body for `data`.
fn add_request(
    data: &ssh_key::private::KeypairData,
    comment: &str,
    lifetime_secs: Option<u32>,
) -> std::result::Result<Zeroizing<Vec<u8>>, ssh_encoding::Error> {
    let key_len = data.encoded_len()?;
    let mut out = Zeroizing::new(Vec::with_capacity(key_len + comment.len() + 16));
    out.push(match lifetime_secs {
        Some(_) => MSG_ADD_ID_CONSTRAINED,
        None => MSG_ADD_IDENTITY,
    });
    // Key type string + key specific fields, as in the OpenSSH private key format.
    data.encode(&mut *out)?;
    put_string(&mut out, comment.as_bytes());
    if let Some(secs) = lifetime_secs {
        out.push(CONSTRAIN_LIFETIME);
        out.extend_from_slice(&secs.to_be_bytes());
    }
    Ok(out)
}

/// Appends an SSH `string` (u32 length + bytes).
fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Fingerprint (`SHA256:...`) of a public key blob, also for blobs `ssh-key` cannot parse.
fn fingerprint_of(blob: &[u8]) -> String {
    match PublicKey::from_bytes(blob) {
        Ok(key) => key.fingerprint(HashAlg::Sha256).to_string(),
        Err(_) => format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob))),
    }
}

/// Converts a raw identity to the public type.
fn identity_of(raw: RawIdentity) -> AgentIdentity {
    let algorithm = match PublicKey::from_bytes(&raw.blob) {
        Ok(key) => algorithm_of(key.algorithm()),
        Err(_) => SshAlgorithm::Other(blob_type_name(&raw.blob)),
    };
    AgentIdentity {
        fingerprint: fingerprint_of(&raw.blob),
        comment: raw.comment,
        algorithm,
    }
}

/// The key type string at the start of a public key blob (empty if malformed).
fn blob_type_name(blob: &[u8]) -> String {
    let mut cursor = Cursor::new(blob);
    cursor
        .string()
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .unwrap_or_default()
}

/// Sends REQUEST_IDENTITIES and parses the answer.
fn list_raw(sock: &Path) -> Result<Vec<RawIdentity>> {
    let reply = roundtrip(sock, &[MSG_REQUEST_IDENTITIES])?;
    parse_identities(&reply).map_err(|e| io_err(sock, e))
}

/// Sends `request` and requires SSH_AGENT_SUCCESS.
fn expect_success(sock: &Path, request: &[u8]) -> Result<()> {
    let reply = roundtrip(sock, request)?;
    match reply.first() {
        Some(&MSG_SUCCESS) => Ok(()),
        Some(&MSG_FAILURE) => Err(io_err(
            sock,
            io::Error::other("the ssh-agent refused the request"),
        )),
        _ => Err(io_err(sock, bad_data("unexpected reply type"))),
    }
}

/// Opens a connection, sends one message and returns the reply (type byte included).
fn roundtrip(sock: &Path, request: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    roundtrip_within(sock, request, ROUNDTRIP_DEADLINE)
}

/// Like [`roundtrip`], failing with `TimedOut` once `total` has elapsed.
///
/// Each read and write also keeps the [`IO_TIMEOUT`] bound, so a peer that
/// sends a byte just before every per-read timeout still cannot hold the
/// caller past `total`.
fn roundtrip_within(sock: &Path, request: &[u8], total: Duration) -> Result<Zeroizing<Vec<u8>>> {
    let run = || -> io::Result<Zeroizing<Vec<u8>>> {
        let stream = UnixStream::connect(sock)?;
        let mut stream = DeadlineStream {
            stream,
            deadline: Instant::now() + total,
        };
        write_message(&mut stream, request)?;
        read_message(&mut stream)
    };
    run().map_err(|e| io_err(sock, e))
}

/// A Unix stream whose reads and writes all end by one deadline.
struct DeadlineStream {
    stream: UnixStream,
    deadline: Instant,
}

impl DeadlineStream {
    /// Time left for the next call, capped at [`IO_TIMEOUT`]; `TimedOut` when none is left.
    fn budget(&self) -> io::Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the ssh-agent did not answer in time",
            ));
        }
        Ok(left.min(IO_TIMEOUT))
    }
}

impl Read for DeadlineStream {
    /// Reads with the remaining budget as timeout.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let budget = self.budget()?;
        self.stream.set_read_timeout(Some(budget))?;
        self.stream.read(buf)
    }
}

impl Write for DeadlineStream {
    /// Writes with the remaining budget as timeout.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let budget = self.budget()?;
        self.stream.set_write_timeout(Some(budget))?;
        self.stream.write(buf)
    }

    /// Flushes the stream (a no-op for Unix sockets).
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// Writes one length-prefixed message.
fn write_message(w: &mut impl Write, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_MESSAGE_BYTES {
        return Err(bad_data("request too large"));
    }
    let mut framed = Zeroizing::new(Vec::with_capacity(body.len() + 4));
    framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
    framed.extend_from_slice(body);
    w.write_all(&framed)?;
    w.flush()
}

/// Reads one length-prefixed message; empty and oversized messages are errors.
fn read_message(r: &mut impl Read) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_MESSAGE_BYTES {
        return Err(bad_data("invalid reply length"));
    }
    let mut body = Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut body)?;
    Ok(body)
}

/// Parses an IDENTITIES_ANSWER message (type byte included).
fn parse_identities(msg: &[u8]) -> io::Result<Vec<RawIdentity>> {
    let mut cursor = Cursor::new(msg);
    match cursor.u8()? {
        MSG_IDENTITIES_ANSWER => {}
        MSG_FAILURE => return Err(io::Error::other("the ssh-agent refused the request")),
        _ => return Err(bad_data("unexpected reply type")),
    }
    let count = cursor.u32()? as usize;
    // Each identity takes at least 8 bytes: reject counts the message cannot hold.
    if count > cursor.remaining() / MIN_IDENTITY_BYTES {
        return Err(bad_data("identity count exceeds the message size"));
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let blob = cursor.string()?.to_vec();
        let comment = String::from_utf8_lossy(cursor.string()?).into_owned();
        out.push(RawIdentity { blob, comment });
    }
    Ok(out)
}

/// Error for a malformed message.
fn bad_data(msg: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("bad ssh-agent message: {msg}"),
    )
}

/// Bounds-checked reader over a message.
struct Cursor<'a> {
    data: &'a [u8],
}

impl<'a> Cursor<'a> {
    /// Starts reading at the beginning of `data`.
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Bytes not read yet.
    fn remaining(&self) -> usize {
        self.data.len()
    }

    /// Takes the next `n` bytes or fails when the message is truncated.
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if n > self.data.len() {
            return Err(bad_data("truncated"));
        }
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        Ok(head)
    }

    /// Reads one byte.
    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Reads a big-endian `u32`.
    fn u32(&mut self) -> io::Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads an SSH `string`.
    fn string(&mut self) -> io::Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an IDENTITIES_ANSWER with the given declared count and raw entries.
    fn answer(count: u32, entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut msg = vec![MSG_IDENTITIES_ANSWER];
        msg.extend_from_slice(&count.to_be_bytes());
        for (blob, comment) in entries {
            put_string(&mut msg, blob);
            put_string(&mut msg, comment);
        }
        msg
    }

    /// Messages are framed with a big-endian length and read back unchanged.
    #[test]
    fn framing_roundtrip() {
        let mut wire = Vec::new();
        write_message(&mut wire, &[MSG_REMOVE_ALL]).unwrap();
        assert_eq!(wire, [0, 0, 0, 1, MSG_REMOVE_ALL]);
        let body = read_message(&mut wire.as_slice()).unwrap();
        assert_eq!(body.as_slice(), [MSG_REMOVE_ALL]);
    }

    /// Zero, oversized and truncated frames are errors, never panics or big allocations.
    #[test]
    fn bad_frames_are_errors() {
        let zero = [0u8; 4];
        assert!(read_message(&mut zero.as_slice()).is_err());
        let huge = u32::MAX.to_be_bytes();
        assert!(read_message(&mut huge.as_slice()).is_err());
        let over = ((MAX_MESSAGE_BYTES + 1) as u32).to_be_bytes();
        assert!(read_message(&mut over.as_slice()).is_err());
        assert!(read_message(&mut [0u8, 0].as_slice()).is_err());
        assert!(read_message(&mut [0u8, 0, 0, 9, 1].as_slice()).is_err());
        assert!(write_message(&mut Vec::new(), &vec![0; MAX_MESSAGE_BYTES + 1]).is_err());
    }

    /// A well formed answer parses, including unparseable blobs.
    #[test]
    fn parses_identities() {
        let msg = answer(1, &[(b"\0\0\0\x04abcd", b"me")]);
        let ids = parse_identities(&msg).unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].comment, "me");
        let id = identity_of(RawIdentity {
            blob: ids[0].blob.clone(),
            comment: "me".into(),
        });
        assert!(id.fingerprint.starts_with("SHA256:"));
        assert_eq!(id.algorithm, SshAlgorithm::Other("abcd".into()));
    }

    /// Malformed answers are errors and never panic.
    #[test]
    fn malformed_answers_do_not_panic() {
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![MSG_IDENTITIES_ANSWER],
            vec![MSG_IDENTITIES_ANSWER, 0, 0],
            vec![MSG_SUCCESS],
            vec![MSG_FAILURE],
            answer(u32::MAX, &[]),
            answer(2, &[(b"a", b"b")]),
            vec![
                MSG_IDENTITIES_ANSWER,
                0,
                0,
                0,
                1,
                0xff,
                0xff,
                0xff,
                0xff,
                0,
                0,
                0,
                0,
            ],
            vec![MSG_IDENTITIES_ANSWER, 0, 0, 0, 1, 0, 0, 0, 5, 1, 2],
        ];
        for case in cases {
            assert!(parse_identities(&case).is_err(), "{case:?}");
        }
        assert!(parse_identities(&answer(0, &[])).unwrap().is_empty());
    }

    /// A peer dripping its reply byte by byte cannot hold a roundtrip past the total deadline.
    #[test]
    fn dripping_peer_hits_the_total_deadline() {
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("drip.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = [0u8; 16];
            let _ = conn.read(&mut buf);
            // Declares 64 bytes, then sends one every 100 ms (well under the
            // per-read timeout), for longer than the total deadline.
            let _ = conn.write_all(&[0, 0, 0, 64]);
            for _ in 0..40 {
                std::thread::sleep(Duration::from_millis(100));
                if conn.write_all(&[0]).is_err() {
                    break;
                }
            }
        });
        let started = std::time::Instant::now();
        let result = roundtrip_within(&sock, &[MSG_REQUEST_IDENTITIES], Duration::from_millis(800));
        let elapsed = started.elapsed();
        assert!(result.is_err());
        assert!(elapsed < Duration::from_secs(3), "took {elapsed:?}");
        server.join().unwrap();
    }

    /// A constrained request carries the lifetime constraint after the comment.
    #[test]
    fn constrained_request_layout() {
        let key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let plain = add_request(key.key_data(), "c", None).unwrap();
        let limited = add_request(key.key_data(), "c", Some(300)).unwrap();
        assert_eq!(plain[0], MSG_ADD_IDENTITY);
        assert_eq!(limited[0], MSG_ADD_ID_CONSTRAINED);
        assert_eq!(&plain[1..], &limited[1..limited.len() - 5]);
        assert_eq!(&limited[limited.len() - 5..], [1, 0, 0, 1, 44]);
    }
}
