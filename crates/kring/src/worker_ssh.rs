//! Worker handlers for SSH keys ([`WorkerConfig::ssh_dir`]) and the ssh-agent
//! ([`WorkerConfig::ssh_agent_sock`]).
//!
//! Keys are addressed by name only: every command resolves the name in a
//! fresh scan of the SSH directory, never from a path sent by the UI (only
//! the import source and the export destination are paths, chosen by the
//! user). None of these commands needs a Secret Service.
//!
//! Key passphrase errors are [`Event::Error`] with exactly
//! [`kring_core::ssh::MSG_KEY_PASSPHRASE_REQUIRED`] or
//! [`kring_core::ssh::MSG_WRONG_KEY_PASSPHRASE`] (the UI reopens its
//! dialog). A missing backup passphrase (an unencrypted private key is
//! backed up age-encrypted) is answered with the passphrase-free echo of
//! [`passphrase_echo`]. An unreachable agent is reported as
//! [`AgentStatus::Unavailable`]; only commands that change the agent also
//! report an error.

use std::path::Path;

use kring_core::backup::BackupInfo;
use kring_core::ssh::{
    AgentIdentity, SshKeyInfo, add_identity, change_passphrase, delete_key, export_private,
    export_public, generate_key, import_key, list_identities, remove_all, remove_identity,
    scan_keys,
};
use kring_core::{KringError, Result};

use crate::worker::{Command, Emitter, Event, WorkerConfig, passphrase_echo};

/// Reason shown when no agent socket is configured.
pub(crate) const MSG_NO_AGENT: &str = "No ssh-agent: SSH_AUTH_SOCK is not set";
/// Error of a key command without an SSH directory (HOME unset).
pub const MSG_NO_SSH_DIR: &str = "No SSH key directory: HOME is not set";
/// Prefix of the error of a failed rescan after a successful change.
pub(crate) const MSG_RESCAN_FAILED: &str = "Cannot rescan the SSH keys";

/// What the ssh-agent holds, or why it cannot be asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentStatus {
    /// The agent answered with these identities.
    Available(Vec<AgentIdentity>),
    /// The agent cannot be reached (no socket configured, or the connection failed).
    Unavailable(String),
}

/// Returns true for commands handled by this module.
pub(crate) fn is_ssh(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::ScanSshKeys
            | Command::GenerateSshKey(_)
            | Command::ImportSshKey { .. }
            | Command::ReadSshPublicKey { .. }
            | Command::ExportSshPrivate { .. }
            | Command::ChangeSshPassphrase { .. }
            | Command::DeleteSshKey { .. }
            | Command::AgentList
            | Command::AgentAdd { .. }
            | Command::AgentRemove { .. }
            | Command::AgentRemoveAll
    )
}

/// Handles one SSH command, reporting failures as [`Event::Error`].
pub(crate) fn handle<N: Fn()>(out: &Emitter<N>, config: &WorkerConfig, cmd: &Command) {
    match cmd {
        Command::AgentList => emit_agent(out, config),
        Command::AgentAdd { .. } | Command::AgentRemove { .. } | Command::AgentRemoveAll => {
            run_agent(out, config, cmd)
        }
        _ => {
            if let Err(e) = run_key(out, config, cmd) {
                report(out, cmd, &e);
            }
        }
    }
}

/// Reports a failed key command: a missing backup passphrase as the echo
/// of `cmd`, anything else as an error.
fn report<N: Fn()>(out: &Emitter<N>, cmd: &Command, e: &KringError) {
    match e {
        KringError::PassphraseRequired => out.emit(passphrase_echo(cmd)),
        other => out.error(message(other)),
    }
}

/// Returns the text of an error: `InvalidInput` messages as they are (the
/// shared passphrase texts), anything else with its kind.
fn message(e: &KringError) -> String {
    match e {
        KringError::InvalidInput(m) => m.clone(),
        other => other.to_string(),
    }
}

/// Builds an `InvalidInput` error.
fn invalid(message: impl Into<String>) -> KringError {
    KringError::InvalidInput(message.into())
}

/// Returns the SSH directory, or [`MSG_NO_SSH_DIR`] when there is none.
fn ssh_dir(config: &WorkerConfig) -> Result<&Path> {
    config
        .ssh_dir
        .as_deref()
        .ok_or_else(|| invalid(MSG_NO_SSH_DIR))
}

/// Resolves key `name` in a fresh scan of the SSH directory.
///
/// Names with a `/`, empty names, `.` and `..` are refused before the scan;
/// the scanner never lists non-key files such as `authorized_keys`.
fn resolve_key(config: &WorkerConfig, name: &str) -> Result<SshKeyInfo> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(invalid("Invalid SSH key name"));
    }
    scan_keys(ssh_dir(config)?)?
        .into_iter()
        .find(|k| k.name == name)
        .ok_or_else(|| invalid(format!("No SSH key named '{name}'")))
}

/// Scans the SSH directory and emits [`Event::SshKeys`]; without a
/// directory (HOME unset) the list is empty (the UI says why).
fn emit_keys<N: Fn()>(out: &Emitter<N>, config: &WorkerConfig) -> Result<()> {
    let keys = match &config.ssh_dir {
        Some(dir) => scan_keys(dir)?,
        None => Vec::new(),
    };
    out.emit(Event::SshKeys(keys));
    Ok(())
}

/// Reports a finished change: the backup, a rescan of the keys, then
/// `Done`. The change happened even when the rescan fails: its error is
/// reported on its own and `Done` still follows.
pub(crate) fn finish<N: Fn()>(
    out: &Emitter<N>,
    config: &WorkerConfig,
    backup: Option<BackupInfo>,
    done: String,
) {
    if let Some(info) = backup {
        out.emit(Event::BackupCreated(info));
    }
    if let Err(e) = emit_keys(out, config) {
        out.error(format!("{MSG_RESCAN_FAILED}: {}", message(&e)));
    }
    out.emit(Event::Done(done));
}

/// Executes a key command.
fn run_key<N: Fn()>(out: &Emitter<N>, config: &WorkerConfig, cmd: &Command) -> Result<()> {
    if matches!(cmd, Command::ScanSshKeys) {
        return emit_keys(out, config);
    }
    let dir = ssh_dir(config)?;
    match cmd {
        Command::GenerateSshKey(key) => {
            let info = generate_key(dir, key)?;
            finish(out, config, None, format!("Key '{}' created", info.name));
            Ok(())
        }
        Command::ImportSshKey { source, name } => {
            let info = import_key(dir, source, name.as_deref())?;
            finish(out, config, None, format!("Key '{}' imported", info.name));
            Ok(())
        }
        Command::ReadSshPublicKey { name } => {
            let info = resolve_key(config, name)?;
            let text = export_public(&info)?;
            out.emit(Event::SshPublicKey {
                name: info.name,
                text,
            });
            Ok(())
        }
        Command::ExportSshPrivate {
            name,
            dest,
            passphrase,
            new_passphrase,
        } => {
            let info = resolve_key(config, name)?;
            export_private(&info, dest, passphrase.as_ref(), new_passphrase.as_ref())?;
            out.emit(Event::Done(exported_message(dest)));
            Ok(())
        }
        Command::ChangeSshPassphrase {
            name,
            old,
            new,
            allow_unencrypted,
            backup_passphrase,
        } => {
            let info = resolve_key(config, name)?;
            let backup = change_passphrase(
                &config.backups,
                dir,
                &info,
                old.as_ref(),
                new.as_ref(),
                *allow_unencrypted,
                backup_passphrase.as_ref(),
            )?;
            let what = match new {
                Some(_) => "Passphrase changed",
                None => "Passphrase removed",
            };
            let done = format!("{what}, backup in {}", backup.dir.display());
            finish(out, config, Some(backup), done);
            Ok(())
        }
        Command::DeleteSshKey {
            name,
            backup_passphrase,
        } => {
            let info = resolve_key(config, name)?;
            let backup = delete_key(&config.backups, dir, &info, backup_passphrase.as_ref())?;
            let done = format!("Key '{name}' deleted, backup in {}", backup.dir.display());
            finish(out, config, Some(backup), done);
            Ok(())
        }
        _ => Err(invalid("Command sent to the SSH key path")),
    }
}

/// Success message of a private key export.
fn exported_message(dest: &Path) -> String {
    format!("Private key exported to {}", dest.display())
}

/// Lists the agent identities and emits [`Event::AgentIdentities`]; an
/// unreachable agent is [`AgentStatus::Unavailable`], never an error.
fn emit_agent<N: Fn()>(out: &Emitter<N>, config: &WorkerConfig) {
    let status = match &config.ssh_agent_sock {
        None => AgentStatus::Unavailable(MSG_NO_AGENT.into()),
        Some(sock) => match list_identities(sock) {
            Ok(ids) => AgentStatus::Available(ids),
            Err(e) => AgentStatus::Unavailable(e.to_string()),
        },
    };
    out.emit(Event::AgentIdentities(status));
}

/// Runs an agent change, then re-lists the agent (also after a failure).
///
/// Without a socket the agent is reported unavailable together with one
/// error, since the user asked for a change that cannot happen.
fn run_agent<N: Fn()>(out: &Emitter<N>, config: &WorkerConfig, cmd: &Command) {
    let Some(sock) = &config.ssh_agent_sock else {
        out.emit(Event::AgentIdentities(AgentStatus::Unavailable(
            MSG_NO_AGENT.into(),
        )));
        return out.error(MSG_NO_AGENT);
    };
    match change_agent(config, sock, cmd) {
        Ok(done) => {
            emit_agent(out, config);
            out.emit(Event::Done(done));
        }
        Err(e) => {
            out.error(message(&e));
            emit_agent(out, config);
        }
    }
}

/// Executes an agent change on `sock`, returning the `Done` message.
fn change_agent(config: &WorkerConfig, sock: &Path, cmd: &Command) -> Result<String> {
    match cmd {
        Command::AgentAdd {
            name,
            passphrase,
            lifetime_secs,
        } => {
            let info = resolve_key(config, name)?;
            add_identity(sock, &info, passphrase.as_ref(), *lifetime_secs)?;
            Ok(format!("Key '{}' added to the agent", info.name))
        }
        Command::AgentRemove { fingerprint } => {
            remove_identity(sock, fingerprint)?;
            Ok("Identity removed from the agent".into())
        }
        Command::AgentRemoveAll => {
            remove_all(sock)?;
            Ok("All identities removed from the agent".into())
        }
        _ => Err(invalid("Command sent to the agent path")),
    }
}

#[cfg(test)]
mod tests;
