//! Read-only dry run over a keyrings directory.
//!
//! Usage: `cargo run -p kring-core --example scan_report -- <dir>`
//!
//! Prints per file only: name, format, size, item count, daemon readability and
//! warning counts by kind, then totals. Never labels, attributes or secrets.

use std::collections::BTreeMap;
use std::path::PathBuf;

use kring_core::keyring_file::summarize_dir;

/// Entry point: summarizes the directory given as the first argument.
fn main() {
    let Some(dir) = std::env::args().nth(1).map(PathBuf::from) else {
        eprintln!("usage: scan_report <keyrings dir>");
        std::process::exit(2);
    };
    let summaries = match summarize_dir(&dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("scan failed: {e}");
            std::process::exit(1);
        }
    };
    let mut by_format: BTreeMap<String, usize> = BTreeMap::new();
    let mut unreadable = 0;
    for s in &summaries {
        println!("{}", s.render());
        *by_format.entry(format!("{:?}", s.format)).or_default() += 1;
        if s.daemon_readable == Some(false) {
            unreadable += 1;
        }
    }
    println!(
        "total={} by_format={by_format:?} daemon_unreadable={unreadable}",
        summaries.len()
    );
}
