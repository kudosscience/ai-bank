//! CLI seam: `clawbank peer add` / `clawbank peer list` petname book.
//! Each test owns an isolated home dir via CLAWBANK_HOME on the child
//! process only, so tests never touch the real profile and never race.

use std::process::{Command, Stdio};

use clawbank_identity::short_peer_id;

fn home() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

struct CliOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

fn run_cli(home: &tempfile::TempDir, args: &[&str], stdin: Option<&str>) -> CliOutput {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_clawbank"));
    cmd.env("CLAWBANK_HOME", home.path()).args(args);
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    if let Some(input) = stdin {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    CliOutput {
        success: out.status.success(),
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

fn output_value(stdout: &str, label: &str) -> String {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix(label))
        .unwrap()
        .to_string()
}

/// A fresh PeerId from `init` in this home: (base58, CID).
fn fresh_peer_id(home: &tempfile::TempDir) -> (String, String) {
    let out = run_cli(home, &["init"], None);
    assert!(out.success, "init must succeed: {}", out.stderr);
    (
        output_value(&out.stdout, "Peer ID (base58): "),
        output_value(&out.stdout, "Peer ID (CID): "),
    )
}

fn short_of(base58: &str) -> String {
    // Single source of truth: the library's display helper, not a reprint.
    short_peer_id(&base58.parse().unwrap())
}

#[test]
fn peer_list_starts_empty() {
    let home = home();
    let out = run_cli(&home, &["peer", "list"], None);
    assert!(out.success, "list must succeed: {}", out.stderr);
    assert!(out.stdout.trim().is_empty(), "fresh book lists nothing");
}

#[test]
fn peer_add_then_list_shows_alias_with_peer_id() {
    let home = home();
    let (id, _) = fresh_peer_id(&home);
    let short = short_of(&id);

    let add = run_cli(&home, &["peer", "add", &id, "alice"], None);
    assert!(add.success, "add must succeed: {}", add.stderr);
    assert!(add.stdout.contains("alice"), "add echoes the alias");
    assert!(add.stdout.contains(&short), "add echoes the PeerId");
    assert!(add.stdout.contains(&id), "full PeerId is always shown");

    let list = run_cli(&home, &["peer", "list"], None);
    assert!(list.success, "list must succeed: {}", list.stderr);
    let lines: Vec<&str> = list.stdout.lines().collect();
    assert_eq!(lines.len(), 1, "one known peer, got: {}", list.stdout);
    assert!(lines[0].contains("alice"), "alias shown: {}", lines[0]);
    assert!(lines[0].contains(&short), "short PeerId beside alias");
    assert!(lines[0].contains(&id), "full PeerId beside alias");
    // Anti-phishing: the alias never appears on a line without the PeerId.
    for line in lines.iter().filter(|l| l.contains("alice")) {
        assert!(line.contains(&short), "alias without PeerId: {line}");
    }
}

#[test]
fn peer_add_rejects_alias_where_peer_id_is_required() {
    let home = home();
    let out = run_cli(&home, &["peer", "add", "alice", "bob"], None);
    assert!(!out.success, "an alias is not identity and must fail");
    assert!(
        out.stderr.contains("not a peer ID"),
        "clear error, got: {}",
        out.stderr
    );
    // Failed add stores nothing.
    let list = run_cli(&home, &["peer", "list"], None);
    assert!(list.success);
    assert!(list.stdout.trim().is_empty());
    assert!(!home.path().join("peers.json").exists());
}

#[test]
fn peer_add_rejects_bad_alias() {
    let home = home();
    let (id, _) = fresh_peer_id(&home);
    for bad in ["", &"a".repeat(65)] {
        let out = run_cli(&home, &["peer", "add", &id, bad], None);
        assert!(!out.success, "bad alias must fail: {bad:?}");
        assert!(
            out.stderr.contains("not a valid alias"),
            "clear error, got: {}",
            out.stderr
        );
    }
    // The alias must never be confusable with identity.
    let out = run_cli(&home, &["peer", "add", &id, &id], None);
    assert!(!out.success);
    assert!(out.stderr.contains("not a valid alias"));
}

#[test]
fn peer_add_updates_the_alias() {
    let home = home();
    let (id, _) = fresh_peer_id(&home);
    assert!(run_cli(&home, &["peer", "add", &id, "alice"], None).success);
    assert!(run_cli(&home, &["peer", "add", &id, "bob"], None).success);
    let list = run_cli(&home, &["peer", "list"], None);
    assert!(list.success);
    assert_eq!(list.stdout.lines().count(), 1, "update, not a duplicate");
    assert!(
        list.stdout.contains("bob ("),
        "new alias shown: {}",
        list.stdout
    );
    assert!(
        !list.stdout.contains("alice ("),
        "old alias gone: {}",
        list.stdout
    );
}

#[test]
fn peer_list_shows_every_known_peer() {
    let home = home();
    let (first, _) = fresh_peer_id(&home);
    let guest = tempfile::tempdir().unwrap();
    let (second, _) = fresh_peer_id(&guest);
    assert!(run_cli(&home, &["peer", "add", &first, "first"], None).success);
    assert!(run_cli(&home, &["peer", "add", &second, "second"], None).success);
    let list = run_cli(&home, &["peer", "list"], None);
    assert!(list.success);
    assert_eq!(list.stdout.lines().count(), 2, "got: {}", list.stdout);
    assert!(list.stdout.contains(&first));
    assert!(list.stdout.contains(&second));
}

#[test]
fn aliases_are_local_to_each_home() {
    let home_a = home();
    let (id, _) = fresh_peer_id(&home_a);
    assert!(run_cli(&home_a, &["peer", "add", &id, "alice"], None).success);

    // A second node sees none of the first node's aliases: nothing about
    // them is broadcast, replicated, or trusted from the network.
    let home_b = home();
    let list = run_cli(&home_b, &["peer", "list"], None);
    assert!(list.success);
    assert!(list.stdout.trim().is_empty(), "aliases stay local");
}

#[test]
fn peer_add_accepts_cid_form_and_stores_base58() {
    let home = home();
    let (id, cid) = fresh_peer_id(&home);
    let add = run_cli(&home, &["peer", "add", &cid, "alice"], None);
    assert!(add.success, "CID names the same identity: {}", add.stderr);
    let list = run_cli(&home, &["peer", "list"], None);
    assert!(list.success);
    assert!(
        list.stdout.contains(&id),
        "stored canonically: {}",
        list.stdout
    );
}
