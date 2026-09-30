//! Local petname address book (ADR-0001 overlay).
//!
//! A user assigns a human-readable alias to a known `PeerId` and sees it
//! everywhere that peer appears, while the full `PeerId` is always still
//! displayed beside the alias so an unverified name can never impersonate
//! an identity. Peers without an alias display by short `PeerId`.
//!
//! Aliases are per-node local state only: they live in `peers.json` inside
//! the node data directory and are never broadcast, replicated, or trusted
//! from the network. Aliases never substitute for identity: no function
//! here (and no CLI command) resolves an alias back to a `PeerId`.

use crate::fs_secure::{ensure_parent_dir, sibling_path, write_secure};
use crate::peer::{peer_id_base58, peer_id_from_cid};
use libp2p_identity::PeerId;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

/// The longest alias accepted, in characters. Long enough for
/// `alice-laptop`, short enough to display beside a PeerId.
const MAX_ALIAS_LEN: usize = 64;

/// Parse text that must be a `PeerId` (base58 `12D3Koo…` or CID `bafz…`).
///
/// Anything else — including a petname alias — is rejected with
/// `InvalidData`, so an alias can never be passed where identity is
/// required.
pub fn parse_peer_id(text: &str) -> io::Result<PeerId> {
    let trimmed = text.trim();
    if let Ok(id) = trimmed.parse::<PeerId>() {
        return Ok(id);
    }
    if let Ok(id) = peer_id_from_cid(trimmed) {
        return Ok(id);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("not a peer ID: {text}"),
    ))
}

/// Validate a petname alias, returning it unchanged when valid.
///
/// Rejects blank names, names with leading or trailing whitespace, names
/// over 64 characters, names containing control characters, and names
/// that parse as a `PeerId` (an alias must never be confusable with
/// identity).
pub fn validate_alias(alias: &str) -> io::Result<String> {
    let invalid = |why: &str| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("not a valid alias: {why}"),
        )
    };
    if alias.is_empty() {
        return Err(invalid("alias is empty"));
    }
    if alias != alias.trim() {
        return Err(invalid("alias has leading or trailing whitespace"));
    }
    if alias.chars().count() > MAX_ALIAS_LEN {
        return Err(invalid("alias is longer than 64 characters"));
    }
    if alias.chars().any(|c| c.is_control()) {
        return Err(invalid("alias contains a control character"));
    }
    if alias.parse::<PeerId>().is_ok() || peer_id_from_cid(alias).is_ok() {
        return Err(invalid("alias must not look like a peer ID"));
    }
    Ok(alias.to_string())
}

/// The short `PeerId` for display: first 10 plus last 6 base58 characters.
/// Shown beside every alias so the identity is always visible.
pub fn short_peer_id(id: &PeerId) -> String {
    // Base58 is ASCII, so byte slicing on character boundaries is safe.
    let full = peer_id_base58(id);
    if full.len() <= 16 {
        return full;
    }
    format!("{}…{}", &full[..10], &full[full.len() - 6..])
}

/// Display text for a peer: `alias (short)` when known, short `PeerId`
/// only when unknown. The alias is never shown without the `PeerId`.
pub fn display_peer(alias: Option<&str>, id: &PeerId) -> String {
    let short = short_peer_id(id);
    match alias {
        Some(name) => format!("{name} ({short})"),
        None => short,
    }
}

/// Read every known `PeerId → alias` pair. A missing file means no aliases
/// yet; malformed content is an `InvalidData` error, never silently
/// ignored.
pub fn aliases(path: &Path) -> io::Result<BTreeMap<PeerId, String>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(e),
    };
    let raw: BTreeMap<String, String> = serde_json::from_slice(&bytes).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("peers file is not a valid address book: {e}"),
        )
    })?;
    let mut book = BTreeMap::new();
    for (key, name) in raw {
        let id = parse_peer_id(&key).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("peers file holds an invalid peer ID: {key}"),
            )
        })?;
        let alias = validate_alias(&name).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("peers file holds an invalid alias for {key}"),
            )
        })?;
        book.insert(id, alias);
    }
    Ok(book)
}

/// Store (or update) the local alias for a `PeerId`.
///
/// The alias is validated before anything is touched, so a rejected name
/// creates no file and leaves existing state intact. The read-modify-write
/// holds a sibling `.lock`, so concurrent `peer add` calls serialize and
/// every alias survives.
pub fn set_alias(path: &Path, id: &PeerId, alias: &str) -> io::Result<()> {
    let name = validate_alias(alias)?;
    let lock_path = sibling_path(path, "lock");
    ensure_parent_dir(&lock_path)?;
    let lock = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    fs2::FileExt::lock_exclusive(&lock)?;
    let outcome = (|| -> io::Result<()> {
        let mut book = aliases(path)?;
        book.insert(*id, name);
        let raw: BTreeMap<String, String> = book
            .into_iter()
            .map(|(id, alias)| (peer_id_base58(&id), alias))
            .collect();
        let bytes = serde_json::to_vec_pretty(&raw)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_secure(path, &bytes)
    })();
    let _ = fs2::FileExt::unlock(&lock);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate, peer_id, peer_id_base58, peer_id_cid};

    /// The fixture identity from `tests/fixtures/identity.key`:
    /// base58 `12D3KooWDrFGgb3hRZL5X9eXFPzbK1629hHR2Xv3z1gAkiED9Hcn`.
    fn fixture_id() -> PeerId {
        "12D3KooWDrFGgb3hRZL5X9eXFPzbK1629hHR2Xv3z1gAkiED9Hcn"
            .parse()
            .unwrap()
    }

    fn peers_file_in(dir: &tempfile::TempDir) -> std::path::PathBuf {
        dir.path().join("peers.json")
    }

    #[test]
    fn alias_round_trips_through_peers_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = peers_file_in(&dir);
        let alice = peer_id(&generate());
        let bob = peer_id(&generate());
        set_alias(&file, &alice, "alice").unwrap();
        set_alias(&file, &bob, "bob").unwrap();
        let loaded = aliases(&file).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.get(&alice).map(String::as_str), Some("alice"));
        assert_eq!(loaded.get(&bob).map(String::as_str), Some("bob"));
    }

    #[test]
    fn missing_peers_file_lists_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(aliases(&peers_file_in(&dir)).unwrap().is_empty());
    }

    #[test]
    fn set_alias_rejects_bad_names_without_touching_state() {
        let id = fixture_id();
        let bad = [
            "",
            "   ",
            "\talice\n",
            &"a".repeat(65),
            "ali\nce",
            "ali\x07ce",
            // An alias must never be confusable with identity.
            "12D3KooWDrFGgb3hRZL5X9eXFPzbK1629hHR2Xv3z1gAkiED9Hcn",
        ];
        for alias in bad {
            let dir = tempfile::tempdir().unwrap();
            let file = peers_file_in(&dir);
            let err = set_alias(&file, &id, alias).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "alias: {alias:?}");
            assert!(!file.exists(), "rejected alias must not create state");
        }
        // Rejection also leaves existing state intact.
        let dir = tempfile::tempdir().unwrap();
        let file = peers_file_in(&dir);
        set_alias(&file, &id, "alice").unwrap();
        let before = std::fs::read(&file).unwrap();
        for alias in ["", &"b".repeat(100)] {
            let err = set_alias(&file, &id, alias).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }
        assert_eq!(std::fs::read(&file).unwrap(), before);
        assert_eq!(
            aliases(&file).unwrap().get(&id).map(String::as_str),
            Some("alice")
        );
    }

    #[test]
    fn set_alias_updates_the_existing_alias() {
        let dir = tempfile::tempdir().unwrap();
        let file = peers_file_in(&dir);
        let id = fixture_id();
        set_alias(&file, &id, "alice").unwrap();
        set_alias(&file, &id, "alice-laptop").unwrap();
        let loaded = aliases(&file).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.get(&id).map(String::as_str), Some("alice-laptop"));
    }

    #[test]
    fn same_alias_for_two_peers_is_allowed_but_peer_id_disambiguates() {
        let dir = tempfile::tempdir().unwrap();
        let file = peers_file_in(&dir);
        let a = peer_id(&generate());
        let b = peer_id(&generate());
        set_alias(&file, &a, "sam").unwrap();
        set_alias(&file, &b, "sam").unwrap();
        assert_eq!(aliases(&file).unwrap().len(), 2);
        // The shared alias still displays beside distinct PeerIds.
        assert_ne!(display_peer(Some("sam"), &a), display_peer(Some("sam"), &b));
    }

    #[test]
    fn parse_peer_id_accepts_both_text_forms_and_rejects_aliases() {
        // Golden vectors, pinned from the fixture identity.
        let base58 = "12D3KooWDrFGgb3hRZL5X9eXFPzbK1629hHR2Xv3z1gAkiED9Hcn";
        let cid = "bafzaajaiaejcao7kdq2ip4qww43y45n3thbczbmf6dtoat7pfg3og26qbgn5hlb3";
        assert_eq!(parse_peer_id(base58).unwrap(), fixture_id());
        assert_eq!(parse_peer_id(cid).unwrap(), fixture_id());
        for bad in ["", "alice", "!!!not-a-peer!!!", "12D3KooWDr"] {
            let err = parse_peer_id(bad).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "input: {bad:?}");
            assert!(
                err.to_string().contains("not a peer ID"),
                "clear error, got: {err}"
            );
        }
    }

    #[test]
    fn display_format_is_alias_plus_short_peer_id_together() {
        let id = fixture_id();
        let short = short_peer_id(&id);
        assert_eq!(short, "12D3KooWDr…ED9Hcn");
        assert_eq!(
            display_peer(Some("alice"), &id),
            "alice (12D3KooWDr…ED9Hcn)"
        );
        // Unknown peers show the short PeerId only — never a bare alias.
        assert_eq!(display_peer(None, &id), "12D3KooWDr…ED9Hcn");
        let shown = display_peer(Some("alice"), &id);
        assert!(shown.contains("alice"), "alias must be shown");
        assert!(
            shown.contains(&short),
            "PeerId must always sit beside the alias"
        );
    }

    #[test]
    fn display_short_matches_generated_peer_ids() {
        let id = peer_id(&generate());
        let base58 = peer_id_base58(&id);
        let short = short_peer_id(&id);
        assert!(short.contains('…'), "long ids must be shortened: {short}");
        assert!(
            base58.starts_with(&short[..10]),
            "short keeps the id prefix"
        );
        assert!(
            base58.ends_with(&short[short.len() - 6..]),
            "short keeps the id suffix"
        );
        let _ = peer_id_cid(&id);
    }

    #[test]
    fn malformed_peers_file_fails_loudly() {
        let dir = tempfile::tempdir().unwrap();
        let file = peers_file_in(&dir);
        for bad in [
            "not json at all {{{",
            "[1, 2, 3]",
            "{\"alice\": \"bob\"}",
            "{\"12D3KooWDr\": \"truncated\"}",
        ] {
            std::fs::write(&file, bad).unwrap();
            let err = aliases(&file).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "input: {bad:?}");
        }
    }

    #[test]
    fn concurrent_adds_keep_every_alias() {
        let dir = tempfile::tempdir().unwrap();
        let file = peers_file_in(&dir);
        let ids: Vec<PeerId> = (0..8).map(|_| peer_id(&generate())).collect();
        std::thread::scope(|s| {
            for (i, id) in ids.iter().enumerate() {
                let file = &file;
                s.spawn(move || set_alias(file, id, &format!("peer-{i}")).unwrap());
            }
        });
        let loaded = aliases(&file).unwrap();
        assert_eq!(loaded.len(), 8);
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(
                loaded.get(id).map(String::as_str),
                Some(format!("peer-{i}").as_str())
            );
        }
    }
}
