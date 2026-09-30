//! Node identity: Ed25519 keypair to libp2p PeerId (ADR-0001).
//!
//! The public key is the identity. Keys are generated locally and persisted
//! as protobuf. They leave the machine only as an explicit operator backup:
//! [`export`] encodes the keypair as portable text for offline storage and
//! [`import`] restores it. Treat an export like the identity file itself —
//! anyone holding it owns the PeerId.

mod fs_secure;
mod paths;
mod peer;
mod petname;
mod sign;

pub use libp2p_identity::{Keypair, PeerId, PublicKey};
pub use paths::{data_dir, identity_file, peers_file};
pub use peer::{peer_id, peer_id_base58, peer_id_cid, peer_id_from_cid};
pub use petname::{aliases, display_peer, parse_peer_id, set_alias, short_peer_id, validate_alias};
pub use sign::{sign, sign_with_domain, signing_bytes, verify, verify_with_domain, BANK_DOMAIN};

use fs_secure::{ensure_parent_dir, needs_perm_repair, sibling_path, write_secure};
use std::fs;
use std::io;
use std::path::Path;

/// Generate a fresh Ed25519 node keypair from the OS random source.
pub fn generate() -> Keypair {
    Keypair::generate_ed25519()
}

/// Persist a keypair as protobuf. See `fs_secure` for permissions.
pub fn save(keypair: &Keypair, path: &Path) -> io::Result<()> {
    let bytes = keypair
        .to_protobuf_encoding()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_secure(path, &bytes)
}

/// Export a keypair as portable text for offline backup.
///
/// The output is base64 of the same protobuf bytes [`save`] persists,
/// so it round-trips byte-identically through [`import`]. Keep it secret:
/// anyone holding it owns the PeerId. Lose both the identity file and
/// this export and the PeerId is unrecoverable by design (ADR-0001).
pub fn export(keypair: &Keypair) -> io::Result<String> {
    let bytes = keypair
        .to_protobuf_encoding()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(data_encoding::BASE64.encode(&bytes))
}

/// Restore a keypair from [`export`] text and persist it to `path`.
///
/// The export is fully validated (base64 plus protobuf plus key shape)
/// before anything is written, so malformed or truncated material fails
/// with `InvalidData` and leaves any existing identity file untouched.
/// Publishing takes the same sibling `.lock` as [`load_or_generate`],
/// so a concurrent first-run `init` cannot interleave a generate between
/// validation and save: every writer publishes one complete file.
/// (Concurrent writers with different keys still last-writer-wins; each
/// call returns the keypair it published.)
pub fn import(exported: &str, path: &Path) -> io::Result<Keypair> {
    let trimmed = exported.trim();
    let bytes = data_encoding::BASE64
        .decode(trimmed.as_bytes())
        .map_err(invalid_export)?;
    let keypair = Keypair::from_protobuf_encoding(&bytes).map_err(invalid_export)?;
    let lock_path = sibling_path(path, "lock");
    ensure_parent_dir(&lock_path)?;
    let lock = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    fs2::FileExt::lock_exclusive(&lock)?;
    let outcome = save(&keypair, path).map(|()| keypair);
    let _ = fs2::FileExt::unlock(&lock);
    outcome
}

fn invalid_export(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("not a valid identity export: {e}"),
    )
}

/// Load a keypair persisted with [`save`]. A missing file is an error;
/// see [`load_or_generate`] for first-run behavior.
pub fn load(path: &Path) -> io::Result<Keypair> {
    let bytes = fs::read(path)?;
    Keypair::from_protobuf_encoding(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Load the identity at `path`, generating and persisting a fresh one
/// when no file exists yet. Generation failures and corrupt files are
/// errors; only a missing file triggers generation.
///
/// First-run creation holds an inter-process lock on a sibling `.lock`
/// file, so concurrent `init` processes serialize: exactly one generates,
/// and every caller returns the identity that is actually stored.
/// (`flock` releases on process death, so a crashed rival never wedges us.)
/// An existing identity with loosened permissions is republished
/// owner-only before returning, so no successful `init` leaves a
/// world-readable private key behind.
pub fn load_or_generate(path: &Path) -> io::Result<Keypair> {
    if let Ok(keypair) = load(path) {
        if !needs_perm_repair(path) {
            return Ok(keypair);
        }
        // Permissions drifted (chmod, umask, restore): fall through to
        // the locked section and repair.
    }
    // Fast path missed: take the lock, then re-check — the winner may have
    // published while we waited.
    let lock_path = sibling_path(path, "lock");
    ensure_parent_dir(&lock_path)?;
    let lock = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    fs2::FileExt::lock_exclusive(&lock)?;
    let outcome = match load(path) {
        Ok(keypair) => {
            if needs_perm_repair(path) {
                save(&keypair, path)?;
            }
            Ok(keypair)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let keypair = generate();
            save(&keypair, path)?;
            Ok(keypair)
        }
        Err(e) => Err(e),
    };
    let _ = fs2::FileExt::unlock(&lock);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p_identity::PeerId;

    #[test]
    fn fresh_keypairs_have_distinct_peer_ids() {
        let a = generate();
        let b = generate();
        assert_ne!(peer_id(&a), peer_id(&b));
    }

    #[test]
    fn saved_keypair_reloads_with_identical_peer_id() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("identity.key");
        let original = generate();
        save(&original, &file).unwrap();
        let loaded = load(&file).unwrap();
        assert_eq!(peer_id(&original), peer_id(&loaded));
    }

    #[test]
    #[cfg(unix)]
    fn saved_identity_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sub").join("identity.key");
        save(&generate(), &file).unwrap();
        let file_mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "identity file must be owner-only");
        let dir_mode = std::fs::metadata(file.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "identity dir must be owner-only");
    }

    #[test]
    #[cfg(unix)]
    fn resaving_tightens_a_previously_permissive_identity_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("identity.key");
        save(&generate(), &file).unwrap();
        // Simulate an identity written before hardening (or chmodded open):
        // re-saving must report success only with the file back at 0600.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        save(&generate(), &file).unwrap();
        let file_mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "re-saved identity must be owner-only");
    }

    #[test]
    #[cfg(unix)]
    fn save_leaves_a_pre_existing_parent_dir_alone() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // An operator-owned dir (e.g. a prepared $CLAWBANK_HOME) keeps its
        // own mode; only directories save() creates get 0700.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let file = dir.path().join("identity.key");
        save(&generate(), &file).unwrap();
        let dir_mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o755, "pre-existing dir must keep its mode");
    }

    #[test]
    #[cfg(unix)]
    fn load_or_generate_repairs_a_permissive_identity_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("identity.key");
        let original = generate();
        save(&original, &file).unwrap();
        // Loosened behind our back: the next init must tighten it again
        // while returning the identical identity.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let reloaded = load_or_generate(&file).unwrap();
        assert_eq!(peer_id(&original), peer_id(&reloaded));
        let file_mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "init must repair loosened permissions");
    }

    #[test]
    fn concurrent_first_run_converges_on_the_stored_identity() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("identity.key");
        let ids: Vec<String> = std::thread::scope(|s| {
            (0..8)
                .map(|_| s.spawn(|| peer_id_base58(&peer_id(&load_or_generate(&file).unwrap()))))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect()
        });
        assert!(ids.iter().all(|id| *id == ids[0]));
        assert_eq!(
            peer_id_base58(&peer_id(&load(&file).unwrap())),
            ids[0],
            "every caller must report the identity that is actually stored"
        );
    }

    #[test]
    fn missing_file_load_or_generate_creates_then_reloads_same_identity() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("identity.key");
        let first = load_or_generate(&file).unwrap();
        assert!(file.exists());
        let second = load_or_generate(&file).unwrap();
        assert_eq!(peer_id(&first), peer_id(&second));
    }

    #[test]
    fn peer_id_cid_round_trips_and_embeds_multihash_bytes() {
        let id = peer_id(&generate());
        let cid = peer_id_cid(&id);
        assert!(cid.starts_with('b'), "CID form must use multibase base32");
        assert!(
            cid.starts_with("bafz"),
            "Ed25519 PeerId CIDs start with bafz per the multicodec table: {cid}"
        );
        assert_eq!(peer_id_from_cid(&cid).unwrap(), id);
        let raw = data_encoding::BASE32_NOPAD
            .decode(cid[1..].to_uppercase().as_bytes())
            .unwrap();
        assert_eq!(&raw[2..], &id.to_bytes()[..]);
    }

    #[test]
    fn peer_id_derivation_is_deterministic_for_fixed_key_bytes() {
        // Golden vector, pinned from a real generated key: the same protobuf
        // bytes must always derive this PeerId through every construction
        // path. Breaks loudly if derivation, encoding, or multihash choice
        // changes.
        let file = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("identity.key");
        let bytes = std::fs::read(&file).unwrap();
        let via_load = peer_id(&load(&file).unwrap());
        let via_direct = peer_id(
            &Keypair::from_protobuf_encoding(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                .unwrap(),
        );
        assert_eq!(via_load, via_direct);
        assert_eq!(
            peer_id_base58(&via_load),
            "12D3KooWDrFGgb3hRZL5X9eXFPzbK1629hHR2Xv3z1gAkiED9Hcn"
        );
        assert_eq!(
            peer_id_cid(&via_load),
            "bafzaajaiaejcao7kdq2ip4qww43y45n3thbczbmf6dtoat7pfg3og26qbgn5hlb3"
        );
    }

    #[test]
    fn data_dir_defaults_to_dot_clawbank_under_home() {
        // Hermetic inputs: the assertion only holds with no CLAWBANK_HOME
        // override and a set HOME; otherwise there is nothing to check.
        // No other test reads process env, so remove/restore is race-free.
        let saved_override = std::env::var("CLAWBANK_HOME").ok();
        std::env::remove_var("CLAWBANK_HOME");
        let outcome = std::env::var("HOME").ok().map(|home| {
            let dir = data_dir().expect("HOME is set, so data_dir must resolve");
            (home, dir)
        });
        if let Some(value) = saved_override {
            std::env::set_var("CLAWBANK_HOME", value);
        }
        let Some((home, dir)) = outcome else {
            return;
        };
        assert_eq!(dir.parent().unwrap(), Path::new(&home));
        assert_eq!(dir.file_name().unwrap().to_str().unwrap(), ".clawbank");
    }

    #[test]
    fn peer_id_base58_round_trips_through_text() {
        let id = peer_id(&generate());
        let text = peer_id_base58(&id);
        let parsed: PeerId = text.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn export_round_trips_to_byte_identical_keypair() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("identity.key");
        let original = generate();
        save(&original, &file).unwrap();
        let before = std::fs::read(&file).unwrap();

        let exported = export(&load(&file).unwrap()).unwrap();
        std::fs::remove_file(&file).unwrap();
        let restored = import(&exported, &file).unwrap();

        assert_eq!(peer_id(&original), peer_id(&restored));
        assert_eq!(before, std::fs::read(&file).unwrap());
        assert_eq!(
            before,
            restored
                .to_protobuf_encoding()
                .expect("restored keypair must encode"),
        );
    }

    #[test]
    fn export_is_single_line_base64_of_protobuf_bytes() {
        let keypair = generate();
        let text = export(&keypair).unwrap().trim().to_string();
        assert!(!text.is_empty());
        assert!(!text.contains(char::is_whitespace));
        let decoded = data_encoding::BASE64.decode(text.as_bytes()).unwrap();
        assert_eq!(
            decoded,
            keypair.to_protobuf_encoding().expect("keypair must encode")
        );
    }

    #[test]
    fn import_rejects_malformed_material_without_touching_state() {
        for bad in [
            "",
            "!!!not-base64!!!",
            "aGVsbG8td29ybGQ=",
            &export(&generate()).unwrap()[..10],
        ] {
            // Existing identity present: failed import keeps it intact.
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("identity.key");
            let original = generate();
            save(&original, &file).unwrap();
            let before = std::fs::read(&file).unwrap();
            let err = import(bad, &file).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "input: {bad:?}");
            assert!(
                err.to_string().contains("not a valid identity export"),
                "clear error, got: {err}"
            );
            assert_eq!(std::fs::read(&file).unwrap(), before);
            assert_eq!(peer_id(&load(&file).unwrap()), peer_id(&original));

            // No identity yet: failed import creates nothing.
            let fresh = dir.path().join("fresh.key");
            let err = import(bad, &fresh).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert!(!fresh.exists(), "failed import must not create a file");
        }
    }

    #[test]
    #[cfg(unix)]
    fn import_restores_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("identity.key");
        let exported = export(&generate()).unwrap();
        let restored = import(&exported, &file).unwrap();
        assert_eq!(peer_id(&load(&file).unwrap()), peer_id(&restored));
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "restored identity must be owner-only");
    }

    #[test]
    fn concurrent_imports_converge_on_the_restored_identity() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("identity.key");
        let exported = export(&generate()).unwrap();
        let ids: Vec<String> = std::thread::scope(|s| {
            (0..8)
                .map(|_| s.spawn(|| peer_id_base58(&peer_id(&import(&exported, &file).unwrap()))))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect()
        });
        assert!(ids.iter().all(|id| *id == ids[0]));
        assert_eq!(
            peer_id_base58(&peer_id(&load(&file).unwrap())),
            ids[0],
            "every importer must report the identity that is actually stored"
        );
    }
}
