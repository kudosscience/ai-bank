//! Domain-separated message signing (ADR-0001, transfer-signing primitive).
//!
//! The node signs arbitrary bytes with its identity key under the bank
//! domain, so any payload can be attributed to a [`PeerId`]. Verification
//! confirms both the Ed25519 signature and that the supplied public key
//! actually belongs to the claimed [`PeerId`]
//! (`PeerId::from_public_key(key) == claimed`), matching the
//! `account_vk.verify(domain + cbor, sig) + PeerId binding` rule ADR-0007
//! assigns to ledger transfers.
//!
//! Wire domain is `b"/clawbank/1/"` per ADR-0012 (ADRs 0001-0011 say
//! `ai-bank`; code reads `clawbank`). [`sign_with_domain`] /
//! [`verify_with_domain`] take a caller suffix (e.g. `b"/clawbank/1/transfer:"`)
//! so ledger signing reuses this exact primitive with its own framing.

use libp2p_identity::{Keypair, PeerId, PublicKey};

/// Bank wire domain framing every signed message. See ADR-0012 rename note.
pub const BANK_DOMAIN: &[u8] = b"/clawbank/1/";

/// The exact bytes that are signed: `domain || message`.
///
/// This matches the ADR-0007 wire rule `account_vk.verify(domain + cbor, sig)`,
/// so the framing is intentionally bare concatenation — changing it (e.g. to
/// length-prefixing) would break ledger wire compatibility.
///
/// Separation holds because the verifier supplies the domain out-of-band as a
/// fixed, caller-known prefix: a signature only verifies under the exact
/// domain it was framed with. Different `(domain, message)` pairs can still
/// collide to identical bytes when one domain is a prefix of another (e.g.
/// `BANK_DOMAIN` + `b"transfer:..."` vs. `b"/clawbank/1/transfer:"` + `...`),
/// so prefix-related domains (bank vs. ledger transfer/batch) are related
/// contexts, not isolated ones — callers must not treat them as such.
/// Domains must be non-empty; see [`sign_with_domain`]/[`verify_with_domain`].
pub fn signing_bytes(domain: &[u8], message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + message.len());
    out.extend_from_slice(domain);
    out.extend_from_slice(message);
    out
}

/// Sign `message` with the node key under [`BANK_DOMAIN`].
pub fn sign(keypair: &Keypair, message: &[u8]) -> Vec<u8> {
    sign_with_domain(keypair, BANK_DOMAIN, message)
}

/// Sign `message` under an explicit domain (e.g. a ledger transfer domain).
///
/// Shaped for direct reuse by ledger transfer/batch signing: those callers
/// pass their own domain constant instead of [`BANK_DOMAIN`].
///
/// # Panics
///
/// Panics when `domain` is empty. An empty domain would frame the bare
/// message with no separation, letting raw Ed25519 signatures verify as
/// domain-separated ones.
pub fn sign_with_domain(keypair: &Keypair, domain: &[u8], message: &[u8]) -> Vec<u8> {
    assert!(!domain.is_empty(), "domain must not be empty");
    let framed = signing_bytes(domain, message);
    keypair
        .sign(&framed)
        .expect("node keypair signing is infallible for supported key types")
}

/// Verify `signature` over `message` under [`BANK_DOMAIN`].
///
/// Returns `true` only when both checks hold:
/// 1. `public_key` actually belongs to `claimed` (`PeerId::from_public_key`),
/// 2. `public_key` verifies the domain-framed signature.
pub fn verify(claimed: &PeerId, public_key: &PublicKey, message: &[u8], signature: &[u8]) -> bool {
    verify_with_domain(claimed, public_key, BANK_DOMAIN, message, signature)
}

/// Verify `signature` over `message` under an explicit domain.
///
/// Domain mismatch fails closed: a signature framed under any other domain
/// (including raw unsigned bytes) does not verify. An empty `domain` fails
/// closed (`false`) so callers cannot bypass separation with `b""`.
pub fn verify_with_domain(
    claimed: &PeerId,
    public_key: &PublicKey,
    domain: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    if domain.is_empty() {
        return false;
    }
    if PeerId::from_public_key(public_key) != *claimed {
        return false;
    }
    public_key.verify(&signing_bytes(domain, message), signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate, peer_id};

    fn keypair_and_id() -> (Keypair, PeerId, PublicKey) {
        let kp = generate();
        let id = peer_id(&kp);
        let pk = kp.public();
        (kp, id, pk)
    }

    #[test]
    fn signing_bytes_round_trip_under_bank_domain_verifies() {
        let (kp, id, pk) = keypair_and_id();
        let message = b"transfer:alice->bob:100";
        let sig = sign(&kp, message);
        assert_eq!(sig.len(), 64, "Ed25519 signatures are 64 bytes");
        assert!(verify(&id, &pk, message, &sig));
    }

    #[test]
    fn tampered_payload_bytes_fail_verification() {
        let (kp, id, pk) = keypair_and_id();
        let sig = sign(&kp, b"transfer:alice->bob:100");
        assert!(!verify(&id, &pk, b"transfer:alice->bob:101", &sig));
        assert!(!verify(&id, &pk, b"", &sig));
    }

    #[test]
    fn signature_from_a_different_key_fails_against_claimed_peer_id() {
        let (kp_a, id_a, _pk_a) = keypair_and_id();
        let (_kp_b, _id_b, pk_b) = keypair_and_id();
        // Attacker signs with their own key but claims victim's PeerId,
        // with the attacker's key supplied as the vk.
        let sig = sign(&kp_a, b"transfer:alice->bob:100");
        let (_kp_attacker, _, pk_attacker) = keypair_and_id();
        let attacker_sig = sign(&_kp_attacker, b"transfer:alice->bob:100");
        // Wrong vk for the claimed id: binding check fails.
        assert!(!verify(&id_a, &pk_b, b"transfer:alice->bob:100", &sig));
        // Attacker's own (id, vk) pair verifies their sig, but the
        // attacker's sig does not verify as the victim's.
        assert!(!verify(
            &id_a,
            &pk_attacker,
            b"transfer:alice->bob:100",
            &attacker_sig
        ));
    }

    #[test]
    fn cross_protocol_replay_is_rejected_by_domain_separation() {
        let (kp, id, pk) = keypair_and_id();
        let message = b"transfer:alice->bob:100";
        // A raw (domain-less) signature over the same bytes.
        let raw_sig = kp.sign(message).expect("raw sign");
        assert!(
            !verify(&id, &pk, message, &raw_sig),
            "a signature without the bank domain must not verify as a bank message"
        );
        // A signature framed under a foreign domain.
        let other_sig = sign_with_domain(&kp, b"/other-protocol/1/", message);
        assert!(
            !verify(&id, &pk, message, &other_sig),
            "a foreign-domain signature must not verify under the bank domain"
        );
        // And the reverse: a bank signature does not verify as foreign.
        let bank_sig = sign(&kp, message);
        assert!(
            !verify_with_domain(&id, &pk, b"/other-protocol/1/", message, &bank_sig),
            "a bank-domain signature must not verify under a foreign domain"
        );
    }

    #[test]
    fn tampered_signature_bytes_fail_verification() {
        let (kp, id, pk) = keypair_and_id();
        let message = b"transfer:alice->bob:100";
        let mut sig = sign(&kp, message);
        sig[0] ^= 0x01;
        assert!(!verify(&id, &pk, message, &sig));
    }

    #[test]
    fn signing_bytes_are_domain_prefixed_message() {
        assert_eq!(signing_bytes(b"/clawbank/1/", b"abc"), b"/clawbank/1/abc");
        assert_eq!(signing_bytes(BANK_DOMAIN, b""), BANK_DOMAIN);
    }

    #[test]
    fn empty_domain_fails_closed() {
        let (kp, id, pk) = keypair_and_id();
        let message = b"transfer:alice->bob:100";
        // A raw Ed25519 signature over the bare message must not verify
        // even when the caller passes an empty domain explicitly.
        let raw_sig = kp.sign(message).expect("raw sign");
        assert!(!verify_with_domain(&id, &pk, b"", message, &raw_sig));
    }

    #[test]
    #[should_panic(expected = "domain must not be empty")]
    fn sign_with_empty_domain_panics() {
        let (kp, _, _) = keypair_and_id();
        let _ = sign_with_domain(&kp, b"", b"transfer:alice->bob:100");
    }
}
