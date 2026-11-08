//! Entry-name-bound ECIES bundle envelopes.
//!
//! The wire layout is an uncompressed secp256k1 point (65 bytes), nonce
//! (16 bytes), authentication tag (16 bytes), then ciphertext.
// Portions adapted from ecies/rs. Copyright (c) 2019-2026 Weiliang Li.
// MIT license: see licenses/ecies-MIT.txt.

use aes_gcm::aead::{AeadInOut, KeyInit, Nonce, Tag};
use aes_gcm::{AesGcm, aes::Aes256, aes::cipher::consts::U16};
use zeroize::Zeroizing;

type Cipher = AesGcm<Aes256, U16>;

/// Decrypt an ECIES envelope with the caller's exact additional authenticated data.
///
/// Returns plaintext only after authentication succeeds, or `None` for an
/// invalid key, malformed envelope, or authentication failure.
pub(crate) fn decrypt(secret: &[u8], envelope: &[u8], aad: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let (ephemeral, payload) = envelope.split_at_checked(65)?;
    let (nonce, payload) = payload.split_at_checked(16)?;
    let (tag, ciphertext) = payload.split_at_checked(16)?;
    let secret = ecies::SecretKey::parse_slice(secret).ok()?;
    let ephemeral = ecies::PublicKey::parse_slice(ephemeral, None).ok()?;
    let key = Zeroizing::new(ecies::utils::decapsulate(&ephemeral, &secret, false).ok()?);
    let cipher = Cipher::new_from_slice(&key[..]).ok()?;
    let nonce = Nonce::<Cipher>::try_from(nonce).ok()?;
    let tag = Tag::<Cipher>::try_from(tag).ok()?;
    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_inout_detached(&nonce, aad, plaintext.as_mut_slice().into(), &tag)
        .ok()?;
    Some(plaintext)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::decrypt;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Vector {
        aad_hex: String,
        ciphertext_hex: String,
        plaintext_hex: String,
    }

    fn vectors() -> Vec<Vector> {
        // Fixed outputs of the previously deployed AAD fork at 81e1b84.
        serde_json::from_str(include_str!("aad/vectors.json")).unwrap()
    }

    #[test]
    fn decrypts_existing_fork_envelopes_byte_exactly() {
        for vector in vectors() {
            let ciphertext = hex::decode(vector.ciphertext_hex).unwrap();
            let aad = hex::decode(vector.aad_hex).unwrap();
            let expected = hex::decode(vector.plaintext_hex).unwrap();
            assert_eq!(
                decrypt(&[0x11; 32], &ciphertext, &aad).unwrap().as_slice(),
                expected
            );
            if aad.is_empty() {
                assert_eq!(ecies::decrypt(&[0x11; 32], &ciphertext).unwrap(), expected);
            } else {
                assert!(decrypt(&[0x11; 32], &ciphertext, b"").is_none());
            }
            assert!(decrypt(&[0x11; 32], &ciphertext, b"wrong-entry").is_none());
            assert!(decrypt(&[0x22; 32], &ciphertext, &aad).is_none());
        }
    }

    #[test]
    fn malformed_and_tampered_envelopes_fail_closed() {
        let vector = vectors().remove(1);
        let ciphertext = hex::decode(vector.ciphertext_hex).unwrap();
        let aad = hex::decode(vector.aad_hex).unwrap();
        for len in 0..ciphertext.len() {
            assert!(decrypt(&[0x11; 32], &ciphertext[..len], &aad).is_none());
        }
        for i in 0..ciphertext.len() {
            let mut changed = ciphertext.clone();
            changed[i] ^= 1;
            assert!(decrypt(&[0x11; 32], &changed, &aad).is_none(), "byte {i}");
        }
        for key in [vec![], vec![0x11; 31], vec![0; 32], vec![0xff; 32]] {
            assert!(decrypt(&key, &ciphertext, &aad).is_none());
        }
    }
}
