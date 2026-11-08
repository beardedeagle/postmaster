//! Test-only AAD envelope construction, independent of the production decoder.
#![allow(clippy::unwrap_used)]

use aes_gcm::aead::{AeadInOut, KeyInit, Nonce};
use aes_gcm::{AesGcm, aes::Aes256, aes::cipher::consts::U16};
use zeroize::Zeroizing;

/// Encrypt a test value with a fresh ephemeral key and the supplied AAD.
pub fn encrypt(public: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    type Cipher = AesGcm<Aes256, U16>;
    let public = ecies::PublicKey::parse_slice(public, None).unwrap();
    let (secret, ephemeral) = ecies::utils::generate_keypair();
    let key = Zeroizing::new(ecies::utils::encapsulate(&secret, &public, false).unwrap());
    let cipher = Cipher::new_from_slice(&key[..]).unwrap();
    // Each fixture uses a fresh derived AES key, so this nonce is never reused with a key.
    let nonce = Nonce::<Cipher>::default();
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_inout_detached(&nonce, aad, ciphertext.as_mut_slice().into())
        .unwrap();
    let mut envelope = ephemeral.serialize().to_vec();
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&tag);
    envelope.extend_from_slice(&ciphertext);
    envelope
}
