use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::error::{Error, Result};
use crate::key::Key;

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

pub fn random_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce)?;
    Ok(nonce)
}

/// Encrypt `plaintext` with the given key, nonce, and associated data.
/// Returns `ciphertext || tag` (16-byte tag appended).
pub fn encrypt(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let xnonce = XNonce::from_slice(nonce);
    cipher
        .encrypt(xnonce, Payload { msg: plaintext, aad })
        .map_err(|_| Error::Aead)
}

/// Decrypt `ciphertext_with_tag` (= ciphertext || 16-byte tag).
/// Returns the plaintext on success, `Error::Aead` on any authentication failure.
pub fn decrypt(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext_with_tag.len() < TAG_LEN {
        return Err(Error::InvalidLength {
            expected: TAG_LEN,
            got: ciphertext_with_tag.len(),
        });
    }
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let xnonce = XNonce::from_slice(nonce);
    cipher
        .decrypt(
            xnonce,
            Payload {
                msg: ciphertext_with_tag,
                aad,
            },
        )
        .map_err(|_| Error::Aead)
}
