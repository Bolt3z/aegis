use aegis::{KdfParams, decrypt, derive_key, encrypt, random_salt};
use aegis::aead::random_nonce;

const PASSWORD: &[u8] = b"correct horse battery staple";
const WRONG_PASSWORD: &[u8] = b"correct horse battery stable";

#[test]
fn kdf_is_deterministic() {
    let salt = [0x42u8; 16];
    let params = KdfParams::fast_for_tests();
    let k1 = derive_key(PASSWORD, &salt, params).unwrap();
    let k2 = derive_key(PASSWORD, &salt, params).unwrap();
    assert_eq!(k1.as_bytes(), k2.as_bytes());
}

#[test]
fn kdf_different_salt_yields_different_key() {
    let s1 = [0x01u8; 16];
    let s2 = [0x02u8; 16];
    let params = KdfParams::fast_for_tests();
    let k1 = derive_key(PASSWORD, &s1, params).unwrap();
    let k2 = derive_key(PASSWORD, &s2, params).unwrap();
    assert_ne!(k1.as_bytes(), k2.as_bytes());
}

#[test]
fn kdf_different_password_yields_different_key() {
    let salt = [0x42u8; 16];
    let params = KdfParams::fast_for_tests();
    let k1 = derive_key(PASSWORD, &salt, params).unwrap();
    let k2 = derive_key(WRONG_PASSWORD, &salt, params).unwrap();
    assert_ne!(k1.as_bytes(), k2.as_bytes());
}

#[test]
fn aead_round_trip() {
    let salt = random_salt().unwrap();
    let key = derive_key(PASSWORD, &salt, KdfParams::fast_for_tests()).unwrap();
    let nonce = random_nonce().unwrap();
    let plaintext = b"the launch codes are in the briefcase";
    let aad = b"file=secret.txt";

    let ct = encrypt(&key, &nonce, aad, plaintext).unwrap();
    assert_ne!(ct.as_slice(), plaintext);
    assert!(ct.len() > plaintext.len()); // tag appended

    let pt = decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(pt.as_slice(), plaintext);
}

#[test]
fn aead_empty_plaintext_round_trip() {
    let key = derive_key(PASSWORD, &[0u8; 16], KdfParams::fast_for_tests()).unwrap();
    let nonce = [0u8; 24];
    let ct = encrypt(&key, &nonce, b"", b"").unwrap();
    let pt = decrypt(&key, &nonce, b"", &ct).unwrap();
    assert!(pt.is_empty());
}

#[test]
fn aead_large_buffer_round_trip() {
    let key = derive_key(PASSWORD, &[7u8; 16], KdfParams::fast_for_tests()).unwrap();
    let nonce = [9u8; 24];
    let plaintext = vec![0xABu8; 1_000_000];
    let ct = encrypt(&key, &nonce, b"meta", &plaintext).unwrap();
    let pt = decrypt(&key, &nonce, b"meta", &ct).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn aead_wrong_password_fails() {
    let salt = [0u8; 16];
    let params = KdfParams::fast_for_tests();
    let good = derive_key(PASSWORD, &salt, params).unwrap();
    let bad = derive_key(WRONG_PASSWORD, &salt, params).unwrap();
    let nonce = random_nonce().unwrap();
    let ct = encrypt(&good, &nonce, b"", b"secret").unwrap();
    assert!(decrypt(&bad, &nonce, b"", &ct).is_err());
}

#[test]
fn aead_wrong_nonce_fails() {
    let key = derive_key(PASSWORD, &[0u8; 16], KdfParams::fast_for_tests()).unwrap();
    let n1 = [1u8; 24];
    let n2 = [2u8; 24];
    let ct = encrypt(&key, &n1, b"", b"secret").unwrap();
    assert!(decrypt(&key, &n2, b"", &ct).is_err());
}

#[test]
fn aead_wrong_aad_fails() {
    let key = derive_key(PASSWORD, &[0u8; 16], KdfParams::fast_for_tests()).unwrap();
    let nonce = [3u8; 24];
    let ct = encrypt(&key, &nonce, b"context-A", b"secret").unwrap();
    assert!(decrypt(&key, &nonce, b"context-B", &ct).is_err());
}

#[test]
fn aead_tampered_ciphertext_fails() {
    let key = derive_key(PASSWORD, &[0u8; 16], KdfParams::fast_for_tests()).unwrap();
    let nonce = [4u8; 24];
    let mut ct = encrypt(&key, &nonce, b"", b"secret payload").unwrap();
    // Flip a byte in the ciphertext body (not the tag).
    ct[0] ^= 0x01;
    assert!(decrypt(&key, &nonce, b"", &ct).is_err());
}

#[test]
fn aead_tampered_tag_fails() {
    let key = derive_key(PASSWORD, &[0u8; 16], KdfParams::fast_for_tests()).unwrap();
    let nonce = [5u8; 24];
    let mut ct = encrypt(&key, &nonce, b"", b"secret payload").unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0x80;
    assert!(decrypt(&key, &nonce, b"", &ct).is_err());
}

#[test]
fn aead_truncated_ciphertext_fails() {
    let key = derive_key(PASSWORD, &[0u8; 16], KdfParams::fast_for_tests()).unwrap();
    let nonce = [6u8; 24];
    let ct = encrypt(&key, &nonce, b"", b"secret payload").unwrap();
    let truncated = &ct[..ct.len() - 1];
    assert!(decrypt(&key, &nonce, b"", truncated).is_err());
}

#[test]
fn random_salt_is_random() {
    let s1 = random_salt().unwrap();
    let s2 = random_salt().unwrap();
    assert_ne!(s1, s2);
}

#[test]
fn random_nonce_is_random() {
    let n1 = random_nonce().unwrap();
    let n2 = random_nonce().unwrap();
    assert_ne!(n1, n2);
}
