use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use aegis::{
    CHUNK_SIZE, Error, FLAG_MASTER_KEY, KdfParams, decrypt_file, encrypt_file, peek_header,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn fresh_tmpdir(name: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "bml-test-{}-{}-{}-{n}",
        std::process::id(),
        name,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_file(path: &Path, content: &[u8]) {
    let mut f = fs::File::create(path).unwrap();
    f.write_all(content).unwrap();
    f.sync_all().unwrap();
}

fn read_file(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap()
}

fn fast_params() -> KdfParams {
    KdfParams::fast_for_tests()
}

const PWD: &[u8] = b"correct horse battery staple";
const WRONG: &[u8] = b"correct horse battery stable";

fn round_trip(content: &[u8], test_name: &str) {
    let dir = fresh_tmpdir(test_name);
    let plain = dir.join("plain.bin");
    let cipher = dir.join("cipher.bml");
    let restored = dir.join("restored.bin");

    write_file(&plain, content);
    encrypt_file(&plain, &cipher, PWD, fast_params(), 0).unwrap();
    decrypt_file(&cipher, &restored, PWD).unwrap();

    let got = read_file(&restored);
    assert_eq!(got, content, "round-trip mismatch for {test_name}");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn rt_empty() {
    round_trip(&[], "empty");
}

#[test]
fn rt_one_byte() {
    round_trip(b"x", "one_byte");
}

#[test]
fn rt_chunk_minus_one() {
    let v: Vec<u8> = (0..CHUNK_SIZE - 1).map(|i| (i % 251) as u8).collect();
    round_trip(&v, "chunk_minus_one");
}

#[test]
fn rt_exact_chunk() {
    let v: Vec<u8> = (0..CHUNK_SIZE).map(|i| (i % 251) as u8).collect();
    round_trip(&v, "exact_chunk");
}

#[test]
fn rt_chunk_plus_one() {
    let v: Vec<u8> = (0..CHUNK_SIZE + 1).map(|i| (i % 251) as u8).collect();
    round_trip(&v, "chunk_plus_one");
}

#[test]
fn rt_two_chunks_exact() {
    let v: Vec<u8> = (0..2 * CHUNK_SIZE).map(|i| (i % 251) as u8).collect();
    round_trip(&v, "two_chunks_exact");
}

#[test]
fn rt_large_5x_plus() {
    let v: Vec<u8> = (0..5 * CHUNK_SIZE + 12345)
        .map(|i| (i % 251) as u8)
        .collect();
    round_trip(&v, "large_5x_plus");
}

#[test]
fn rt_one_megabyte() {
    let v = vec![0xCDu8; 1_000_000];
    round_trip(&v, "one_megabyte");
}

#[test]
fn refuse_to_overwrite_output_on_encrypt() {
    let dir = fresh_tmpdir("refuse_overwrite_enc");
    let plain = dir.join("plain.bin");
    let cipher = dir.join("cipher.bml");

    write_file(&plain, b"hello");
    write_file(&cipher, b"existing");

    let err = encrypt_file(&plain, &cipher, PWD, fast_params(), 0).unwrap_err();
    assert!(matches!(err, Error::OutputAlreadyExists), "got {err:?}");
}

#[test]
fn refuse_to_overwrite_output_on_decrypt() {
    let dir = fresh_tmpdir("refuse_overwrite_dec");
    let plain = dir.join("plain.bin");
    let cipher = dir.join("cipher.bml");
    let restored = dir.join("restored.bin");

    write_file(&plain, b"hello world");
    encrypt_file(&plain, &cipher, PWD, fast_params(), 0).unwrap();
    write_file(&restored, b"existing");

    let err = decrypt_file(&cipher, &restored, PWD).unwrap_err();
    assert!(matches!(err, Error::OutputAlreadyExists), "got {err:?}");
}

#[test]
fn wrong_password_fails_cleanly() {
    let dir = fresh_tmpdir("wrong_pwd");
    let plain = dir.join("plain.bin");
    let cipher = dir.join("cipher.bml");
    let restored = dir.join("restored.bin");

    write_file(&plain, b"secret payload here");
    encrypt_file(&plain, &cipher, PWD, fast_params(), 0).unwrap();

    let err = decrypt_file(&cipher, &restored, WRONG).unwrap_err();
    assert!(matches!(err, Error::Aead), "got {err:?}");
    // Tmp file must have been cleaned up
    assert!(!restored.exists(), "restored should not be present");
    let tmp = {
        let mut s: std::ffi::OsString = restored.as_os_str().into();
        s.push(".tmp");
        std::path::PathBuf::from(s)
    };
    assert!(!tmp.exists(), "tmp file leaked: {tmp:?}");
}

#[test]
fn header_byte_tampered_fails() {
    let dir = fresh_tmpdir("tamper_header");
    let plain = dir.join("plain.bin");
    let cipher = dir.join("cipher.bml");
    let restored = dir.join("restored.bin");

    write_file(&plain, b"payload");
    encrypt_file(&plain, &cipher, PWD, fast_params(), 0).unwrap();

    // Flip a byte in the salt region (offset 20: middle of salt).
    let mut bytes = read_file(&cipher);
    bytes[20] ^= 0x01;
    fs::remove_file(&cipher).unwrap();
    write_file(&cipher, &bytes);

    let err = decrypt_file(&cipher, &restored, PWD).unwrap_err();
    // Tampering the salt changes the derived key, so AEAD fails on chunk 0.
    assert!(matches!(err, Error::Aead), "got {err:?}");
}

#[test]
fn magic_tampered_fails_with_invalid_header() {
    let dir = fresh_tmpdir("tamper_magic");
    let plain = dir.join("plain.bin");
    let cipher = dir.join("cipher.bml");
    let restored = dir.join("restored.bin");

    write_file(&plain, b"payload");
    encrypt_file(&plain, &cipher, PWD, fast_params(), 0).unwrap();

    let mut bytes = read_file(&cipher);
    bytes[0] = b'X';
    fs::remove_file(&cipher).unwrap();
    write_file(&cipher, &bytes);

    let err = decrypt_file(&cipher, &restored, PWD).unwrap_err();
    assert!(matches!(err, Error::InvalidHeader(_)), "got {err:?}");
}

#[test]
fn payload_byte_tampered_fails() {
    let dir = fresh_tmpdir("tamper_payload");
    let plain = dir.join("plain.bin");
    let cipher = dir.join("cipher.bml");
    let restored = dir.join("restored.bin");

    write_file(&plain, &vec![0xABu8; 200]);
    encrypt_file(&plain, &cipher, PWD, fast_params(), 0).unwrap();

    let mut bytes = read_file(&cipher);
    // Flip a byte well past the 64-byte header.
    let idx = 100.min(bytes.len() - 1);
    bytes[idx] ^= 0x01;
    fs::remove_file(&cipher).unwrap();
    write_file(&cipher, &bytes);

    let err = decrypt_file(&cipher, &restored, PWD).unwrap_err();
    assert!(matches!(err, Error::Aead), "got {err:?}");
}

#[test]
fn last_byte_tampered_fails() {
    let dir = fresh_tmpdir("tamper_last");
    let plain = dir.join("plain.bin");
    let cipher = dir.join("cipher.bml");
    let restored = dir.join("restored.bin");

    write_file(&plain, b"some bytes here");
    encrypt_file(&plain, &cipher, PWD, fast_params(), 0).unwrap();

    let mut bytes = read_file(&cipher);
    let last = bytes.len() - 1;
    bytes[last] ^= 0x80;
    fs::remove_file(&cipher).unwrap();
    write_file(&cipher, &bytes);

    let err = decrypt_file(&cipher, &restored, PWD).unwrap_err();
    assert!(matches!(err, Error::Aead), "got {err:?}");
}

#[test]
fn truncated_payload_fails() {
    let dir = fresh_tmpdir("truncated");
    let plain = dir.join("plain.bin");
    let cipher = dir.join("cipher.bml");
    let restored = dir.join("restored.bin");

    // Multi-chunk file so truncation removes a real chunk.
    let v: Vec<u8> = (0..3 * CHUNK_SIZE).map(|i| (i % 251) as u8).collect();
    write_file(&plain, &v);
    encrypt_file(&plain, &cipher, PWD, fast_params(), 0).unwrap();

    let bytes = read_file(&cipher);
    // Drop the entire final chunk (and then some) to simulate truncation.
    let truncated = &bytes[..bytes.len() - (CHUNK_SIZE + 16)];
    fs::remove_file(&cipher).unwrap();
    write_file(&cipher, truncated);

    let err = decrypt_file(&cipher, &restored, PWD).unwrap_err();
    // Could fail either as Aead (chunk thought to be last fails auth)
    // or Truncated (final read got <TAG_LEN bytes). Both are acceptable.
    assert!(
        matches!(err, Error::Aead | Error::Truncated),
        "got {err:?}"
    );
}

#[test]
fn header_only_file_fails_truncated() {
    let dir = fresh_tmpdir("header_only");
    let plain = dir.join("plain.bin");
    let cipher = dir.join("cipher.bml");
    let restored = dir.join("restored.bin");

    write_file(&plain, b"payload");
    encrypt_file(&plain, &cipher, PWD, fast_params(), 0).unwrap();

    // Keep only the 64-byte header, drop the entire ciphertext payload.
    let bytes = read_file(&cipher);
    let only_header = &bytes[..64];
    fs::remove_file(&cipher).unwrap();
    write_file(&cipher, only_header);

    let err = decrypt_file(&cipher, &restored, PWD).unwrap_err();
    assert!(matches!(err, Error::Truncated), "got {err:?}");
}

#[test]
fn chunk_swap_fails() {
    let dir = fresh_tmpdir("chunk_swap");
    let plain = dir.join("plain.bin");
    let cipher = dir.join("cipher.bml");
    let restored = dir.join("restored.bin");

    let v: Vec<u8> = (0..2 * CHUNK_SIZE + 100).map(|i| (i % 251) as u8).collect();
    write_file(&plain, &v);
    encrypt_file(&plain, &cipher, PWD, fast_params(), 0).unwrap();

    // File layout: [64B header][chunk0=CHUNK_SIZE+16][chunk1=CHUNK_SIZE+16][last chunk=100+16]
    let mut bytes = read_file(&cipher);
    let chunk_full = CHUNK_SIZE + 16;
    let c0_start = 64;
    let c1_start = c0_start + chunk_full;
    let chunk0: Vec<u8> = bytes[c0_start..c0_start + chunk_full].to_vec();
    let chunk1: Vec<u8> = bytes[c1_start..c1_start + chunk_full].to_vec();
    bytes[c0_start..c0_start + chunk_full].copy_from_slice(&chunk1);
    bytes[c1_start..c1_start + chunk_full].copy_from_slice(&chunk0);

    fs::remove_file(&cipher).unwrap();
    write_file(&cipher, &bytes);

    let err = decrypt_file(&cipher, &restored, PWD).unwrap_err();
    assert!(matches!(err, Error::Aead), "got {err:?}");
}

#[cfg(unix)]
#[test]
fn output_file_mode_is_0600() {
    use std::os::unix::fs::PermissionsExt;

    let dir = fresh_tmpdir("mode_check");
    let plain = dir.join("plain.bin");
    let cipher = dir.join("cipher.bml");

    write_file(&plain, b"hi");
    encrypt_file(&plain, &cipher, PWD, fast_params(), 0).unwrap();
    let mode = fs::metadata(&cipher).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "encrypted file mode is {mode:o}");
}

#[test]
fn master_flag_is_set_when_requested() {
    let dir = fresh_tmpdir("master_flag");
    let plain = dir.join("plain.bin");
    let cipher = dir.join("cipher.bml");
    write_file(&plain, b"secret");

    encrypt_file(&plain, &cipher, PWD, fast_params(), FLAG_MASTER_KEY).unwrap();
    let header = peek_header(&cipher).unwrap();
    assert_eq!(header.flags & FLAG_MASTER_KEY, FLAG_MASTER_KEY);
}

#[test]
fn master_flag_is_absent_when_not_requested() {
    let dir = fresh_tmpdir("no_master_flag");
    let plain = dir.join("plain.bin");
    let cipher = dir.join("cipher.bml");
    write_file(&plain, b"secret");

    encrypt_file(&plain, &cipher, PWD, fast_params(), 0).unwrap();
    let header = peek_header(&cipher).unwrap();
    assert_eq!(header.flags & FLAG_MASTER_KEY, 0);
}

#[test]
fn master_flag_round_trip_decrypts() {
    let dir = fresh_tmpdir("master_round_trip");
    let plain = dir.join("plain.bin");
    let cipher = dir.join("cipher.bml");
    let restored = dir.join("restored.bin");
    write_file(&plain, b"important payload");

    encrypt_file(&plain, &cipher, PWD, fast_params(), FLAG_MASTER_KEY).unwrap();
    decrypt_file(&cipher, &restored, PWD).unwrap();
    assert_eq!(fs::read(&restored).unwrap(), b"important payload");
}
