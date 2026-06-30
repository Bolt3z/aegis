use std::fs;
use std::path::PathBuf;

use aegis::{
    FLAG_KEYFILE, FLAG_MASTER_KEY, KdfParams, decrypt_file, encrypt_file, keyfile, peek_header,
};

fn tmpdir(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let unique = format!(
        "aegis-keyfile-{}-{}",
        name,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    p.push(unique);
    fs::create_dir(&p).unwrap();
    p
}

fn write(path: &std::path::Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
}

#[test]
fn combine_returns_password_when_no_digest() {
    let pwd = b"hunter2";
    let out = keyfile::combine(pwd, None);
    assert_eq!(out, pwd.to_vec());
}

#[test]
fn combine_appends_digest_when_provided() {
    let pwd = b"hunter2";
    let digest = [0xAAu8; keyfile::DIGEST_LEN];
    let out = keyfile::combine(pwd, Some(&digest));
    assert_eq!(out.len(), pwd.len() + keyfile::DIGEST_LEN);
    assert_eq!(&out[..pwd.len()], pwd);
    assert_eq!(&out[pwd.len()..], &digest);
}

#[test]
fn digest_file_is_deterministic() {
    let dir = tmpdir("digest-det");
    let kf = dir.join("key.bin");
    write(&kf, b"some keyfile content");

    let a = keyfile::digest_file(&kf).unwrap();
    let b = keyfile::digest_file(&kf).unwrap();
    assert_eq!(a, b);
}

#[test]
fn digest_file_differs_for_different_content() {
    let dir = tmpdir("digest-diff");
    let kf1 = dir.join("a.bin");
    let kf2 = dir.join("b.bin");
    write(&kf1, b"content one");
    write(&kf2, b"content two");

    let d1 = keyfile::digest_file(&kf1).unwrap();
    let d2 = keyfile::digest_file(&kf2).unwrap();
    assert_ne!(d1, d2);
}

#[test]
fn digest_file_handles_empty_file() {
    let dir = tmpdir("digest-empty");
    let kf = dir.join("empty.bin");
    write(&kf, b"");
    let d = keyfile::digest_file(&kf).unwrap();
    // BLAKE2b-256 of empty input is well-defined; we only assert it's stable.
    let d2 = keyfile::digest_file(&kf).unwrap();
    assert_eq!(d, d2);
}

#[test]
fn round_trip_with_keyfile() {
    let dir = tmpdir("roundtrip");
    let input = dir.join("doc.txt");
    let output = dir.join("doc.txt.bml");
    let recovered = dir.join("doc.roundtrip");
    let kf = dir.join("key.bin");
    write(&input, b"top secret payload");
    write(&kf, b"32-byte minimal keyfile content!");

    let pwd = b"hunter2";
    let digest = keyfile::digest_file(&kf).unwrap();
    let combined = keyfile::combine(pwd, Some(&digest));

    encrypt_file(
        &input,
        &output,
        &combined,
        KdfParams::fast_for_tests(),
        FLAG_MASTER_KEY | FLAG_KEYFILE,
    )
    .unwrap();

    // Header must carry the FLAG_KEYFILE bit.
    let header = peek_header(&output).unwrap();
    assert!(header.flags & FLAG_KEYFILE != 0);
    assert!(header.flags & FLAG_MASTER_KEY != 0);

    decrypt_file(&output, &recovered, &combined).unwrap();
    assert_eq!(fs::read(&input).unwrap(), fs::read(&recovered).unwrap());
}

#[test]
fn wrong_keyfile_fails_aead() {
    let dir = tmpdir("wrong-kf");
    let input = dir.join("doc.txt");
    let output = dir.join("doc.txt.bml");
    let recovered = dir.join("doc.roundtrip");
    let kf_good = dir.join("good.bin");
    let kf_bad = dir.join("bad.bin");
    write(&input, b"top secret payload");
    write(&kf_good, b"the right keyfile content");
    write(&kf_bad, b"the wrong keyfile content");

    let pwd = b"hunter2";
    let good_digest = keyfile::digest_file(&kf_good).unwrap();
    let bad_digest = keyfile::digest_file(&kf_bad).unwrap();
    let good_combined = keyfile::combine(pwd, Some(&good_digest));
    let bad_combined = keyfile::combine(pwd, Some(&bad_digest));

    encrypt_file(
        &input,
        &output,
        &good_combined,
        KdfParams::fast_for_tests(),
        FLAG_KEYFILE,
    )
    .unwrap();

    let err = decrypt_file(&output, &recovered, &bad_combined).unwrap_err();
    assert!(matches!(err, aegis::Error::Aead));
}

#[test]
fn wrong_password_with_right_keyfile_fails_aead() {
    let dir = tmpdir("wrong-pwd");
    let input = dir.join("doc.txt");
    let output = dir.join("doc.txt.bml");
    let recovered = dir.join("doc.roundtrip");
    let kf = dir.join("key.bin");
    write(&input, b"top secret payload");
    write(&kf, b"32-byte keyfile content here!");

    let digest = keyfile::digest_file(&kf).unwrap();
    let combined_good = keyfile::combine(b"correct password", Some(&digest));
    let combined_bad = keyfile::combine(b"wrong   password", Some(&digest));

    encrypt_file(
        &input,
        &output,
        &combined_good,
        KdfParams::fast_for_tests(),
        FLAG_KEYFILE,
    )
    .unwrap();

    let err = decrypt_file(&output, &recovered, &combined_bad).unwrap_err();
    assert!(matches!(err, aegis::Error::Aead));
}

#[test]
fn keyfile_digest_unchanged_by_repeated_calls() {
    // Guards against any state leakage between calls (e.g., bad hasher reuse).
    let dir = tmpdir("repeat");
    let kf = dir.join("k.bin");
    write(&kf, &vec![0xCDu8; 4096]);
    let mut digests = Vec::new();
    for _ in 0..5 {
        digests.push(keyfile::digest_file(&kf).unwrap());
    }
    for d in &digests[1..] {
        assert_eq!(d, &digests[0]);
    }
}
