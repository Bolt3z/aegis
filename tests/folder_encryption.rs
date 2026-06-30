use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use aegis::{
    CHUNK_SIZE, Error, FLAG_DIRECTORY, KdfParams, decrypt_dir, decrypt_file, encrypt_dir,
    encrypt_file, peek_header,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn fresh_tmpdir(name: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "bml-folder-{}-{}-{}-{n}",
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
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut f = fs::File::create(path).unwrap();
    f.write_all(content).unwrap();
    f.sync_all().unwrap();
}

fn collect_files(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let e = entry.unwrap();
            let p = e.path();
            if p.is_dir() {
                walk(&p, base, out);
            } else if p.is_file() {
                let rel = p.strip_prefix(base).unwrap().to_path_buf();
                let content = fs::read(&p).unwrap();
                out.push((rel, content));
            }
        }
    }
    let mut v = Vec::new();
    walk(root, root, &mut v);
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

const PWD: &[u8] = b"a strong-enough test password";

fn fast() -> KdfParams {
    KdfParams::fast_for_tests()
}

#[test]
fn folder_round_trip_simple() {
    let workspace = fresh_tmpdir("simple");
    let src = workspace.join("src");
    write_file(&src.join("hello.txt"), b"Hello, world!\n");
    write_file(&src.join("readme.md"), b"# Test project\n");
    let cipher = workspace.join("archive.bml");
    let restored = workspace.join("restored");

    encrypt_dir(&src, &cipher, PWD, fast(), 0).unwrap();
    decrypt_dir(&cipher, &restored, PWD).unwrap();

    let original = collect_files(&src);
    let got = collect_files(&restored);
    assert_eq!(got, original);
}

#[test]
fn folder_round_trip_nested() {
    let workspace = fresh_tmpdir("nested");
    let src = workspace.join("src");
    write_file(&src.join("a.txt"), b"top level");
    write_file(&src.join("dir1/b.txt"), b"nested 1");
    write_file(&src.join("dir1/dir2/c.txt"), b"deep");
    write_file(&src.join("dir1/dir2/dir3/d.bin"), &vec![0xAAu8; 12345]);
    write_file(&src.join("other/x.log"), b"log entry");
    let cipher = workspace.join("archive.bml");
    let restored = workspace.join("restored");

    encrypt_dir(&src, &cipher, PWD, fast(), 0).unwrap();
    decrypt_dir(&cipher, &restored, PWD).unwrap();

    let original = collect_files(&src);
    let got = collect_files(&restored);
    assert_eq!(got, original);
}

#[test]
fn folder_round_trip_with_large_file() {
    let workspace = fresh_tmpdir("large");
    let src = workspace.join("src");
    write_file(&src.join("small.txt"), b"small");
    // > 3 chunks
    let big: Vec<u8> = (0..3 * CHUNK_SIZE + 7777).map(|i| (i % 251) as u8).collect();
    write_file(&src.join("sub/big.bin"), &big);
    let cipher = workspace.join("archive.bml");
    let restored = workspace.join("restored");

    encrypt_dir(&src, &cipher, PWD, fast(), 0).unwrap();
    decrypt_dir(&cipher, &restored, PWD).unwrap();

    let original = collect_files(&src);
    let got = collect_files(&restored);
    assert_eq!(got, original);
}

#[test]
fn header_has_directory_flag_after_encrypt_dir() {
    let workspace = fresh_tmpdir("flag");
    let src = workspace.join("src");
    write_file(&src.join("x.txt"), b"data");
    let cipher = workspace.join("a.bml");

    encrypt_dir(&src, &cipher, PWD, fast(), 0).unwrap();
    let header = peek_header(&cipher).unwrap();
    assert_eq!(header.flags & FLAG_DIRECTORY, FLAG_DIRECTORY);
}

#[test]
fn header_has_no_directory_flag_after_encrypt_file() {
    let workspace = fresh_tmpdir("flag_file");
    let plain = workspace.join("plain.txt");
    write_file(&plain, b"data");
    let cipher = workspace.join("a.bml");

    encrypt_file(&plain, &cipher, PWD, fast(), 0).unwrap();
    let header = peek_header(&cipher).unwrap();
    assert_eq!(header.flags & FLAG_DIRECTORY, 0);
}

#[test]
fn decrypt_file_refuses_directory_payload() {
    let workspace = fresh_tmpdir("mismatch_file");
    let src = workspace.join("src");
    write_file(&src.join("x.txt"), b"data");
    let cipher = workspace.join("a.bml");
    let restored = workspace.join("restored");
    encrypt_dir(&src, &cipher, PWD, fast(), 0).unwrap();

    let err = decrypt_file(&cipher, &restored, PWD).unwrap_err();
    assert!(matches!(err, Error::InvalidHeader(_)), "got {err:?}");
}

#[test]
fn decrypt_dir_refuses_file_payload() {
    let workspace = fresh_tmpdir("mismatch_dir");
    let plain = workspace.join("plain.txt");
    write_file(&plain, b"data");
    let cipher = workspace.join("a.bml");
    let restored = workspace.join("restored");
    encrypt_file(&plain, &cipher, PWD, fast(), 0).unwrap();

    let err = decrypt_dir(&cipher, &restored, PWD).unwrap_err();
    assert!(matches!(err, Error::InvalidHeader(_)), "got {err:?}");
}

#[test]
fn decrypt_dir_refuses_non_empty_output_directory() {
    let workspace = fresh_tmpdir("non_empty_out");
    let src = workspace.join("src");
    write_file(&src.join("x.txt"), b"data");
    let cipher = workspace.join("a.bml");
    let restored = workspace.join("restored");
    fs::create_dir_all(&restored).unwrap();
    write_file(&restored.join("existing.txt"), b"do not clobber");

    encrypt_dir(&src, &cipher, PWD, fast(), 0).unwrap();
    let err = decrypt_dir(&cipher, &restored, PWD).unwrap_err();
    assert!(matches!(err, Error::OutputAlreadyExists), "got {err:?}");
}

#[test]
fn decrypt_dir_accepts_existing_empty_output_directory() {
    let workspace = fresh_tmpdir("empty_out");
    let src = workspace.join("src");
    write_file(&src.join("x.txt"), b"data");
    let cipher = workspace.join("a.bml");
    let restored = workspace.join("restored");
    fs::create_dir_all(&restored).unwrap();

    encrypt_dir(&src, &cipher, PWD, fast(), 0).unwrap();
    decrypt_dir(&cipher, &restored, PWD).unwrap();
    let got = collect_files(&restored);
    let original = collect_files(&src);
    assert_eq!(got, original);
}

#[test]
fn folder_wrong_password_fails_cleanly() {
    let workspace = fresh_tmpdir("dir_wrong_pwd");
    let src = workspace.join("src");
    write_file(&src.join("x.txt"), b"data");
    let cipher = workspace.join("a.bml");
    let restored = workspace.join("restored");

    encrypt_dir(&src, &cipher, PWD, fast(), 0).unwrap();
    let err = decrypt_dir(&cipher, &restored, b"wrong password").unwrap_err();
    assert!(matches!(err, Error::Aead), "got {err:?}");
    // Tmp dir must have been cleaned up
    let tmp = {
        let mut s: std::ffi::OsString = restored.as_os_str().into();
        s.push(".tmp");
        PathBuf::from(s)
    };
    assert!(!tmp.exists(), "tmp dir leaked: {tmp:?}");
    assert!(!restored.exists(), "restored should not be present");
}

#[test]
fn folder_tampered_payload_fails() {
    let workspace = fresh_tmpdir("dir_tamper");
    let src = workspace.join("src");
    write_file(&src.join("x.txt"), &vec![0x55u8; 500]);
    let cipher = workspace.join("a.bml");
    let restored = workspace.join("restored");

    encrypt_dir(&src, &cipher, PWD, fast(), 0).unwrap();
    // Flip a byte well past the header.
    let mut bytes = fs::read(&cipher).unwrap();
    let idx = 100.min(bytes.len() - 1);
    bytes[idx] ^= 0x01;
    fs::remove_file(&cipher).unwrap();
    let mut f = fs::File::create(&cipher).unwrap();
    f.write_all(&bytes).unwrap();
    f.sync_all().unwrap();

    let err = decrypt_dir(&cipher, &restored, PWD).unwrap_err();
    assert!(matches!(err, Error::Aead), "got {err:?}");
}
