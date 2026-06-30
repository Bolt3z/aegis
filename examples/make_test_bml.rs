use std::path::PathBuf;

use aegis::{KdfParams, encrypt_dir, encrypt_file};

fn main() {
    // File case
    let plain = PathBuf::from("/tmp/bml-smoke-plain.txt");
    let cipher = PathBuf::from("/tmp/bml-smoke.txt.bml");
    let _ = std::fs::remove_file(&plain);
    let _ = std::fs::remove_file(&cipher);
    std::fs::write(&plain, b"BitlokerMeglio smoke-test payload\nLine 2: secret\n").unwrap();
    encrypt_file(&plain, &cipher, b"hunter2", KdfParams::fast_for_tests(), 0).unwrap();

    // Directory case
    let src = PathBuf::from("/tmp/bml-smoke-dir");
    let dir_cipher = PathBuf::from("/tmp/bml-smoke-dir.bml");
    let _ = std::fs::remove_dir_all(&src);
    let _ = std::fs::remove_file(&dir_cipher);
    std::fs::create_dir_all(src.join("sub/deeper")).unwrap();
    std::fs::write(src.join("a.txt"), b"alpha contents\n").unwrap();
    std::fs::write(src.join("b.md"), b"# beta\n\nsome markdown\n").unwrap();
    std::fs::write(src.join("sub/c.bin"), &vec![0x42u8; 4096]).unwrap();
    std::fs::write(src.join("sub/deeper/d.txt"), b"deep file\n").unwrap();
    encrypt_dir(&src, &dir_cipher, b"hunter2", KdfParams::fast_for_tests(), 0).unwrap();

    println!("== File ==");
    println!("plain:  {}", plain.display());
    println!("cipher: {}", cipher.display());
    println!();
    println!("== Directory ==");
    println!("src:    {}", src.display());
    println!("cipher: {}", dir_cipher.display());
    println!();
    println!("Password for both: hunter2");
}
