use std::fs::File;
use std::io::Read;
use std::path::Path;

use blake2::{Blake2b, Digest, digest::consts::U32};

pub const DIGEST_LEN: usize = 32;
pub const DEFAULT_SIZE: usize = 64;
const READ_CHUNK: usize = 64 * 1024;

type Blake2b256 = Blake2b<U32>;

/// Stream-hash the entire content of a keyfile with BLAKE2b-256.
/// Returns a fixed 32-byte digest regardless of file size.
pub fn digest_file(path: &Path) -> Result<[u8; DIGEST_LEN], String> {
    let mut file = File::open(path).map_err(|e| format!("cannot open keyfile: {e}"))?;
    let mut hasher = Blake2b256::new();
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("cannot read keyfile: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let out = hasher.finalize();
    let mut digest = [0u8; DIGEST_LEN];
    digest.copy_from_slice(&out);
    Ok(digest)
}

/// Combine password bytes with an optional keyfile digest into the Argon2
/// input. If digest is None, returns a clone of the password (byte-for-byte
/// identical to the pre-keyfile behavior, so existing .bml files keep working).
pub fn combine(password: &[u8], digest: Option<&[u8; DIGEST_LEN]>) -> Vec<u8> {
    match digest {
        None => password.to_vec(),
        Some(d) => {
            let mut out = Vec::with_capacity(password.len() + DIGEST_LEN);
            out.extend_from_slice(password);
            out.extend_from_slice(d);
            out
        }
    }
}
