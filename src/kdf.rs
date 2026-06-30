use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::Result;
use crate::key::{KEY_LEN, Key};

pub const SALT_LEN: usize = 16;

#[derive(Clone, Copy, Debug)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    pub const fn default_strong() -> Self {
        Self {
            memory_kib: 256 * 1024,
            iterations: 3,
            parallelism: 4,
        }
    }

    pub const fn fast_for_tests() -> Self {
        Self {
            memory_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
        }
    }
}

pub fn random_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt)?;
    Ok(salt)
}

pub fn derive_key(password: &[u8], salt: &[u8; SALT_LEN], params: KdfParams) -> Result<Key> {
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut out = [0u8; KEY_LEN];
    argon.hash_password_into(password, salt, &mut out)?;
    let key = Key::from_bytes(out);
    out.fill(0);
    Ok(key)
}
