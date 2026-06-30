use crate::error::{Error, Result};
use crate::kdf::{KdfParams, SALT_LEN};

pub const MAGIC: &[u8; 4] = b"BML1";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 64;
pub const NONCE_PREFIX_LEN: usize = 19;
pub const CHUNK_SIZE: usize = 65536;

pub const FLAG_DIRECTORY: u8 = 0b0000_0001;
pub const FLAG_MASTER_KEY: u8 = 0b0000_0010;
pub const FLAG_KEYFILE: u8 = 0b0000_0100;
/// The payload is gzip-compressed before encryption (directories only).
pub const FLAG_COMPRESSED: u8 = 0b0000_1000;
const KNOWN_FLAGS: u8 = FLAG_DIRECTORY | FLAG_MASTER_KEY | FLAG_KEYFILE | FLAG_COMPRESSED;

const MAX_MEMORY_KIB: u32 = 4 * 1024 * 1024;
const MAX_ITERATIONS: u32 = 64;
const MAX_PARALLELISM: u32 = 64;

#[derive(Clone, Debug)]
pub struct Header {
    pub flags: u8,
    pub kdf_params: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
}

impl Header {
    pub fn new(flags: u8, kdf_params: KdfParams) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        getrandom::getrandom(&mut salt)?;
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        getrandom::getrandom(&mut nonce_prefix)?;
        Ok(Self {
            flags,
            kdf_params,
            salt,
            nonce_prefix,
        })
    }

    pub fn serialize(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(MAGIC);
        out[4] = VERSION;
        out[5] = self.flags;
        // bytes 6..8 reserved
        out[8..12].copy_from_slice(&self.kdf_params.memory_kib.to_be_bytes());
        out[12] = u8::try_from(self.kdf_params.iterations.min(255)).unwrap_or(255);
        out[13] = u8::try_from(self.kdf_params.parallelism.min(255)).unwrap_or(255);
        // bytes 14..16 reserved
        out[16..32].copy_from_slice(&self.salt);
        out[32..51].copy_from_slice(&self.nonce_prefix);
        // bytes 51..64 reserved
        out
    }

    pub fn parse(bytes: &[u8; HEADER_LEN]) -> Result<Self> {
        if &bytes[0..4] != MAGIC {
            return Err(Error::InvalidHeader("magic mismatch"));
        }
        if bytes[4] != VERSION {
            return Err(Error::InvalidHeader("unsupported version"));
        }
        let flags = bytes[5];
        // We only know FLAG_DIRECTORY today; refuse unknown bits to be forward-safe.
        if flags & !KNOWN_FLAGS != 0 {
            return Err(Error::InvalidHeader("unknown flag bits set"));
        }

        let memory_kib = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        let iterations = u32::from(bytes[12]);
        let parallelism = u32::from(bytes[13]);

        if memory_kib == 0
            || memory_kib > MAX_MEMORY_KIB
            || iterations == 0
            || iterations > MAX_ITERATIONS
            || parallelism == 0
            || parallelism > MAX_PARALLELISM
        {
            return Err(Error::InvalidHeader("Argon2 params out of range"));
        }

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[16..32]);
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        nonce_prefix.copy_from_slice(&bytes[32..51]);

        Ok(Self {
            flags,
            kdf_params: KdfParams {
                memory_kib,
                iterations,
                parallelism,
            },
            salt,
            nonce_prefix,
        })
    }
}
