pub mod aead;
pub mod error;
pub mod file;
pub mod header;
pub mod kdf;
pub mod key;
pub mod keyfile;
pub mod stream;

pub use aead::{decrypt, encrypt};
pub use error::{Error, Result};
pub use file::{decrypt_dir, decrypt_file, encrypt_dir, encrypt_file, peek_header};
pub use header::{CHUNK_SIZE, FLAG_DIRECTORY, FLAG_KEYFILE, FLAG_MASTER_KEY, HEADER_LEN, Header};
pub use kdf::{KdfParams, derive_key, random_salt};
pub use key::Key;
pub use stream::{StreamDecoder, StreamEncoder};
