use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    Kdf(argon2::Error),
    Aead,
    Rng(getrandom::Error),
    Io(io::Error),
    InvalidHeader(&'static str),
    InvalidLength { expected: usize, got: usize },
    ChunkCounterOverflow,
    OutputAlreadyExists,
    Truncated,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Kdf(e) => write!(f, "key derivation failed: {e}"),
            Error::Aead => write!(
                f,
                "authenticated decryption failed (wrong password or tampered data)"
            ),
            Error::Rng(e) => write!(f, "random number generator failed: {e}"),
            Error::Io(e) => write!(f, "i/o error: {e}"),
            Error::InvalidHeader(why) => write!(f, "invalid file header: {why}"),
            Error::InvalidLength { expected, got } => {
                write!(f, "invalid length: expected {expected}, got {got}")
            }
            Error::ChunkCounterOverflow => write!(f, "stream chunk counter overflowed"),
            Error::OutputAlreadyExists => write!(f, "output path already exists"),
            Error::Truncated => write!(f, "encrypted file is truncated or empty"),
        }
    }
}

impl std::error::Error for Error {}

impl From<argon2::Error> for Error {
    fn from(e: argon2::Error) -> Self {
        Error::Kdf(e)
    }
}

impl From<getrandom::Error> for Error {
    fn from(e: getrandom::Error) -> Self {
        Error::Rng(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
