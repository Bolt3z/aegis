//! Thin wrapper around the system secret service (libsecret / kwallet on Linux)
//! storing the user's "master password" under `service="aegis", account="master"`.

const SERVICE: &str = "aegis";
const ACCOUNT: &str = "master";

#[derive(Debug)]
pub enum KeychainError {
    Unavailable(String),
}

impl std::fmt::Display for KeychainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeychainError::Unavailable(msg) => {
                write!(f, "system keyring is unavailable: {msg}")
            }
        }
    }
}

impl std::error::Error for KeychainError {}

pub fn service() -> &'static str {
    SERVICE
}

pub fn account() -> &'static str {
    ACCOUNT
}

fn entry() -> Result<keyring::Entry, KeychainError> {
    keyring::Entry::new(SERVICE, ACCOUNT).map_err(|e| KeychainError::Unavailable(e.to_string()))
}

pub fn set_master(password: &str) -> Result<(), KeychainError> {
    entry()?
        .set_password(password)
        .map_err(|e| KeychainError::Unavailable(e.to_string()))
}

/// Returns `Ok(None)` if no master is stored, `Ok(Some(pwd))` if one is.
pub fn get_master() -> Result<Option<String>, KeychainError> {
    let e = entry()?;
    match e.get_password() {
        Ok(p) => Ok(Some(p)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => Err(KeychainError::Unavailable(err.to_string())),
    }
}

/// Returns `true` if a master entry existed and was removed, `false` if nothing
/// was stored to begin with.
pub fn forget_master() -> Result<bool, KeychainError> {
    let e = entry()?;
    match e.delete_password() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(err) => Err(KeychainError::Unavailable(err.to_string())),
    }
}

pub fn is_set() -> Result<bool, KeychainError> {
    Ok(get_master()?.is_some())
}
