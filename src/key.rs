use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_LEN: usize = 32;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key").field("bytes", &"<redacted>").finish()
    }
}
