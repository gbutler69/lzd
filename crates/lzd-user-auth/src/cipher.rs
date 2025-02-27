use aes_gcm_siv::{Aes256GcmSiv, KeyInit};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Base64 decoding error: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    #[error("Cipher secreat invalid length: {0}")]
    CipherKeyInvalidLength(#[from] crypto_common::InvalidLength),
}

pub fn create(secret: &str) -> Result<Aes256GcmSiv, Error> {
    let key = STANDARD_NO_PAD.decode(secret.as_bytes())?;
    Aes256GcmSiv::new_from_slice(&key).map_err(Into::into)
}
