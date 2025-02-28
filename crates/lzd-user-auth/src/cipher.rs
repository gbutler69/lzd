use aes_gcm_siv::{aead::Aead, Aes256GcmSiv, KeyInit};
use argon2::{
    password_hash::{self, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use crypto_common::generic_array::GenericArray;
use rand::TryRngCore;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Base64 decoding error: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    #[error("Cipher secreat invalid length: {0}")]
    CipherKeyInvalidLength(#[from] crypto_common::InvalidLength),
    #[error("Hash failure: {0}")]
    Hash(password_hash::Error),
    #[error("Encryption or Decryption failed: {0}")]
    EncryptionDecryption(aes_gcm_siv::Error),
    #[error("Parsing Stored Pass Phrase Hash: {0}")]
    StoredPassPhraseUnableToParse(password_hash::Error),
    #[error("Unable to verify Pass Phrase: {0}")]
    PassPhraseUnableToVerify(password_hash::Error),
}

pub struct Cipher {
    master: Aes256GcmSiv,
}

impl Cipher {
    pub fn from_base64_encoded(secret: &str) -> Result<Cipher, Error> {
        let key = STANDARD_NO_PAD.decode(secret.as_bytes())?;
        Ok(Cipher {
            master: Aes256GcmSiv::new_from_slice(&key)?,
        })
    }

    pub fn hash_passphrase(&self, pass_phrase: &[u8]) -> Result<String, Error> {
        let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        Argon2::default()
            .hash_password(pass_phrase, &salt)
            .map(|h| h.to_string())
            .map_err(|err| Error::Hash(err))
    }

    pub fn verify_pass_phrase(
        &self,
        pass_phrase: &str,
        pass_phrase_hash: &str,
    ) -> Result<bool, Error> {
        let parsed_pass_phrase = PasswordHash::new(pass_phrase_hash)
            .map_err(|err| Error::StoredPassPhraseUnableToParse(err))?;
        let pass_phrase = pass_phrase
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();
        match Argon2::default().verify_password(pass_phrase.as_bytes(), &parsed_pass_phrase) {
            Ok(_) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(err) => Err(Error::PassPhraseUnableToVerify(err)),
        }
    }

    pub fn encrypt_content_with_new_key_and_supply_encrypted_content_and_key(
        &self,
        content: &[u8],
    ) -> Result<EncryptedContentAndKey, Error> {
        let key = Aes256GcmSiv::generate_key(&mut aes_gcm_siv::aead::OsRng);
        let mut nonce = [0; 12];
        rand::rng().try_fill_bytes(&mut nonce).ok();
        let nonce = GenericArray::from_slice(&nonce);
        let mut encrypted_key = self
            .master
            .encrypt(nonce, key.as_slice())
            .map_err(|err| Error::EncryptionDecryption(err))?;
        encrypted_key.extend_from_slice(nonce.as_slice());
        let encrypted_content = self.encrypt_with_unencrypted_key(key.as_slice(), content)?;
        Ok(EncryptedContentAndKey {
            encrypted_content,
            encrypted_key,
        })
    }

    fn encrypt_with_unencrypted_key(&self, key: &[u8], content: &[u8]) -> Result<Vec<u8>, Error> {
        let key = GenericArray::from_slice(key);
        let mut nonce = [0; 12];
        rand::rng().try_fill_bytes(&mut nonce).ok();
        let nonce = GenericArray::from_slice(&nonce);
        let cipher = Aes256GcmSiv::new(key);
        let mut encrypted_content = cipher
            .encrypt(nonce, content)
            .map_err(|err| Error::EncryptionDecryption(err))?;
        encrypted_content.extend_from_slice(nonce.as_slice());
        Ok(encrypted_content)
    }
}

impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cipher")
            .field("master", &"redacted")
            .finish()
    }
}

pub struct EncryptedContentAndKey {
    pub encrypted_content: Vec<u8>,
    pub encrypted_key: Vec<u8>,
}
