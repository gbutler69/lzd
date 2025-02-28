use aes_gcm_siv::{
    Aes256GcmSiv,
    aead::{KeyInit, OsRng},
};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};

fn main() {
    let key = Aes256GcmSiv::generate_key(&mut OsRng);
    let encoded_key = STANDARD_NO_PAD.encode(key.as_slice());
    println!("AES-256 GCM SIV (Base0-64 encoded): {encoded_key}");
}
