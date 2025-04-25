/*
See https://github.com/runassu/chrome_v20_decryption/blob/main/decrypt_chrome_v20_cookie.py
cargo build --release --features appbound
*/
use base64::{prelude::BASE64_STANDARD, Engine};
use eyre::{bail, Result};

use aes_gcm::{
  aead::{generic_array::GenericArray, Aead, KeyInit},
  Aes256Gcm, Key,
};
use chacha20poly1305::ChaCha20Poly1305;

mod impersonate;

fn decrypt(key: &mut [u8], as_system: bool) -> Result<Vec<u8>> {
  let mut handle = None;
  if as_system {
    handle = Some(impersonate::start_impersonate()?);
  }
  let result = crate::windows::dpapi::decrypt(key)?;
  if let Some(handle) = handle {
    impersonate::stop_impersonate(handle)?;
  }
  Ok(result)
}

pub fn get_keys(key64: &str) -> Result<Vec<Vec<u8>>> {
  let mut keys: Vec<Vec<u8>> = Vec::new();

  let key_u8 = BASE64_STANDARD.decode(key64)?;
  if !key_u8.starts_with(b"APPB") {
    bail!("key not starts with APPB")
  }
  let key_u8 = &key_u8[4..];
  let key64 = BASE64_STANDARD.encode(key_u8);
  let mut system_decrypted = decrypt(&mut BASE64_STANDARD.decode(key64)?, true)?;
  let user_decrypted = decrypt(&mut system_decrypted, false)?;
  let key = &user_decrypted[user_decrypted.len() - 61..];

  // Most chrome browsers can use the system->user decrypted key directly (last 32 bytes)
  keys.push(key[key.len() - 32..].to_vec());

  // Chrome also decrypt the decrypted key with hardcoded AES key from elevation_service.exe
  let decrypted_key = &key[key.len() - 61..];
  let flag = decrypted_key[0];
  let iv = &decrypted_key[1..1 + 12];
  let ciphertext = &decrypted_key[1 + 12..];
  let nonce = GenericArray::from_slice(iv); // 96-bits; unique per message
  if flag == 1 {
    let aes_key = b"\xB3\x1C\x6E\x24\x1A\xC8\x46\x72\x8D\xA9\xC1\xFA\xC4\x93\x66\x51\xCF\xFB\x94\x4D\x14\x3A\xB8\x16\x27\x6B\xCC\x6D\xA0\x28\x47\x87";
    let aes_key = Key::<Aes256Gcm>::from_slice(aes_key);
    let cipher = Aes256Gcm::new(aes_key);
    if let Ok(plain) = cipher.decrypt(nonce, ciphertext) {
      keys.push(plain)
    }
  } else if flag == 2 {
    let chacha_key = b"\xE9\x8F\x37\xD7\xF4\xE1\xFA\x43\x3D\x19\x30\x4D\xC2\x25\x80\x42\x09\x0E\x2D\x1D\x7E\xEA\x76\x70\xD4\x1F\x73\x8D\x08\x72\x96\x60";
    let chacha_key = Key::<ChaCha20Poly1305>::from_slice(chacha_key);
    let cipher = ChaCha20Poly1305::new(chacha_key);
    if let Ok(plain) = cipher.decrypt(nonce, ciphertext) {
      keys.push(plain)
    }
  }

  Ok(keys)
}
