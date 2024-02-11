mod constants;
mod utils;

pub mod mlkem {
  
  use crate::utils::{kpke_decrypt, kpke_encrypt, kpke_keygen};
  use rand::{CryptoRng, RngCore};
  use sha3::{Sha3_256, digest::{Update, FixedOutput}};

  /// Generates a key pair
  ///   
  /// Arguments
  /// key_length: could 512, 768 or 1024
  /// 
  /// Return value
  /// encapsulation and decapsulation key
  pub fn keygen(key_length: u16, mut rng: impl RngCore + CryptoRng) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut z = [0 as u8; 32];
    let mut s = [0 as u8; 32];

    rng.fill_bytes(&mut z);
    rng.fill_bytes(&mut s);

    let (k, eta) = match key_length {
      512 =>  (2, 3),
      768 => (3, 2),
      1024 => (4, 2),
      _ => return None
    };

    let (ek, pdk) = kpke_keygen(&s, k, eta);

    let mut dk = vec![0 as u8; 768 * k + 96];

    let pdk_l = pdk.len();
    let ek_l = ek.len();

    dk[0..pdk_l].copy_from_slice(&pdk);
    dk[pdk_l..(pdk_l + ek_l)].copy_from_slice(&ek);
    dk[(pdk_l + ek_l)..(pdk_l + ek_l + 32)].copy_from_slice(&Sha3_256::default().chain(ek.clone()).finalize_fixed());
    dk[(pdk_l + ek_l + 32)..].copy_from_slice(&z);

    Some((ek, dk))
  }

}