mod constants;
mod utils;

use crate::utils::{byte_decode, byte_encode, kpke_decrypt, kpke_encrypt, kpke_keygen};
use rand::{CryptoRng, RngCore};
use sha3::{digest::{FixedOutput, Update}, Sha3_256, Sha3_512};

/// Generates a key pair
///   
/// # Arguments
/// - key_length: could 512, 768 or 1024  
/// - rng: cryptographically secure PRG 
/// 
/// # caReturn value
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

/// Uses the encapsulation key to generate a shared key and an 
/// associated ciphertext.
/// 
/// # Arguments
/// - ek: encapsulation key 
/// - rng: cryptographically secure pseudo random number generator
/// 
/// # Return value
/// Tuple with the shared key and the associated ciphertext
pub fn encapsulate(ek: Vec<u8>, mut rng: impl RngCore + CryptoRng) -> Option<([u8; 32], Vec<u8>)> {
  let mut m = [0 as u8; 32];
  rng.fill_bytes(&mut m);

  // Validate key length
  let k = (ek.len() - 32) / 384;
  if k != 2 && k != 3 && k != 4 {
    println!("A");
    return None;
  }

  // Check for rounding errors
  if ek.len() != 384 * k + 32 {
    println!("B");
    return None;
  }

  // Check for modulus
  for ek_chunk in ek.chunks_exact(384) {
    if ek_chunk != byte_encode(&byte_decode(&ek_chunk.to_vec(), 12).unwrap(), 12).unwrap() {
      println!("C");
      return None;
    }
  }

  // Parameters selection 
  let (eta_1, eta_2, du, dv) = match k {
    2 => (3, 2, 10, 4),
    3 => (2, 2, 10, 4),
    4 => (2, 2, 11, 5),
    _ => unreachable!()
  };

  // Encapsulation
  let mut h = [0 as u8; 32];
  Sha3_256::default().chain(ek.clone()).finalize_into((&mut h).into());

  let mut g = [0 as u8; 64];
  Sha3_512::default().chain(m).chain(h).finalize_into((&mut g).into());
    
  let (key, r) = g.split_at(32);
  let c = kpke_encrypt(ek, m, r.try_into().unwrap(), k, eta_1, eta_2, du, dv);

  Some((key.try_into().expect("Incorrect shared key length."), c))
}
