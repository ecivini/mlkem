use crate::constants::{Q, N, ZETAS, GAMMAS};
use sha3::{Shake128, Shake256, digest::{Update, ExtendableOutput, XofReader, FixedOutput}};

/// Element in Z_q. Since q = 3329 < 2^16, 16 bits are enough
type FieldElement = u16;

/// Polynomial in R_q
type RingElement = [FieldElement; N]; 

/// Converts a vector of bits into a vector of bytes (assumes little endian)
/// 
/// # Arguments
/// bits: vector of bits. Each element must be either 0 or 1
/// 
/// # Return value
/// Vector of the byte reprgesentation 
fn bits_to_bytes(bits: Vec<u8>) -> Option<Vec<u8>> {
  let bits_length = bits.len();
  if bits_length % 8 != 0 {
    return None;
  }

  let mut bytes: Vec<u8> = vec![0; bits_length / 8];
  for (index, bit) in bits.iter().enumerate() {
    let shift_pos = index % 8;
    let byte_pos = index / 8;
    bytes[byte_pos] |= bit << shift_pos;
  }

  Some(bytes)
}

/// Converts a vector of bytes into a vector of bits (little endian)
/// 
/// # Arguments
/// bits: vector of bytes.
/// 
/// # Return value
/// Vector of the bit representation 
fn bytes_to_bits(bytes: Vec<u8>) -> Option<Vec<u8>> {
  let bits_length = bytes.len() * 8;
  let mut bits = vec![0; bits_length];

  for (index, byte) in bytes.iter().enumerate() {
    let base = index * 8;
    bits[base]     = byte & 0b00000001;
    bits[base + 1] = (byte & 0b00000010) >> 1;
    bits[base + 2] = (byte & 0b00000100) >> 2;
    bits[base + 3] = (byte & 0b00001000) >> 3;
    bits[base + 4] = (byte & 0b00010000) >> 4;
    bits[base + 5] = (byte & 0b00100000) >> 5;
    bits[base + 6] = (byte & 0b01000000) >> 6;
    bits[base + 7] = (byte & 0b10000000) >> 7;
  }

  Some(bits)
}

/// Encodes an array of d-bit integers into a byte array
/// 
/// # Arguments
/// f: Integers modulo m array of length 256
/// d: Segment size (1 <= d <= 12). If d < 12, then m = 2^d. If d = 12, m = Q
/// 
/// # Return value
/// Encoded byte array of length 32 * d
pub fn byte_encode(f: &RingElement, d: u8) -> Option<Vec<u8>> {
  let mut bits: Vec<u8> = vec![0; 256 * d as usize];

  for i in 0..N {
    let mut a = f[i];
    for j in 0..d {
      let index = i * d as usize + j as usize;
      bits[index] = (a & 0b1) as u8;
      a = a >> 1;
    }
  }

  bits_to_bytes(bits)
}

/// Decodes a byte array into an array of d-bit integers
/// 
/// Arguments
/// b: Encoded byte array of length 32 * d
/// d: Segment size (1 <= d <= 12). If d < 12, then m = 2^d. If d = 12, m = Q
/// 
/// Return value
/// Array of d-bit integers
pub fn byte_decode(b: &Vec<u8>, d: u8) -> Option<RingElement> {
  let bits = bytes_to_bits(b.to_vec()).unwrap();
  let mut integers: RingElement = [0; N];

  let mut modulo = Q;
  if d < 12 {
    modulo = 2_u16.pow(d.into());
  }

  for i in 0..N {
    for j in 0..d {
      let index = i * d as usize + j as usize;
      integers[i] += (bits[index] as u16) << j;
    }
    integers[i] %= modulo;
  }

  Some(integers)
}

/// Divides and rounds to the nearest integer
/// 
/// Arguments
/// dividend: dividend
/// divisor: divisor
/// 
/// Return value
/// round(dividend / divisor)
fn div_and_round(dividend: u32, divisor: u32) -> FieldElement {
  field_reduce(((dividend + (divisor >> 1)) / divisor) as u16)
}

/// Compresses a RingElement
///
/// Arguments
/// f: ring element
/// d: exponent
/// 
/// Return value
/// Compressed element
fn compress(mut f: RingElement, d: u16) -> RingElement{
  for i in 0..N {
    f[i] = div_and_round((1 << d) as u32 * f[i] as u32, Q as u32);
  }

  f 
}

/// Decompresses a RingElement
///
/// Arguments
/// f: ring element
/// d: exponent
/// 
/// Return value
/// Compressed element
fn decompress(mut f: RingElement, d: u16) -> RingElement{
  for i in 0..N {
    f[i] = div_and_round(f[i] as u32 * Q as u32, (1 << d) as u32);
  }

  f 
}

/// Reduce an element into Z_q in constant time
/// 
/// Taken from Filippo Valsorda' implementation
/// https://github.com/FiloSottile/mlkem768/blob/main/mlkem768.go#L360
/// 
/// # Arguments
/// e: element to reduce
/// 
/// # Return value
/// Reduced element
fn field_reduce(e: FieldElement) -> FieldElement {
  let we = e.wrapping_sub(Q);
  
  we.wrapping_add((we >> 15).wrapping_mul(Q))
}

/// Field multiplication
/// 
/// # Arguments
/// a: first element in the field
/// b: second element in the field
/// 
/// # Return value
/// Product of a and b reduced in the field
fn field_mul(a: FieldElement, b: FieldElement) -> FieldElement {
  ((a as u32).wrapping_mul(b as u32) % Q as u32) as FieldElement
}

/// Field addition
/// 
/// # Arguments
/// a: first element in the field
/// b: second element in the field
/// 
/// # Return value
/// Sum of a and b reduced in the field
fn field_add(a: FieldElement, b: FieldElement) -> FieldElement {
  field_reduce(a.wrapping_add(b))
}

/// Field subtraction
/// 
/// # Arguments
/// a: first element in the field
/// b: second element in the field
/// 
/// # Return value
/// Difference of a and b reduced in the field
fn field_sub(a: FieldElement, b: FieldElement) -> FieldElement {
  field_reduce(a.wrapping_sub(b).wrapping_add(Q))
}

/// Computes the NTT of the given polynomial f
/// 
/// Arguments
/// f: polynomial 
/// 
/// Return value
/// NTT Representation of f
fn ntt(f: RingElement) -> RingElement {
  let mut f_hat = f.clone();
  let mut k: usize = 1;
  let mut len = 128;

  while len >= 2 {
    let mut start = 0;
    while start < N {
      let zeta = ZETAS[k];
      k += 1;
      
      for j in start..(start + len) {
        let t = field_mul(zeta, f_hat[j + len]);
        f_hat[j + len] = field_sub(f_hat[j], t);
        f_hat[j] = field_add(f_hat[j], t);
      }

      start += 2 * len;
    }

    len /= 2;
  }

  f_hat 
}

/// Computes the inverse NTT of the given polynomial f_hat
/// 
/// Arguments
/// f_hat: NTT polynomial 
/// 
/// Return value
/// Original Representation of f_hat
pub fn inverse_ntt(f_hat: RingElement) -> RingElement {
  let mut f = f_hat.clone();
  let mut k: usize = 127;
  let mut len = 2;

  while len <= 128 {
    let mut start = 0;
    while start < N {
      let zeta = ZETAS[k];
      k -= 1;
      
      for j in start..(start + len) {
        let t = f[j];
        f[j] = field_add(t, f[j + len]);
        f[j + len] = field_mul(zeta, field_sub(f[j + len], t));
      }

      start += 2 * len;
    }

    len *= 2;
  }

  for i in 0..N {
    f[i] = field_mul(f[i], 3303);
  }

  f 
}

/// Converts a stream of bytes into a polynomial in the NTT domain
/// 
/// Arguments
/// bytes: byte stream
/// 
/// Return value
/// Coefficients of the NTT polynomial
fn sample_ntt(rho: &[u8], xof_i: u8, xof_j: u8) -> Option<RingElement> {
  // Random source
  let mut xof = Shake128::default().chain(rho).chain([xof_i, xof_j]).finalize_xof();

  let mut j = 0;
  let mut b = [0 as u8; 3];
  let mut f: RingElement = [0 as FieldElement; N];

  while j < N {
    // read three bytes
    xof.read(&mut b);

    let d_1 = b[0] as u16 + N as u16 * (b[1] as u16 & 0b1111);
    let d_2 = (b[1] / 16) as u16 + 16 * b[2] as u16;

    if d_1 < Q {
      f[j] = d_1;
      j += 1;
    }

    if d_2 < Q && j < N {
      f[j] = d_2;
      j += 1;
    }
  }

  Some(f)
} 

/// Samples the coeffcient array of a polynomial f ∈ Rq according to the
/// distribution Dη(Rq).
/// 
/// Arguments
/// 
/// 
/// Return value
/// Coefficients of the NTT polynomial
fn sample_poly_cbd(eta: usize, s: &[u8], b: u8) -> Option<RingElement> {
  if eta != 2 && eta != 3 {
    return None;
  }

  let mut xof_out = vec![0 as u8; 64 * eta];
  Shake256::default().chain(s).chain([b]).finalize_xof_into(&mut xof_out);
  let bits = bytes_to_bits(xof_out).unwrap();

  let mut f: RingElement = [0 as u16; N];
  for i in 0..N {
    let mut x: FieldElement = 0;
    let mut y: FieldElement = 0;

    for j in 0..eta {
      x += bits[2 * i * eta + j] as u16;
      y += bits[eta * 2 * i + eta + j] as u16;
    }

    f[i] = field_sub(x, y);
  }

  Some(f)
}

/// Adds two polynomials
/// 
/// Arguments
/// f: first polynomial
/// g: second polynomial
/// 
/// Return value
/// Sum of the two polynomials
fn poly_add(mut f: RingElement, g: RingElement) -> RingElement {
  for i in 0..N {
    f[i] = field_add(f[i], g[i]);
  }

  f
}

/// Subtracts two polynomials (f - g)
/// 
/// Arguments
/// f: first polynomial
/// g: second polynomial
/// 
/// Return value
/// Difference of the two polynomials
fn poly_sub(mut f: RingElement, g: RingElement) -> RingElement {
  for i in 0..N {
    f[i] = field_sub(f[i], g[i]);
  }

  f
}

/// Computes the product of two degree-one polynomials with respect to a 
/// quadratic modulus.
/// 
/// Polynomials are the following two:
/// - a_0 + a_1 * X
/// - b_0 * a_1 * X
/// 
/// Return value
/// Coefficients of the resulting polynomial
fn ntt_base_case_mul(a_0: FieldElement, a_1: FieldElement, b_0: FieldElement, b_1: FieldElement, gamma: FieldElement) -> (FieldElement, FieldElement) {
  let c_0 = field_add(field_mul(a_0, b_0), field_mul(field_mul(a_1, b_1), gamma));
  let c_1 = field_add(field_mul(a_0, b_1), field_mul(a_1, b_0));

  (c_0, c_1)
}

/// Computes the product (in the ring Tq) of two NTT representations.
/// 
/// Arguments
/// f: coefficients of the first NTT representation
/// g: coefficients of the second NTT representation
/// 
/// Return value
/// Coefficients of the resulting polynomial
fn ntt_mul(f: RingElement, g: RingElement) -> RingElement {
  let mut h: RingElement = [0; N];

  for i in 0..128 {
    let ti = 2 * i; // Two times I
    let tipo = 2 * i + 1; // Two times I Plus One
    (h[ti], h[tipo]) = ntt_base_case_mul(f[ti], f[tipo], g[ti], g[tipo], GAMMAS[i]); 
  }

  h
}

/// K-PKE Key generation algorithm
/// 
/// Arguments
/// s: random seed generated by a secure PRG
/// k: vectors dimension factor. 2 for ML-KEM 512, 3 for ML-KEM 768 and 
///   4 for ML-KEM 1024.
/// 
/// Return value
/// Key pair in the form of (encryption key, decryption key)
pub fn kpke_keygen(s: &[u8; 32], k: usize, eta_1: usize) -> (Vec<u8>, Vec<u8>) {
  let g_out = sha3::Sha3_512::default().chain(s).finalize_fixed();
  let (rho, sigma) = g_out.split_at(32);

  let mut a = vec![[0; N]; k * k];
  for i in 0..k {
    for j in 0..k {
      // i and j are inverted because of a typo in the draft
      a[i * k + j] = sample_ntt(rho, j as u8, i as u8).unwrap();
    } 
  }

  let mut s = vec![[0; N]; k];
  let mut e = vec![[0; N]; k];
  for i in 0..k {
    s[i] = ntt(sample_poly_cbd(eta_1, sigma, i as u8).unwrap());
    e[i] = ntt(sample_poly_cbd(eta_1, sigma, (k + i) as u8).unwrap());
  }

  // A mat_mul s + e
  let mut t = vec![[0; N]; k];
  for i in 0..k {
    t[i] = e[i];
    for j in 0..k {
      t[i] = poly_add(ntt_mul(a[i * k + j], s[j]), t[i]);
    }
  }

  let mut e_key = vec![0 as u8; k * 384 + 32];
  for i in 0..k {
    e_key[(i * 384)..(i + 1) * 384].copy_from_slice(byte_encode(&t[i], 12).unwrap().as_slice());
  }
  e_key[(k * 384)..].copy_from_slice(rho);

  let mut d_key = vec![0 as u8; 384 * k];
  for i in 0..k {
    d_key[(i * 384)..(i + 1) * 384].copy_from_slice(byte_encode(&s[i], 12).unwrap().as_slice());
  }

  (e_key, d_key)
}

/// Uses the encryption key to encrypt a plaintext message using randomness r.
/// 
/// Arguments
/// ek: encryption key
/// m: encoded plaintext
/// rand: randomness
/// k: vectors dimension factor. 2 for ML-KEM 512, 3 for ML-KEM 768 and 
///   4 for ML-KEM 1024.
/// du: bits for u
/// dv: bits for v
/// 
/// Return value
/// Ciphertext
pub fn kpke_encrypt(ek: Vec<u8>, m: [u8; 32], rand: [u8; 32], k: usize, eta_1: usize, eta_2: usize, du: u8, dv: u8) -> Vec<u8> {
  let (t_encoded, rho) = ek.split_at(384 * k);
  let mut t = vec![[0 as u16; N]; k];
  for (i, t_at) in t_encoded.chunks_exact(384).enumerate() {
    t[i] = byte_decode(&t_at.to_vec(), 12).unwrap();
  }

  let mut a = vec![[0; N]; k * k];
  for i in 0..k {
    for j in 0..k {
      a[i * k + j] = sample_ntt(rho, i as u8, j as u8).unwrap();
    } 
  }

  let mut r = vec![[0; N]; k];
  let mut e = vec![[0; N]; k];
  for i in 0..k {
    r[i] = ntt(sample_poly_cbd(eta_1, &rand, i as u8).unwrap());
    e[i] = sample_poly_cbd(eta_2, &rand, (k + i) as u8).unwrap();
  }

  let e_2 = sample_poly_cbd(eta_2, &rand, (2 * k) as u8).unwrap();

  // A transpose mat_mul r_hat + e
  let mut u = vec![[0; N]; k];
  for i in 0..k {
    u[i] = e[i];
    for j in 0..k {
      u[i] = poly_add(inverse_ntt(ntt_mul(a[i * k + j], r[j])), u[i]);
    }
  }

  let mu = decompress(byte_decode(&m.to_vec(), 1).unwrap(), 1);

  // t transpose mat_mul r_hat + e_2 + mu
  let mut v = [0 as u16; N];
  for i in 0..k {
    v = poly_add(ntt_mul(t[i], r[i]), v);
  }
  v = poly_add(poly_add(inverse_ntt(v), e_2), mu);

  let mut c_1 = vec![0 as u8; 32 * du as usize * k];
  for (i, c) in c_1.chunks_exact_mut(32 * du as usize).enumerate() {
    // Ugly as hell I know
    c.copy_from_slice(
        byte_encode(&compress(u[i], du as u16), du).unwrap().as_slice()
    );
  }

  let c_2 = byte_encode(&compress(v, dv as u16), dv).unwrap();

  [c_1, c_2].concat()
}

/// Decrypts a ciphertext
/// 
/// Arguments
/// dk: decryption key
/// c: ciphertext
/// 
/// Return value
/// Plaintext
pub fn kpke_decrypt(dk: Vec<u8>, c: Vec<u8>, k: usize, du: u8, dv: u8) -> Vec<u8> {
  let (c_1, c_2) = c.split_at(32 * du as usize * k);

  let mut u = vec![[0 as u16; N]; k];
  for (i, chunk) in c_1.chunks_exact(32 * du as usize).enumerate() {
    u[i] = decompress(byte_decode(&chunk.to_vec(), du).unwrap(), du as u16);
  }

  let v = decompress(byte_decode(&c_2.to_vec(), dv).unwrap(), dv as u16);

  let mut s_hat = vec![[0; N]; k];
  for (i, chunk) in dk.chunks_exact(384).enumerate() {
    s_hat[i] = byte_decode(&chunk.to_vec(), 12).unwrap();
  }

  let mut to_sub_term = [0; N];
  for (s, u) in s_hat.into_iter().zip(u) {
    to_sub_term = poly_add(to_sub_term, ntt_mul(s, ntt(u)));
  } 

  let w = poly_sub(v, inverse_ntt(to_sub_term));

  byte_encode(&compress(w, 1), 1).unwrap()
}

///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_bits_to_bytes() {
    // Fail
    let mut bits = vec![1, 0, 1, 0];
    let mut output = bits_to_bytes(bits);
    assert_eq!(output.is_none(), true);

    // Success
    bits = vec![1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0];
    output = bits_to_bytes(bits);

    assert_eq!(output.unwrap(), vec![129, 3]);
  }

  #[test]
  fn test_bytes_to_bits() {
    let bytes: Vec<u8> = vec![125, 27, 88];
    let output = bytes_to_bits(bytes).unwrap();

    assert_eq!(output, vec![1, 0, 1, 1, 1, 1, 1, 0,   1, 1, 0, 1, 1, 0, 0, 0,   0, 0, 0, 1, 1, 0, 1, 0])
  }

  #[test]
  fn test_bytes_encode_decode_d12() {
    let mut element: RingElement = [0; N];
    for i in 0..N {
      element[i] = i as FieldElement;
    }

    let output = byte_decode(&byte_encode(&element, 12).unwrap(), 12);

    assert_eq!(output.unwrap(), element)
  }

  #[test]
  fn test_mul() {
    for a in 0..Q {
      for b in 0..Q {
        let c = ((a as u32).wrapping_mul(b as u32)) % Q as u32;
        assert_eq!(field_mul(a, b), c as u16);
      }
    }
  }

  #[test]
  fn test_kpke_encrypt() {
    let s = [1 as u8; 32];
    let (ek, dk) = kpke_keygen(&s, 3, 2);

    let m = [2 as u8; 32];

    let c = kpke_encrypt(ek, m, s, 3, 2, 2, 10, 4);
    let m_computed = kpke_decrypt(dk, c, 3, 10, 4);

    assert_eq!(m.to_vec(), m_computed)
  }
}