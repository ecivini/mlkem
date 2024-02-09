use crate::constants::{Q, N, ZETAS};

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
/// Vector of the byte representation 
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
fn byte_encode(f: &RingElement, d: u8) -> Option<Vec<u8>> {
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
fn byte_decode(b: &Vec<u8>, d: u8) -> Option<RingElement> {
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
  field_reduce(a.wrapping_sub(b))
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
      println!("Index: {} {}", k, zeta);
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
    fn mul() {
        for a in 0..Q {
            for b in 0..Q {
                let c = ((a as u32).wrapping_mul(b as u32)) % Q as u32;
                assert_eq!(field_mul(a, b), c as u16);
            }
        }
    }
}