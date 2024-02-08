use crate::constants::{Q, N};

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
pub fn bits_to_bytes(bits: Vec<u8>) -> Option<Vec<u8>> {
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
pub fn bytes_to_bits(bytes: Vec<u8>) -> Option<Vec<u8>> {
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
pub fn byte_encode(f: &Vec<u16>, d: u8) -> Option<Vec<u8>> {
  let mut bits: Vec<u8> = vec![0; 256 * d as usize];

  for i in 0..N {
    let mut a = f[i];
    for j in 0..d {
      println!("Encode: {} {}", i, j);
      let index = i * d as usize + j as usize;
      bits[index] = (a % 2) as u8;
      a = (a - bits[index] as u16) / 2;
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
pub fn byte_decode(b: &Vec<u8>, d: u8) -> Option<Vec<u16>> {
  let bits = bytes_to_bits(b.to_vec()).unwrap();
  let mut integers: Vec<u16> = vec![0; N];

  let mut modulo = Q;
  if d < 12 {
    modulo = 2_u16.pow(d.into());
  }

  for i in 0..N {
    for j in 0..d {
      println!("Decode: {} {}", i, j);
      let index = i * d as usize + j as usize;
      integers[i] = (integers[i] + (bits[index] as u16) << j) % modulo;
    }
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
pub fn field_reduce(e: u16) -> u16 {
  let we = e.wrapping_sub(Q);
  
  we.wrapping_add((we >> 15).wrapping_mul(Q))
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
}