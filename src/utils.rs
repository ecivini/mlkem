use crate::constants::{Q, D};

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
pub fn bytes_to_bits(bytes: Vec<u8>) -> Vec<u8> {
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

  bits
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
      let output = bytes_to_bits(bytes);

      assert_eq!(output, vec![1, 0, 1, 1, 1, 1, 1, 0,   1, 1, 0, 1, 1, 0, 0, 0,   0, 0, 0, 1, 1, 0, 1, 0])
    }
}