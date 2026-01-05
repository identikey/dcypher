//! Coefficient conversion utilities for PRE

/// Convert bytes to BFV coefficients (16-bit unsigned integers)
///
/// Each pair of bytes becomes one coefficient. If the input has an odd
/// number of bytes, a zero byte is appended.
pub fn bytes_to_coefficients(data: &[u8]) -> Vec<i64> {
    data.chunks(2)
        .map(|chunk| {
            let val = if chunk.len() == 2 {
                u16::from_le_bytes([chunk[0], chunk[1]])
            } else {
                chunk[0] as u16
            };
            val as i64
        })
        .collect()
}

/// Convert coefficients back to bytes
///
/// Each coefficient is treated as an unsigned 16-bit value and converted
/// to two bytes in little-endian order. The result is truncated to
/// `original_len` bytes.
pub fn coefficients_to_bytes(coeffs: &[i64], original_len: usize) -> Vec<u8> {
    let bytes: Vec<u8> = coeffs
        .iter()
        .flat_map(|&c| (c as u16).to_le_bytes())
        .collect();

    bytes.into_iter().take(original_len).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_even() {
        let original = b"Hello!";
        let coeffs = bytes_to_coefficients(original);
        let recovered = coefficients_to_bytes(&coeffs, original.len());
        assert_eq!(&recovered, original);
    }

    #[test]
    fn test_roundtrip_odd() {
        let original = b"Hello";
        let coeffs = bytes_to_coefficients(original);
        let recovered = coefficients_to_bytes(&coeffs, original.len());
        assert_eq!(&recovered, original);
    }
}
