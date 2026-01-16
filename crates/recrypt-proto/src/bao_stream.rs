//! Streaming verification via Blake3/Bao
//!
//! Provides helpers for:
//! - Encoding files with Bao tree (outboard mode)
//! - Streaming verification during download
//! - Slice extraction for random access

use crate::error::{ProtoError, ProtoResult};
use std::io::Read;

/// Bao encoder for creating verification trees
pub struct BaoEncoder {
    #[allow(dead_code)]
    outboard: Vec<u8>,
}

impl BaoEncoder {
    /// Create a new encoder
    pub fn new() -> Self {
        Self {
            outboard: Vec::new(),
        }
    }

    /// Encode data and return (bao_hash, outboard)
    pub fn encode(&mut self, data: &[u8]) -> ProtoResult<([u8; 32], Vec<u8>)> {
        let (outboard, hash) = bao::encode::outboard(data);
        Ok((*hash.as_bytes(), outboard))
    }

    /// Encode with streaming input
    pub fn encode_streaming<R: Read>(&mut self, mut reader: R) -> ProtoResult<([u8; 32], Vec<u8>)> {
        let mut data = Vec::new();
        reader
            .read_to_end(&mut data)
            .map_err(|e| ProtoError::BaoVerification(e.to_string()))?;
        self.encode(&data)
    }
}

impl Default for BaoEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Bao decoder for streaming verification
pub struct BaoDecoder {
    expected_hash: bao::Hash,
}

impl BaoDecoder {
    /// Create decoder expecting a specific root hash
    pub fn new(expected_hash: [u8; 32]) -> Self {
        Self {
            expected_hash: bao::Hash::from(expected_hash),
        }
    }

    /// Verify data against expected hash (simple mode)
    pub fn verify(&self, data: &[u8], outboard: &[u8]) -> ProtoResult<()> {
        // Compute hash and compare
        let computed = blake3::hash(data);

        // For now, simple verification (full Bao verification requires outboard parsing)
        // TODO: Use bao::decode::outboard when API stabilizes
        if computed.as_bytes() != self.expected_hash.as_bytes() {
            return Err(ProtoError::BaoVerification(
                "Hash mismatch: data corrupted".into(),
            ));
        }

        // Verify outboard size is reasonable
        let expected_outboard_size = bao::encode::outboard_size(data.len() as u64);
        if outboard.len() as u128 != expected_outboard_size {
            return Err(ProtoError::BaoVerification(format!(
                "Outboard size mismatch: {} != {}",
                outboard.len(),
                expected_outboard_size
            )));
        }

        Ok(())
    }

    /// Verify streaming (chunk by chunk)
    pub fn verify_streaming<R: Read>(&self, data: R, outboard: &[u8]) -> ProtoResult<Vec<u8>> {
        // For now, buffer and verify
        // TODO: True streaming verification
        let mut buf = Vec::new();
        std::io::copy(
            &mut std::io::BufReader::new(data),
            &mut std::io::Cursor::new(&mut buf),
        )
        .map_err(|e| ProtoError::BaoVerification(e.to_string()))?;

        self.verify(&buf, outboard)?;
        Ok(buf)
    }
}

/// Extract and verify a slice of data
pub struct SliceVerifier {
    expected_hash: bao::Hash,
}

impl SliceVerifier {
    pub fn new(expected_hash: [u8; 32]) -> Self {
        Self {
            expected_hash: bao::Hash::from(expected_hash),
        }
    }

    /// Extract a verified slice from encoded data
    ///
    /// This allows downloading only a portion of a file while still
    /// cryptographically verifying it belongs to the expected file.
    pub fn extract_slice(
        &self,
        data: &[u8],
        outboard: &[u8],
        start: u64,
        len: u64,
    ) -> ProtoResult<Vec<u8>> {
        // For random access, we'd need bao's slice extraction
        // For now, verify whole and return slice
        let decoder = BaoDecoder::new(*self.expected_hash.as_bytes());
        decoder.verify(data, outboard)?;

        let end = (start + len) as usize;
        if end > data.len() {
            return Err(ProtoError::BaoVerification(format!(
                "Slice out of bounds: {}..{} > {}",
                start,
                end,
                data.len()
            )));
        }

        Ok(data[start as usize..end].to_vec())
    }
}

/// Compute outboard size for a given data size
pub fn outboard_size(data_len: u64) -> u128 {
    bao::encode::outboard_size(data_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let data = b"Hello, Bao streaming!";

        let mut encoder = BaoEncoder::new();
        let (hash, outboard) = encoder.encode(data).unwrap();

        let decoder = BaoDecoder::new(hash);
        decoder.verify(data, &outboard).unwrap();
    }

    #[test]
    fn test_corrupted_data_detected() {
        let data = b"Original data";

        let mut encoder = BaoEncoder::new();
        let (hash, outboard) = encoder.encode(data).unwrap();

        let corrupted = b"Corrupted data";
        let decoder = BaoDecoder::new(hash);

        assert!(decoder.verify(corrupted, &outboard).is_err());
    }

    #[test]
    fn test_slice_extraction() {
        let data = b"Hello, this is a longer message for slicing!";

        let mut encoder = BaoEncoder::new();
        let (hash, outboard) = encoder.encode(data).unwrap();

        let verifier = SliceVerifier::new(hash);
        let slice = verifier.extract_slice(data, &outboard, 7, 4).unwrap();

        assert_eq!(&slice, b"this");
    }
}
