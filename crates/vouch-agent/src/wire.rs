// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Wire protocol utilities for length-prefixed messages.
//!
//! This module provides helpers for reading and writing length-prefixed messages
//! used by both the agent IPC protocol and the SSH agent protocol.

use crate::error::{AgentError, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum message size (1MB).
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Read a length-prefixed message (4-byte BE length + payload).
///
/// Returns `Ok(None)` on clean EOF (client disconnected).
/// Returns `Err` for protocol errors or unexpected EOF mid-message.
pub async fn read_message<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    // Read 4-byte length prefix
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            // Clean disconnect
            return Ok(None);
        }
        Err(e) => return Err(AgentError::Connection(e)),
    }

    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Err(AgentError::Protocol("empty message".to_string()));
    }
    if len > MAX_MESSAGE_SIZE {
        return Err(AgentError::Protocol(format!(
            "message too large: {len} bytes (max: {MAX_MESSAGE_SIZE})"
        )));
    }

    // Read message body
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;

    Ok(Some(buf))
}

/// Write a length-prefixed message (4-byte BE length + payload).
pub async fn write_message<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| AgentError::Protocol("message too large".to_string()))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a u32 from a buffer at the given offset (advances offset).
pub fn read_u32(buf: &[u8], offset: &mut usize) -> Result<u32> {
    if *offset + 4 > buf.len() {
        return Err(AgentError::Protocol("buffer underflow".to_string()));
    }
    let bytes: [u8; 4] = buf
        .get(*offset..*offset + 4)
        .ok_or_else(|| AgentError::Protocol("buffer underflow".to_string()))?
        .try_into()
        .map_err(|_| AgentError::Protocol("buffer underflow".to_string()))?;
    *offset += 4;
    Ok(u32::from_be_bytes(bytes))
}

/// Encode a u32 as 4-byte big-endian.
#[inline]
pub fn encode_u32(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

/// Encode a string with u32 length prefix.
///
/// # Errors
///
/// Returns an error if the string length exceeds `u32::MAX`.
pub fn encode_string(s: &str) -> Result<Vec<u8>> {
    let bytes = s.as_bytes();
    let len = u32::try_from(bytes.len())
        .map_err(|_| AgentError::Protocol("string too large for wire format".to_string()))?;
    let mut buf = Vec::with_capacity(4 + bytes.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
    Ok(buf)
}

/// Encode a byte slice with u32 length prefix.
///
/// # Errors
///
/// Returns an error if the data length exceeds `u32::MAX`.
pub fn encode_bytes(data: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(data.len())
        .map_err(|_| AgentError::Protocol("data too large for wire format".to_string()))?;
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
    Ok(buf)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_read_write_message_roundtrip() {
        let original = b"Hello, wire protocol!";

        // Write message to buffer
        let mut buf = Vec::new();
        write_message(&mut buf, original).await.unwrap();

        // Read it back
        let mut cursor = Cursor::new(buf);
        let read_back = read_message(&mut cursor).await.unwrap().unwrap();

        assert_eq!(read_back, original);
    }

    #[tokio::test]
    async fn test_read_message_empty_returns_error() {
        let mut buf = Cursor::new(vec![0u8, 0, 0, 0]); // length = 0
        let result = read_message(&mut buf).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_read_message_too_large() {
        // 2MB message length
        let mut buf = Cursor::new(vec![0u8, 0x20, 0, 0]);
        let result = read_message(&mut buf).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[tokio::test]
    async fn test_read_message_clean_eof() {
        let mut buf = Cursor::new(Vec::<u8>::new());
        let result = read_message(&mut buf).await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_read_u32() {
        let buf = [0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x01, 0x00];
        let mut offset = 0;

        let val1 = read_u32(&buf, &mut offset).unwrap();
        assert_eq!(val1, 0x42);
        assert_eq!(offset, 4);

        let val2 = read_u32(&buf, &mut offset).unwrap();
        assert_eq!(val2, 0x100);
        assert_eq!(offset, 8);
    }

    #[test]
    fn test_read_u32_underflow() {
        let buf = [0x00, 0x00];
        let mut offset = 0;
        let result = read_u32(&buf, &mut offset);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_u32() {
        assert_eq!(encode_u32(0), [0, 0, 0, 0]);
        assert_eq!(encode_u32(1), [0, 0, 0, 1]);
        assert_eq!(encode_u32(256), [0, 0, 1, 0]);
        assert_eq!(encode_u32(0x12345678), [0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_encode_string() {
        let encoded = encode_string("test").unwrap();
        assert_eq!(encoded.len(), 8); // 4 bytes length + 4 bytes "test"
        assert_eq!(&encoded[..4], &[0, 0, 0, 4]);
        assert_eq!(&encoded[4..], b"test");
    }

    #[test]
    fn test_encode_string_empty() {
        let encoded = encode_string("").unwrap();
        assert_eq!(encoded, vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_encode_bytes() {
        let data = [0x01, 0x02, 0x03];
        let encoded = encode_bytes(&data).unwrap();
        assert_eq!(encoded.len(), 7);
        assert_eq!(&encoded[..4], &[0, 0, 0, 3]);
        assert_eq!(&encoded[4..], &[0x01, 0x02, 0x03]);
    }
}
