//! Transport abstraction for agent IPC communication.
//!
//! This module provides a trait-based abstraction over the IPC transport layer,
//! enabling integration testing without running a real Unix socket server.

use std::io::Result;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Trait for abstracting the agent IPC transport.
///
/// This trait enables testing agent communication without Unix sockets.
pub trait AgentTransport: Send + Unpin {
    /// Write all bytes to the transport.
    fn write_all(&mut self, buf: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Read exactly `buf.len()` bytes from the transport.
    fn read_exact(
        &mut self,
        buf: &mut [u8],
    ) -> impl std::future::Future<Output = Result<usize>> + Send;
}

// Implement for any type that implements AsyncRead + AsyncWrite + Send + Unpin
impl<T> AgentTransport for T
where
    T: AsyncRead + AsyncWrite + Send + Unpin,
{
    async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        AsyncWriteExt::write_all(self, buf).await
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<usize> {
        AsyncReadExt::read_exact(self, buf).await
    }
}

/// In-memory bidirectional channel for testing agent communication.
///
/// This provides a pair of connected transports that can be used to test
/// client-server communication without actual Unix sockets.
#[cfg(any(test, feature = "test-utils"))]
pub struct TestTransportPair {
    /// The client side of the transport.
    pub client: TestTransport,
    /// The server side of the transport.
    pub server: TestTransport,
}

#[cfg(any(test, feature = "test-utils"))]
impl TestTransportPair {
    /// Create a new pair of connected test transports.
    #[must_use]
    pub fn new(buffer_size: usize) -> Self {
        let (client_tx, server_rx) = tokio::sync::mpsc::channel(buffer_size);
        let (server_tx, client_rx) = tokio::sync::mpsc::channel(buffer_size);

        Self {
            client: TestTransport::new(client_rx, client_tx),
            server: TestTransport::new(server_rx, server_tx),
        }
    }

    /// Create a new pair with default buffer size (16).
    #[must_use]
    pub fn default_pair() -> Self {
        Self::new(16)
    }
}

/// One side of a test transport channel.
#[cfg(any(test, feature = "test-utils"))]
pub struct TestTransport {
    /// Receiver for incoming data.
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    /// Sender for outgoing data.
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Buffer for partially read data.
    read_buffer: Vec<u8>,
    /// Position in the read buffer.
    read_pos: usize,
}

#[cfg(any(test, feature = "test-utils"))]
impl TestTransport {
    /// Create a new test transport with the given channels.
    fn new(
        rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
        tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> Self {
        Self {
            rx,
            tx,
            read_buffer: Vec::new(),
            read_pos: 0,
        }
    }

    /// Write all bytes to the transport.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel is closed.
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.tx
            .send(buf.to_vec())
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "channel closed"))
    }

    /// Read exactly `buf.len()` bytes from the transport.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel is closed before enough bytes are available.
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut filled = 0;

        while filled < buf.len() {
            // If we have buffered data, use it first
            if self.read_pos < self.read_buffer.len() {
                let available = self.read_buffer.len() - self.read_pos;
                let needed = buf.len() - filled;
                let to_copy = available.min(needed);

                if let Some(dest) = buf.get_mut(filled..filled + to_copy)
                    && let Some(src) = self.read_buffer.get(self.read_pos..self.read_pos + to_copy)
                {
                    dest.copy_from_slice(src);
                    self.read_pos += to_copy;
                    filled += to_copy;
                }

                // Clear buffer if fully consumed
                if self.read_pos >= self.read_buffer.len() {
                    self.read_buffer.clear();
                    self.read_pos = 0;
                }

                continue;
            }

            // Need more data from channel
            match self.rx.recv().await {
                Some(data) => {
                    self.read_buffer = data;
                    self.read_pos = 0;
                }
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "channel closed",
                    ));
                }
            }
        }

        Ok(filled)
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl std::fmt::Debug for TestTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestTransport")
            .field("buffer_len", &self.read_buffer.len())
            .field("read_pos", &self.read_pos)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_transport_pair_roundtrip() {
        let pair = TestTransportPair::default_pair();
        let mut client = pair.client;
        let mut server = pair.server;

        // Client sends to server
        let message = b"hello server";
        client.write_all(message).await.ok();

        let mut buf = vec![0u8; message.len()];
        let result = server.read_exact(&mut buf).await;
        assert!(result.is_ok());
        assert_eq!(&buf, message);

        // Server sends to client
        let response = b"hello client";
        server.write_all(response).await.ok();

        let mut buf = vec![0u8; response.len()];
        let result = client.read_exact(&mut buf).await;
        assert!(result.is_ok());
        assert_eq!(&buf, response);
    }

    #[tokio::test]
    async fn test_transport_multiple_messages() {
        let pair = TestTransportPair::default_pair();
        let mut client = pair.client;
        let mut server = pair.server;

        // Send multiple messages
        client.write_all(b"one").await.ok();
        client.write_all(b"two").await.ok();
        client.write_all(b"three").await.ok();

        // Read them back
        let mut buf1 = vec![0u8; 3];
        let mut buf2 = vec![0u8; 3];
        let mut buf3 = vec![0u8; 5];

        let r1 = server.read_exact(&mut buf1).await;
        let r2 = server.read_exact(&mut buf2).await;
        let r3 = server.read_exact(&mut buf3).await;

        assert!(r1.is_ok());
        assert!(r2.is_ok());
        assert!(r3.is_ok());
        assert_eq!(&buf1, b"one");
        assert_eq!(&buf2, b"two");
        assert_eq!(&buf3, b"three");
    }

    #[tokio::test]
    async fn test_transport_partial_read() {
        let pair = TestTransportPair::default_pair();
        let mut client = pair.client;
        let mut server = pair.server;

        // Send one big message
        client.write_all(b"hello world").await.ok();

        // Read it in parts
        let mut buf1 = vec![0u8; 5];
        let mut buf2 = vec![0u8; 6];

        let r1 = server.read_exact(&mut buf1).await;
        let r2 = server.read_exact(&mut buf2).await;

        assert!(r1.is_ok());
        assert!(r2.is_ok());
        assert_eq!(&buf1, b"hello");
        assert_eq!(&buf2, b" world");
    }
}
