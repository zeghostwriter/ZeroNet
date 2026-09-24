//! Stream abstraction shared by transports and protocols.

use std::any::Any;
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};

/// A bidirectional byte stream.
///
/// Transports wrap these; protocols consume them. Neither layer is allowed to
/// know how the underlying socket was obtained.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    /// Expose a type-erased hook for protocol adapters that need to request
    /// an optional carrier transition without depending on a concrete
    /// security implementation.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Stream for T {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// A boxed stream, used where the concrete type would otherwise leak into a
/// signature. Setup boundaries only — never per packet.
pub type BoxStream = Pin<Box<dyn Stream>>;

pub fn boxed<S: Stream>(s: S) -> BoxStream {
    Box::pin(s)
}
