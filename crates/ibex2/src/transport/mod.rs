//! Transports: the platform half of the sandwich.
//!
//! LLP 0057 §3 draws the line here. Everything above — header folding, redirect
//! policy, the body state machine, the error taxonomy — is Rust's and is
//! identical on every platform. Everything below is the operating system's:
//! sockets, TLS, proxy configuration, HTTP/2 and /3, connection pooling, and
//! the certificate store. Inverting that gives four platforms four different
//! `fetch`es, which is the failure a cross-platform runtime exists to prevent.
//!
//! @ref LLP 0057#3-the-boundary — Rust owns semantics, the platform owns transport

pub mod dev_tcp;
pub use dev_tcp::DevTcpTransport;

#[cfg(target_vendor = "apple")]
pub mod darwin;
#[cfg(target_vendor = "apple")]
pub use darwin::DarwinTransport;

/// The transport this build uses by default.
///
/// Apple platforms get `NSURLSession`; everything else falls back to the
/// development transport until its own platform binding exists. The fallback
/// speaks no TLS, so it is a development convenience and not a shipping story.
pub fn default_transport() -> Box<dyn crate::stdlib::fetch::Transport> {
    // The platform transport, engine or not: a Rust consumer (LLP 0068) has
    // no engine in the process and gets the same `fetch` underneath.
    #[cfg(target_vendor = "apple")]
    {
        Box::new(DarwinTransport::new())
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        Box::new(DevTcpTransport::new())
    }
}
