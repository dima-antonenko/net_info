//! Diagnostic HTTP client: one request, timed phase by phase.
//!
//! The CLI is a Rust counterpart of httptap. It measures DNS, TCP connect,
//! TLS, server wait, and body transfer for a single request (and its redirects).

pub mod analyzer;
pub mod cli;
pub mod client;
pub mod dns;
pub mod exit;
pub mod export;
pub mod models;
pub mod options;
pub mod otlp;
pub mod proxy;
pub mod redact;
pub mod render;
pub mod slo;
pub mod tls;

#[cfg(test)]
mod live_tests;

pub use analyzer::analyze;
pub use exit::*;
pub use models::*;
