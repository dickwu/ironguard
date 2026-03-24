//! IronGuard relay for guaranteed fallback connectivity.
//!
//! When direct connections and hole punching fail, the relay
//! provides a guaranteed path between peers. The relay only
//! forwards opaque encrypted bytes -- it never sees plaintext.
//!
//! Peers authenticate with ephemeral relay tokens (NOT public
//! keys) to prevent the relay from correlating long-lived
//! identities across sessions.

pub mod client;
pub mod protocol;
pub mod server;
