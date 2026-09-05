//! Tunnel core — DNS handling, routing, engine, settings.
//!
//! **Rule:** nothing in this module may depend on egui/eframe. It must stay
//! testable headlessly with plain `cargo test`.
//!
//! Module plan follows `docs/design.md` §4: `dns`, `forwarder`, `router`,
//! `redirect`, `engine`.

pub mod dns;
pub mod engine;
pub mod etw;
pub mod forwarder;
pub mod redirect;
pub mod router;
pub mod settings;
