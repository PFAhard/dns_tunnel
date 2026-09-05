//! `dns_tunnel` — GUI application for a DNS tunnel.
//!
//! Split into two layers:
//! - [`app`]: egui/eframe UI — state, rendering, intent dispatch.
//! - [`core`]: tunnel logic — free of any GUI dependency, testable headlessly.

pub mod app;
pub mod core;
