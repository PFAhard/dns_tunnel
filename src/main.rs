//! Binary entry point — thin eframe bootstrap. No application logic here.

// GUI subsystem (no console window) in release builds; debug builds keep
// the console so `cargo run` panics are visible in the terminal.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use dns_tunnel::app::App;
use eframe::egui;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([720.0, 480.0])
            .with_min_inner_size([480.0, 320.0]),
        ..Default::default()
    };

    eframe::run_native(
        "DNS Tunnel",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}
