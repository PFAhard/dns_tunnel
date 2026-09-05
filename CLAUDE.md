# DNS Tunnel

Rust GUI application built with egui/eframe. GUI for a DNS tunnel — the tunneling
protocol and engine design are still being defined.

## Status

- [x] egui MVP: window + minimal app skeleton
- [x] Project skeleton: lib/bin split, lints
- [x] Multi-tab UI (tunnel placeholder + settings editor)
- [x] Persistent settings (eframe built-in storage)
- [x] Tunnel design (→ `docs/design.md`) — reviewed, approved (IPv4-only)
- [x] Core engine (`dns/`, `forwarder`, `router/`, `redirect`, `engine`)
- [ ] Battle-testing via cmd/nslookup — pending user review

## Architecture

```
src/
├── main.rs    # thin eframe bootstrap only — no logic
├── lib.rs     # crate root: module tree + docs
├── app.rs     # egui App — UI state, rendering, intent dispatch
└── core/      # tunnel logic — zero egui/eframe dependency
    ├── mod.rs      # module plan: dns/, forwarder, router/, redirect, engine
    └── settings.rs # persistent settings: model, defaults, validation
```

**Rules**

- `core/` must never import egui/eframe; it stays testable headlessly with `cargo test`.
- `app.rs` contains no protocol logic — it reads state and dispatches intents.
- New dependencies must be justified. egui's tree is already 400+ crates; DNS wire
  format is simple — hand-roll it rather than pull in a crate.
- Settings persistence uses eframe's built-in storage (`eframe::get_value`/`set_value`
  in `App::save`) — deliberately no extra persistence crates. Storage glue lives only
  in `app.rs`; the model + validation live in `core/settings.rs`.
- Window geometry (size, position, fullscreen, maximized) persistence comes free from
  eframe's `NativeOptions::persist_window` (default on, same storage file, `window`
  key) — no custom code.

## Commands

| Task   | Command                                     |
| ------ | ------------------------------------------- |
| Run    | `cargo run`                                 |
| Test   | `cargo test`                                |
| Lint   | `cargo clippy --all-targets -- -D warnings` |
| Format | `cargo fmt --all`                           |

## Lints (Cargo.toml `[lints]`)

- `unsafe_code = "forbid"` — entire crate
- `missing_docs = "warn"` — public API must be documented
- clippy `all` + `pedantic` at warn; the canonical check is
  `cargo clippy --all-targets -- -D warnings`

## Conventions

- Every commit compiles; messages describe intent — `git log` is the changelog.
- Design decisions and protocol rationale go in `docs/` (the *why*); code comments
  explain the *what*.
- Keep this file current: any non-obvious decision lands here at commit time.
