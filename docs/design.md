# DNS Tunnel — Design

Status: draft v1 (2026-08-22) — awaiting review before implementation.

## 1. Idea

The app turns DNS resolution into a routing policy engine ("DNS-driven policy
routing", a smart split-tunnel):

- It runs as the system DNS server.
- Every query is forwarded transparently to a real resolver.
- If the queried domain is on the user's redirect list, the IPv4 addresses
  returned in the answer are pinned into the OS routing table pointing at the
  VPN gateway — so subsequent connections to those addresses egress through
  the VPN tunnel.
- Everything else resolves and egresses normally.
- DNS content is **never modified** — bytes pass through verbatim in both
  branches. The app decides routing, not answers.

The 15-minute route lifetime matches DNS caching behavior: clients keep using
resolved IPs for the cache duration; when they re-resolve, we refresh the
route. Routes never need to outlive the cache.

## 2. Cycles

### Main cycle (per query)

```
client → UDP :53 → parse question → forward raw bytes to upstream resolver
                                       ↓
              upstream response → match pending by query ID
                                       ↓
              domain in redirect list?
                ├── no  → return response to client, as-is
                └── yes → parse A records (IPv4) from the answer section
                          add/refresh one route per IP (→ VPN gateway)
                          return response to client, as-is
```

The response is always returned, no matter what happens in the routing step.
Routing errors (e.g. unreachable gateway) are logged and surfaced in the UI but
never affect the DNS answer.

### Cleanup

| Trigger          | Action                                              |
| ---------------- | --------------------------------------------------- |
| Every 15 minutes | Remove all route entries added 15+ minutes ago      |
| App shutdown     | Remove **all** routes added by this run             |
| App startup      | Remove routes left over from a previous (crashed) run |

Leftovers after a crash are possible; the added-route registry is persisted to
disk so the next start can clean them. Routes are added non-persistent (no `-p`
flag), so a reboot also clears them.

## 3. Decisions

| Decision             | Choice                                            | Rationale |
| -------------------- | ------------------------------------------------- | --------- |
| VPN target           | Point-to-point peer discovery (`vpn_interface`) with static-gateway fallback | A `/30` TAP tunnel only routes via the peer address — the server IP is one hop beyond and never answers ARP (routes through it are silently dead) |
| Platform             | Windows only for now                              | Router code behind a trait; later ports stay cheap |
| App form             | One binary: egui GUI + engine in background threads | Fastest to develop/debug; a Windows service mode can be added later without touching `core/` |
| Domain matching      | Exact + subdomains                                | `example.com` matches `www.example.com`, not `badexample.com` (suffix match on label boundary) |
| DNS transport        | UDP only for MVP                                  | TCP listener added only if TC-bit truncation problems appear in practice |
| Routed records       | A only (IPv4)                                    | CNAMEs are skipped over — the final A records are what we route |
| IPv6                 | Out of scope                                     | No AAAA routing, no `route -6`/netsh for now |
| Route expiry         | Sliding: a re-query refreshes the 15-min timer    | Long-lived connections (SSH, downloads) must not be cut at an arbitrary boundary |
| Crash safety         | Registry persisted to disk, cleaned on next start | See cleanup table |
| Elevation            | Admin required for spawning `route.exe`          | The app never binds :53 — elevation is only for routing-table changes |
| Route command style  | Spawn `route.exe` via `std::process::Command`    | Argument arrays only — no shell string building; outputs captured into error events |

## 4. Module layout

```
src/core/
├── settings.rs      # settings; gains vpn_gateway + redirect_list (validated, normalized)
├── dns/
│   ├── message.rs   # hand-rolled wire format: header, compression-aware names, RR walk
│   └── server.rs    # UDP listener + pending-query table
├── forwarder.rs     # upstream UDP client — raw byte passthrough
├── etw.rs           # per-app attribution via the DNS-Client ETW provider (ferrisetw)
├── redirect.rs      # redirect-list matching (label-boundary suffix)
├── router/
│   ├── mod.rs       # RouteRegistry: added IPs + timestamps + disk persistence
│   ├── cidr.rs      # CIDR parsing (static always-routed networks)
│   └── windows.rs   # route add/delete via route.exe (IPv4)
└── engine.rs        # threads (listener, upstream, cleanup) + command/event channels
```

`app.rs` (Tunnel tab) becomes: engine status + start/stop, redirect-list
editor, event log. The Settings tab gains `vpn_gateway` and `redirect_list`.
Communication is `std::sync::mpsc`: commands into the engine
(`Start { settings }`, `Stop`), events out (`Started`, `Stopped`,
`QueryForwarded { domain }`, `RouteAdded { ip }`, `RouteRemoved { ip }`,
`Error(String)`). The UI polls events each frame; zero new dependencies.

Engine shutdown: `EngineHandle` is held by `App`; on drop it signals the
threads, joins them, and performs full route cleanup. Drop runs on normal exit
and on unwind, so cleanup is not dependent on a specific eframe hook.

## 5. DNS details

- **Query**: parse header + question name only (minimal, with compression
  safety); forward the raw datagram unchanged. EDNS, cookies, and any qtype
  pass through untouched.
- **Correlation**: the client's query ID is replaced by our own (16-bit
  counter, collisions skipped) before forwarding; the pending table maps our
  ID → (client addr, original ID, routing flag, deadline). The original ID is
  restored before the response is returned, so client ID collisions are
  impossible.
- **`timeout_ms`**: bounds each pending entry — a dropped/never-answered
  upstream query must not leak state. On expiry the entry is discarded and an
  event is emitted. (This is the setting's concrete role.)
- **Answer walking**: compression-aware name skipping over all records;
  collect A (IPv4) addresses from the answer section only (no
  additional-section glue).
- **Proactive pinning**: the engine pre-resolves redirect-list domains itself
  (at start for the whole list, on save for newly added ones) with synthetic
  queries (`client: None`) — the routes are pinned immediately, so clients
  holding cached IPs don't need to re-query (and don't need their cache
  flushed) for routing to take effect.
- **Per-app attribution**: two complementary mechanisms.
  1. *ETW*: the DNS-Client provider emits query events *from the requesting
     process* (header PID = requester — verified empirically); `ferrisetw`
     subscribes in-process, and queries are matched two-phase (pending
     queue + batched event join by domain within a ~2s window).
  2. *Port ownership*: browsers run built-in resolvers that query the proxy
     directly and emit no ETW events — their PID is recovered from a 1s
     `netstat` snapshot of UDP local ports (source port → owner).
  Together they cover OS-resolver apps and direct clients; only apps that
  both bypass the OS resolver *and* hide behind another process are
  unattributable.
- **Answers never leave from the `:53` listener socket.** Windows filters
  loopback UDP datagrams *sourced* from port 53 (DNS machinery intercepts
  them), so every client response is sent from the ephemeral upstream socket
  instead — clients only require the reply's source address to match the
  queried server, never its source port. (Cost us a long debugging
  session; do not "fix" this back.)
- **Answers never leave from the upstream socket either.** A late answer to
  a client port that already closed (dnscache retries under load) makes the
  local stack emit a loopback ICMP port-unreachable, delivered as
  WSAECONNRESET to the *sending* socket — poisoning the upstream receiver
  with no trace on the wire. Client answers go out from a dedicated
  responder socket that is never read; the blast lands harmlessly there.
  (Also do not "fix" this back.)
- The response bytes are returned to the client verbatim in both branches.

## 6. Routing details (Windows)

- IPv4: `route add <ip> mask 255.255.255.255 <vpn_gateway>` /
  `route delete <ip> mask 255.255.255.255 <vpn_gateway>`
- Next hop: for `/30` point-to-point tunnels the next hop is the **peer**
  address — the other host address in the subnet. Discovered automatically:
  the VPN tunnel adapter is matched by driver description (TAP/DCO/wintun)
  via PowerShell, because interface indices change across reboots; an
  explicit `vpn_interface` (alias or ifIndex) overrides. The VPN's server
  address is not on-link; routes via it are silently ignored by Windows
  (dead gateway).
- `route.exe` idempotency: "The object already exists" (add) and "Element
  not found" (delete) are treated as success.
- Static networks: `cidr_list` entries are routed for the engine's whole
  lifetime (no TTL) — one OS route per CIDR — for services that connect by
  raw IP without DNS (e.g. Telegram). Re-applied on Save and re-pinned
  immediately after VPN peer changes.
- The gateway must be reachable on-link from the VPN adapter. If the command
  fails (unreachable gateway), an `Error` event is emitted and the DNS answer
  is still returned.
- Registry file: `%APPDATA%\dns_tunnel\routes.ron` — added IPs plus the
  gateway (for deletes), written after each mutation and emptied on clean
  shutdown.

## 7. Settings

New fields (Settings tab):

| Field          | Example              | Validation                          |
| -------------- | -------------------- | ----------------------------------- |
| `vpn_gateway`  | `10.0.0.1`           | must parse as IPv4; fallback next hop only when tunnel discovery fails |
| `vpn_interface`| empty (auto)        | tunnel adapter auto-detected by driver description (TAP/DCO/wintun); alias/ifIndex overrides — indices change across reboots |
| `cidr_list`    | `91.108.0.0/16`, … | networks always routed while the engine runs; prefix 1..=32 (no `/0`) |
| `redirect_list`| `example.com`, ...   | valid DNS names, normalized to lowercase |

`listen_addr` defaults to `127.0.0.1:53` — the engine is the machine's main
resolver (point the adapter's DNS at `127.0.0.1`). The port must be free:
Windows' ICS service holds `0.0.0.0:53` on Win10/11 and must be stopped or
disabled if present. Port 5353 is avoided because mDNS owns it. The listen
port is configurable. The redirect list applies on Save without an engine
restart; all other settings require one (hot reload for the rest is future
work).

Engine state restoration: whether the engine was running at last exit is
persisted under a separate storage key (`engine_running`, written by
eframe's periodic auto-save) — the app auto-starts the engine on launch
unless the user stopped it explicitly.

## 8. Open items / future work

- TCP DNS listener (truncated / large responses).
- Windows service mode (`--service` + GUI as client).
- Hot reload of settings without an engine restart.
- Multiple upstream resolvers / DoH upstreams.
- Wildcard matching, if exact+subdomain proves insufficient.
