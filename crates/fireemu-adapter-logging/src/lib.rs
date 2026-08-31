//! The official Firebase **Logging emulator**: an RFC 6455 WebSocket server that streams the
//! `EmulatorLog` wire format the Emulator UI's Logs page reads.
//!
//! # What this mirrors
//!
//! `firebase-tools@15.28.2` (`src/emulator/loggingEmulator.js`) runs a `ws` WebSocket server on
//! the logging port (default 4500) as a winston transport. Every CLI log line becomes one text
//! frame
//!
//! ```json
//! {"level": "<lowercase>", "data": <merged splat objects>, "timestamp": <ms since epoch>,
//!  "message": "<text, VT control characters stripped>"}
//! ```
//!
//! `data.metadata.level` / `data.metadata.message` override the top-level `level` / `message`;
//! `EmulatorLogger.forEmulator(name)` tags `data.metadata.emulator.name`, `forFunction(name)`
//! adds `data.metadata.function.name`, and function user output is type `USER` at level `info`.
//! On connect a client first receives the whole history, then live frames. There is no
//! request/response, no filtering and no authentication.
//!
//! # Deliberate divergences from the official emulator (recorded in the compatibility contract)
//!
//! - **Loopback-only bind.** The handshake is refused unless the `Host` header names loopback,
//!   the same DNS-rebinding guard every other fireemu listener applies. The official server has
//!   none.
//! - **Bounded history.** The official transport keeps every line in memory forever. This one
//!   retains the most recent [`LogBus`] cap (default [`DEFAULT_HISTORY_CAP`]) and drops the
//!   oldest, so an unbounded producer cannot exhaust memory.
//! - **Control-character stripping is slightly more aggressive.** Node's
//!   `stripVTControlCharacters` removes ANSI escape sequences but keeps `\n` / `\t`; this strips
//!   ANSI sequences *and* every remaining C0/DEL control byte, so no control character reaches
//!   the frame. `serde_json` would already escape them; stripping is defence in depth.
//!
//! The pure protocol and bus logic ([`bus`], [`wire`]) is testable without a socket; only
//! [`server::serve_logging`] touches the network.

pub mod bus;
pub mod server;
pub mod wire;

pub use bus::{LogBus, LogInput, DEFAULT_HISTORY_CAP};
pub use server::serve_logging;
