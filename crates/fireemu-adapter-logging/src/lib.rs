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
//! adds `data.metadata.function.name`, and function user output is type `USER` while retaining
//! the production severity.
//! On connect a client first receives the whole history, then live frames. There is no
//! request/response, no filtering and no authentication.
//!
//! # Deliberate divergences from the official emulator (recorded in the compatibility contract)
//!
//! - **Loopback-only bind.** The handshake is refused unless the `Host` header names loopback,
//!   the same DNS-rebinding guard every other fireemu listener applies. The official server has
//!   none.
//! - **Loopback-only browser `Origin`.** A handshake carrying an `Origin` that is not an HTTP(S)
//!   loopback origin is refused with 403 before any frame is written, the same policy the
//!   Auth/control listener and the Hub apply to browser requests. WebSocket handshakes are
//!   exempt from the same-origin policy, so without this any web page could read the stream,
//!   which carries the Auth out-of-band links and SMS codes the official emulator also prints.
//!   A request with no `Origin` is a non-browser client and still connects. The official server
//!   has no such guard; the official UI's Logs page connects from a loopback origin, so the
//!   compatibility cost is nil. The stream's *contents* stay at parity: out-of-band links and
//!   codes are streamed as the official emulator streams them (`auth.logActionCodes = false`
//!   silences them at the source).
//! - **Bounded handshake.** The request head must arrive whole inside a ten-second deadline and
//!   within 8 KiB, otherwise the connection is answered 408 or 431 and dropped. The official
//!   server has no such bound, so one peer can hold a connection open indefinitely by stalling.
//!   A well-formed client is nowhere near either limit: a handshake is a few hundred bytes sent
//!   in one write.
//! - **Bounded history.** The official transport keeps every line in memory forever. This one
//!   retains the most recent [`LogBus`] cap (default [`DEFAULT_HISTORY_CAP`]) and drops the
//!   oldest, so an unbounded producer cannot exhaust memory.
//! - **Control-character stripping is slightly more aggressive.** Node's
//!   `stripVTControlCharacters` removes ANSI escape sequences but keeps `\n` / `\t`; this strips
//!   ANSI sequences, C0/C1/DEL bytes and Unicode bidi-formatting controls from messages and
//!   structured fields. Sanitized key collisions receive deterministic suffixes, so neither
//!   value disappears. `serde_json` would already escape controls; stripping is defence in depth.
//!
//! The pure protocol and bus logic ([`bus`], [`wire`]) is testable without a socket; only
//! [`server::serve_logging`] touches the network.

pub mod bus;
pub mod server;
pub mod wire;

pub use bus::{LogBus, LogInput, DEFAULT_HISTORY_CAP};
pub use server::{serve_logging, serve_logging_with_limits, HandshakeLimits};
