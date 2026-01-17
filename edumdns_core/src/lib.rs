//! Core primitives shared by edumdns components (server, probe, proxy).
//!
//! This crate provides:
//! - Application-level packet types (`app_packet`) used over TCP between server and probe
//! - Bincode/Serde-friendly wrappers for low-level types (`bincode_types`)
//! - Framed TCP/UDP connection utilities with timeouts and optional TLS (`connection`)
//! - Error type that unifies failures from I/O, parsing, networking, and codec layers (`error`)
//! - Packet parsing/manipulation across datalink/IP/transport layers (`network_packet`, `rewrite`)
//! - Metadata structures carried alongside packets (`metadata`)
//! - Misc utilities and retry helpers (`utils`), plus optional low-level interface helpers (`interface`)
//!
//! The modules are consumed by higher-level crates to exchange messages, frame connections,
//! and parse or rewrite packets in a consistent and testable way.

pub mod app_packet;
pub mod bincode_types;
pub mod connection;
pub mod error;
pub mod interface;
pub mod metadata;
pub mod network_packet;
pub mod rewrite;
pub mod utils;

pub const BUFFER_CAPACITY: usize = 1000;
