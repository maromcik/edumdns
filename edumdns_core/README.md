# edumdns_core

Shared library crate containing common types, utilities, and the connection actor model used by both the server and probe components of the edumDNS system.

## Overview

The `edumdns_core` crate provides:

- Shared data types and structures used across the system
- Network packet parsing and manipulation utilities
- Connection actor model for reliable TCP communication
- Common error types and utilities
- Binary encoding/decoding for network communication

This crate serves as the foundation for communication between probes and the server, ensuring type safety and consistency across the distributed system.

## Actor Model for Connection Handling

The crate implements an actor-based architecture for managing TCP connections, providing a robust and scalable way to handle network communication.

### Architecture

The connection actor model consists of three main actors that work together:

1. **Send Actor** (`TcpConnectionSender`): Handles outgoing packets
2. **Receive Actor** (`TcpConnectionReceiver`): Handles incoming packets
3. **Message Multiplexer**: Routes messages to the appropriate actor

### Key Components

#### TcpConnectionHandle

The `TcpConnectionHandle` is the main interface for interacting with a connection. It provides:

- **`send_message_with_response<T>()`**: Send a message and wait for a response
- **`close()`**: Gracefully close the connection

The handle uses message passing through channels, ensuring thread-safe communication.

#### TcpConnectionMessage

Messages sent to the connection actors:

- **`SendPacket`**: Send a packet (immediate or buffered)
- **`ReceivePacket`**: Receive a packet (with optional timeout)
- **`Close`**: Close the connection

#### Actor Channels

The system uses three separate channels:

- **Command Channel**: Main entry point for all operations
- **Send Channel**: Routes send operations to the send actor
- **Receive Channel**: Routes receive operations to the receive actor

### How It Works

1. **Initialization**: When a connection is established, three actors are spawned:
   - Send actor: Manages the outgoing packet stream
   - Receive actor: Manages the incoming packet stream
   - Message multiplexer: Routes messages to the appropriate actor

2. **Message Flow**:
   ```
   Client Code
      ↓
   TcpConnectionHandle
      ↓
   Command Channel
      ↓
   Message Multiplexer
      ↓
   Send Channel / Receive Channel
      ↓
   Send Actor / Receive Actor
      ↓
   Network Stream
   ```

3. **Sending Packets**:
   - Client calls `send_message_with_response()` on the handle
   - Message is sent through the command channel
   - Multiplexer routes it to the send channel
   - Send actor encodes and sends the packet
   - Response is sent back through a oneshot channel

4. **Receiving Packets**:
   - Client calls `send_message_with_response()` with a `ReceivePacket` message
   - Message is sent through the command channel
   - Multiplexer routes it to the receive channel
   - Receive actor waits for and decodes the next packet
   - Packet is sent back through a oneshot channel

### Benefits of the Actor Model

1. **Concurrency**: Send and receive operations happen independently
2. **Backpressure**: Buffering prevents overwhelming the network
3. **Error Isolation**: Errors in one direction don't affect the other
4. **Clean Shutdown**: Graceful cleanup when connections close
5. **Type Safety**: Strongly typed message passing prevents errors

### Usage Example

```rust
use edumdns_core::connection::TcpConnectionHandle;
use edumdns_core::app_packet::NetworkAppPacket;
use edumdns_core::connection::TcpConnectionMessage;

// Connect to server
let handle = TcpConnectionHandle::connect_tls(
    "server.example.com:5000",
    "server.example.com",
    client_config,
    Duration::from_secs(10),
).await?;

// Send a packet and wait for response
let response: Result<(), CoreError> = handle
    .send_message_with_response(|tx| {
        TcpConnectionMessage::send_packet(
            tx,
            NetworkAppPacket::Status(/* ... */),
        )
    })
    .await?;

// Receive a packet
let packet: Option<NetworkAppPacket> = handle
    .send_message_with_response(|tx| {
        TcpConnectionMessage::receive_packet(tx, Some(Duration::from_secs(5)))
    })
    .await?;

// Close the connection
handle.close().await?;
```

### Connection Types

The actor model supports multiple connection types:

- **Plain TCP**: Unencrypted connections
- **TLS Client**: Client-side TLS connections
- **TLS Server**: Server-side TLS connections

All connection types use the same actor model interface, providing a consistent API regardless of the underlying transport.

### Buffer Capacity

The connection actors use a buffer capacity of 10,000 messages (`BUFFER_CAPACITY`), allowing for high-throughput scenarios while maintaining backpressure control.

### Timeout Handling

All operations respect a global timeout, ensuring that:

- Stalled connections don't block indefinitely
- Network issues are detected promptly
- Resources are freed in a timely manner

## Other Features

### Network Packet Types

- **NetworkAppPacket**: High-level application packets
- **NetworkCommandPacket**: Commands sent to probes
- **NetworkStatusPacket**: Status updates from probes

### Binary Encoding

The crate uses `bincode` for efficient binary serialization of network packets, ensuring:

- Compact representation
- Fast encoding/decoding
- Type-safe deserialization

### Utilities

- **Host parsing and resolution**: Utilities for parsing hostnames and resolving addresses
- **Interface enumeration**: Network interface discovery
- **Packet rewriting**: Utilities for modifying packet headers (used by proxy)

## Dependencies

- **tokio**: Async runtime and networking
- **rustls**: TLS implementation
- **bincode**: Binary serialization
- **pnet**: Network packet manipulation
- **pcap**: Packet capture (for probe use)

## Integration

This crate is used by:

- **edumdns_server**: Server-side connection handling
- **edumdns_probe**: Probe-side connection handling

Both components use the same actor model, ensuring consistent behavior and reliable communication across the distributed system.

