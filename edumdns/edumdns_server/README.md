# edumdns_server

Server component of the edumDNS system that facilitates probe connections and handles all commands from remote probes.

## Overview

The `edumdns_server` crate is responsible for:

- Accepting and managing connections from remote probes
- Processing commands and data packets from probes
- Managing probe state and tracking probe health
- Transmitting mDNS packets to requesting clients
- Integrating with eBPF proxy for secure packet relaying
- Storing captured packet data in the database
- Performing commands on behalf of the web interface

The server uses an actor-based architecture with message channels for coordination between components.

---

## Configuration

The server component is configured through the main `edumdns.toml` configuration file under the `[server]` section. See the main `edumdns` README for the complete configuration structure.

### Server Binding

- **`server.hostnames`** (optional, default: `["[::]:5000"]`)
  - List of hostname:port addresses to bind the server listener
  - Supports both IPv4 and IPv6 addresses
  - Use `0.0.0.0:5000` to bind to all IPv4 interfaces or `[::]:5000` for all IPv4 and IPv6 interfaces
  - Example: `hostnames = ["127.0.0.1:5000", "[::1]:5000"]`

- **`server.channel_buffer_capacity`** (optional, default: `1000`)
  - Internal message channel buffer size.
  - Typically, no adjustments should be needed.
  - Consider lowering the value only if memory requirements are strict

### Connection Configuration (`[server.connection]`)

- **`server.connection.global_timeout`** (optional, default: `10` seconds)
  - Global timeout in seconds for server operations
  - Used for connection timeouts, packet operations, and probe health checks

- **`server.connection.buffer_capacity`** (optional, default: `1000`)
  - Connection buffer capacity
  - Typically, no adjustments should be needed.
  - Consider lowering the value only if memory requirements are strict

### Packet Transmission Configuration (`[server.transmit]`)

- **`server.transmit.max_transmit_subnet_size`** (optional, default: `512`)
  - Maximum subnet size for a single packet transmission request
  - Limits the number of devices that can receive transmitted packets in a single operation

- **`server.transmit.transmit_repeat_delay_multiplicator`** (optional, default: `5`)
  - Delay multiplicator for packet repetition
  - The actual delay is calculated as `transmit_repeat_delay_multiplicator * device_interval_from_db`

### eBPF Proxy Configuration (`[server.ebpf]`)

The following settings are used when eBPF proxy functionality is enabled for devices:

- **`server.ebpf.proxy_ipv4`** (required for eBPF proxy)
  - IPv4 address used by the eBPF proxy for packet rewriting
  - This is the IP address that will appear in A records of mDNS packets transmitted to a client
  - Must match the IPv4 address configured for `edumdns_proxy`

- **`server.ebpf.proxy_ipv6`** (required for eBPF proxy)
  - IPv6 address used by the eBPF proxy for packet rewriting
  - This is the IP address that will appear in AAAA records of mDNS packets transmitted to a client
  - Must match the IPv6 address configured for `edumdns_proxy`

- **`server.ebpf.pin_location`** (optional, default: `"/sys/fs/bpf/edumdns"`)
  - Directory path where eBPF maps are pinned by the proxy
  - Must be a BPF filesystem (BPFFS) mount point
  - The server reads the pinned maps from this location to update IP mappings

### TLS Configuration (`[server.tls]`)
**Warning**: Running without TLS is not recommended for production use

- **`server.tls.cert_path`** (optional)
  - Path to the TLS certificate file (PEM format)
  - If not set, the server will run without TLS encryption

- **`server.tls.key_path`** (optional)
  - Path to the TLS private key file (PEM format)
  - Must be set together with `cert_path` to enable TLS

---

## Architecture

The server component consists of several key modules:

### Connection Management

- **ConnectionManager**: Handles individual probe connections
- **ListenerSpawner**: Manages TCP listeners and accepts new connections
- **ProbeHandles**: Shared map of active probe connections

### Packet Processing

- **ServerManager**: Main packet processing coordinator (see detailed description below)
- **DatabaseManager**: Handles database write operations
- **Transmitter**: Manages packet transmission to clients

### Probe Tracking

- **ProbeTracker**: Tracks probe health and connection status
- **Watchdog**: Monitors probes and handles timeouts

### eBPF Integration

- **EbpfUpdater**: Updates eBPF maps with IP address mappings for proxy functionality

---

## ServerManager Module

The `ServerManager` (`manager.rs`) is the central component that routes commands and data between probes, the database, and transmitters. It serves as the core coordination point for the entire server.

### Responsibilities

The `ServerManager` is responsible for:

- **Packet Routing**: Receives packets from probes and routes them to appropriate handlers
- **Command Processing**: Processes commands from the web interface and probes
- **Packet Caching**: Maintains in-memory cache of recently seen packets per device
- **Transmitter Management**: Spawns and manages UDP transmitter tasks for targeted packet transmission
- **WebSocket Coordination**: Manages WebSocket connections for real-time probe status updates
- **eBPF Map Updates**: Coordinates updates to eBPF maps when proxy mode is enabled
- **Cache Invalidation**: Manages cache invalidation when devices or probes are deleted

### Packet Handling

The `ServerManager` handles two types of packets:

#### Network Packets (from Probes)

When receiving `NetworkAppPacket` from probes:

1. **Status Packets**: Forwards `ProbeResponse` messages to registered WebSocket clients
2. **Data Packets**: Processes captured mDNS packets:
   - Updates in-memory cache (deduplicated by probe, device MAC, and device IP)
   - Forwards live updates to active transmitters (if any)
   - Queues packets for database persistence
   - Tracks device information (MAC, IP) per probe

The cache structure is hierarchical:
```
Probe ID → (Device MAC, Device IP) → Set of ProbePackets
```

#### Local Packets (from Web Interface)

When receiving `LocalAppPacket` from the web interface:

1. **Commands**:
   - **RegisterForEvents**: Registers WebSocket sessions for probe event updates
   - **UnregisterFromEvents**: Removes WebSocket session registrations
   - **TransmitDevicePackets**: Initiates targeted packet transmission (see validation below)
   - **StopTransmitDevicePackets**: Stops an active transmitter and cleans up resources
   - **ReconnectProbe**: Sends reconnect command to a probe and closes its connection
   - **InvalidateCache**: Clears cached packets for a probe or device
   - **ExtendPacketTransmitRequest**: Extends the duration of an active transmitter

2. **Status**:
   - **GetLiveProbes**: Queries for active probe connections
   - **IsProbeLive**: Checks if a specific probe is currently connected
   - **OperationUpdateToWs**: Sends status updates to WebSocket clients

### Message Flow

The `ServerManager` uses a main event loop that continuously polls two channels:

1. **Command Channel**: Receives control packets from web interface and internal subsystems
2. **Data Channel**: Receives network packets from probes

The loop uses `try_recv` for immediate processing when packets are available, falling back to `tokio::select!` for awaiting packets when queues are empty. This ensures efficient processing with minimal latency.

### WebSocket Integration

The `ServerManager` maintains a registry of WebSocket sessions. Web interface registers sessions to receive probe updates that can be sent to all sessions for a probe or to a specific session.

---

## Targeted Packet Transmission

The `ServerManager` implements targeted packet transmission

### Validation Process

1. **Proxy Configuration Check**:
   - If proxy mode is requested but eBPF is not configured, transmission is rejected

2. **Subnet Size Validation**:
   - Target subnet size must not exceed `server.transmit.max_transmit_subnet_size` (default: 512)
   - Prevents accidental broadcast to overly large subnets

3. **Proxy Mode Subnet Restriction**:
   - When proxy mode is enabled, target must be a single host:
     - IPv4: Must be /32 (single address)
     - IPv6: Must be /128 (single address)
   - This ensures point-to-point communication through the proxy

4. **Packet Availability**:
   - Queries database for packets matching the device (probe ID, MAC, IP)
   - If no packets found, transmission is rejected

5. **Packet Processing**:
   - Loaded packets are processed (DNS A/AAAA records rewritten if proxy enabled)
   - If no packets remain after processing, transmission is rejected

### Transmission Lifecycle

If all validations pass:

1. **eBPF Map Update**: If proxy mode is enabled, adds bidirectional IP mappings to eBPF maps:
   - Maps device IP ↔ target IP (both directions)
   - Enables kernel-level packet rewriting

2. **Transmitter Spawn**: Creates a `PacketTransmitter` task that:
   - Periodically transmits processed packets to the target
   - Receives live updates for newly captured packets
   - Automatically stops when duration expires

3. **Live Updates**: Sets up a channel so newly captured packets are automatically forwarded to the transmitter

4. **Cleanup**: When transmission stops (manually or by timeout):
   - Removes transmit request from database
   - Removes IP mappings from eBPF maps (if proxy was used)
   - Aborts the transmitter task
   - Clears live update channel

---
