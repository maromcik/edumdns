# edumdns_probe

Remote probe binary for the EduMDNS system. This binary runs on subnets with smart devices to capture and parse mDNS packets, forwarding aggregated data to the central server.

## Overview

The `edumdns_probe` binary is a standalone application that:

- Captures network packets using libpcap
- Parses mDNS (multicast DNS) packets from the network
- Maintains a persistent connection to the central server
- Forwards captured packet data to the server
- Receives and executes commands from the server
- Handles reconnection and retry logic automatically

The probe uses the Tokio async runtime for efficient packet processing and network communication.

--- 

## Environment Variables

### Server Connection

- **`EDUMDNS_PROBE_SERVER_HOST`** (required)
  - Hostname or IP address of the central server
  - Can be a domain name or IP address (IPv4 or IPv6)
  - Example: `EDUMDNS_PROBE_SERVER_HOST=edumdns.example.com`
  - Example: `EDUMDNS_PROBE_SERVER_HOST=192.168.1.100`

- **`EDUMDNS_PROBE_SERVER_PORT`** (optional, default: `"5000"`)
  - Port number of the central server
  - Must match the port configured on the server
  - Example: `EDUMDNS_PROBE_SERVER_PORT=5000`

### Probe Identity

- **`EDUMDNS_PROBE_UUID`** (optional)
  - UUID string for the probe identity
  - If not set, the probe will generate or load a UUID from the UUID file
  - Format: Standard UUID format (e.g., `550e8400-e29b-41d4-a716-446655440000`)
  - Example: `EDUMDNS_PROBE_UUID=550e8400-e29b-41d4-a716-446655440000`

- **`EDUMDNS_PROBE_UUID_FILE`** (optional, default: `"uuid"`)
  - Path to a file storing the probe's persistent UUID
  - If the file exists and contains a valid UUID, it will be used
  - If the file doesn't exist or contains an invalid UUID, a new UUID will be generated and saved
  - This ensures the probe maintains the same identity across restarts
  - Example: `EDUMDNS_PROBE_UUID_FILE=/var/lib/edumdns-probe/uuid`

### Connection Security

- **`EDUMDNS_PROBE_NO_TLS`** (optional, default: `false`)
  - Disable TLS encryption for the connection to the server
  - Set to `true` to use an unencrypted connection (not recommended for production)
  - If not set or set to `false`, TLS will be used
  - Example: `EDUMDNS_PROBE_NO_TLS=false`

- **`EDUMDNS_PROBE_PRE_SHARED_KEY`** (optional)
  - Pre-shared key for authentication with the server
  - Used for additional security beyond TLS
  - If not set, authentication relies solely on TLS and probe adoption
  - Example: `EDUMDNS_PROBE_PRE_SHARED_KEY=your-pre-shared-key`

### Connection Retry Configuration

- **`EDUMDNS_PROBE_RETRY_INTERVAL`** (optional, default: `"1"`)
  - Interval in seconds between reconnection attempts
  - The probe will wait this duration before retrying a failed connection
  - Example: `EDUMDNS_PROBE_RETRY_INTERVAL=5`

- **`EDUMDNS_PROBE_GLOBAL_TIMOUT`** (optional, default: `"10"`)
  - Global timeout in seconds for probe operations
  - Used for connection timeouts and packet operations
  - Note: There is a typo in the variable name (`TIMOUT` instead of `TIMEOUT`)
  - Example: `EDUMDNS_PROBE_GLOBAL_TIMOUT=30`

- **`EDUMDNS_PROBE_MAX_RETRIES`** (optional, default: `"5"`)
  - Maximum number of retry attempts before giving up
  - After this many failed attempts, the probe will exit with an error
  - Set to a high value for production deployments to ensure continuous operation
  - Example: `EDUMDNS_PROBE_MAX_RETRIES=20`

### Logging

- **`EDUMDNS_PROBE_LOG_LEVEL`** (optional, default: `"info"`)
  - Logging level for the probe application
  - Valid values: `trace`, `debug`, `info`, `warn`, `error`
  - Example: `EDUMDNS_PROBE_LOG_LEVEL=debug`

---

## Command Line Arguments

All environment variables can also be provided as command-line arguments. The probe uses `clap` for argument parsing, and command-line arguments take precedence over environment variables.

### Common Usage

```bash
# Using environment variables
edumdns_probe

# Using command-line arguments
edumdns_probe --server-host edumdns.example.com --server-port 5000

# Using a custom .env file
edumdns_probe --env-file /path/to/.env
```

---

## Probe Lifecycle

1. **Initialization**: The probe loads or generates its UUID
2. **Connection**: Establishes a TCP connection (with optional TLS) to the server
3. **Authentication**: Authenticates with the server and receives initial configuration
4. **Packet Capture**: Starts capturing mDNS packets from network interfaces
5. **Data Transmission**: Forwards captured packets to the server
6. **Command Processing**: Receives and executes commands from the server
7. **Reconnection**: Automatically reconnects if the connection is lost

---

## Packet Capture

The probe captures mDNS packets from all available network interfaces. It uses libpcap for packet capture. 
Captured packets are aggregated and sent to the server in batches for efficient transmission.

---

## Error Handling

The probe includes robust error handling:

- **Connection Failures**: Automatic retry with configurable intervals
- **Packet Capture Errors**: Errors are logged and reported to the server
- **Server Commands**: Invalid commands are logged and ignored
- **Reconnection**: The probe can be instructed to reconnect by the server

---

## Building

```bash
cargo build --release
```

The resulting binary will be located at `target/release/edumdns_probe`.

---

## Deployment

The probe should be deployed on each subnet where smart devices are located. It requires:

- Network access to the central server
- Permissions to capture packets (typically requires `CAP_NET_RAW` or root privileges)
- Network interfaces configured for the target subnet

## Example Configuration File

Create a `.env` file with the following content:

```env
EDUMDNS_PROBE_SERVER_HOST=edumdns.example.com
EDUMDNS_PROBE_SERVER_PORT=5000
EDUMDNS_PROBE_UUID_FILE=/var/lib/edumdns-probe/uuid
EDUMDNS_PROBE_LOG_LEVEL=info
EDUMDNS_PROBE_MAX_RETRIES=20
EDUMDNS_PROBE_RETRY_INTERVAL=5
EDUMDNS_PROBE_GLOBAL_TIMOUT=30
```

