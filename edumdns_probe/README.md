# edumdns_probe

Remote probe binary for the edumDNS system. This binary runs on subnets with smart devices to capture and parse mDNS packets, forwarding aggregated data to the central server.

## Overview

The `edumdns_probe` binary is a standalone application that:

- Captures network packets using libpcap
- Parses multicast DNS (mDNS) packets
- Maintains a persistent connection to a central server
- Forwards aggregated packet data
- Receives and executes commands from the server
- Automatically handles retries and reconnections

The probe is built on the Tokio async runtime for efficient I/O and concurrency.

---

## Configuration Model

`edumdns_probe` supports two equivalent configuration mechanisms:

1. Command-line arguments
2. Environment variables (optionally loaded from a `.env` file)

Both mechanisms configure the same runtime parameters.  
**Command-line arguments take precedence over environment variables.**

---

## Command-Line Arguments

Each command-line argument is documented below, along with its corresponding environment variable (if any).

---

### `--env-file <ENV_FILE>`

**Description**  
Path to a `.env` file used to load environment variables before argument parsing.

This is useful for deployments where configuration should not be passed directly on the command line.

**Behavior**
- The file is read before parsing other arguments
- Variables behave exactly like regular environment variables
- CLI arguments still override values from the file

**Environment Variable**  
None

**Example**

```bash
edumdns_probe --env-file /etc/edumdns/probe.env
```

---

### `-s, --server-host <SERVER_HOST>`

**Description**  
Hostname or IP address of the central edumDNS server to connect to.

This may be a DNS name, IPv4 address, or IPv6 address.

**Environment Variable**  
`EDUMDNS_PROBE_SERVER_HOST` (required)

**Examples**

```bash
edumdns_probe --server-host edumdns.example.com
```

```bash
export EDUMDNS_PROBE_SERVER_HOST=192.168.1.100
edumdns_probe
```

---

### `-p, --server-port <SERVER_PORT>`

**Description**  
TCP port on which the central server is listening.

Must match the server’s configured port.

**Default**  
`5000`

**Environment Variable**  
`EDUMDNS_PROBE_SERVER_PORT` (optional)

**Examples**

```bash
edumdns_probe --server-port 5000
```

```bash
export EDUMDNS_PROBE_SERVER_PORT=6000
edumdns_probe
```

---

### `-u, --uuid <UUID>`

**Description**  
Explicit UUID to use as the probe’s identity.

If provided, this UUID overrides any value loaded from the UUID file.

**Format**  
Standard UUID string  
(e.g. `550e8400-e29b-41d4-a716-446655440000`)

**Environment Variable**  
`EDUMDNS_PROBE_UUID` (optional)

**Examples**

```bash
edumdns_probe --uuid 550e8400-e29b-41d4-a716-446655440000
```

```bash
export EDUMDNS_PROBE_UUID=550e8400-e29b-41d4-a716-446655440000
edumdns_probe
```

---

### `-f, --uuid-file <UUID_FILE>`

**Description**  
Path to a file containing a persistent UUID for the probe.

If the file exists and contains a valid UUID, it will be used.  
Otherwise, a new UUID is generated and written to this file.

This ensures stable probe identity across restarts.

**Default**  
`uuid`

**Environment Variable**  
`EDUMDNS_PROBE_UUID_FILE` (optional)

**Examples**

```bash
edumdns_probe --uuid-file /var/lib/edumdns-probe/uuid
```

```bash
export EDUMDNS_PROBE_UUID_FILE=/var/lib/edumdns-probe/uuid
edumdns_probe
```

---

### `-n, --no-tls`

**Description**  
Disable TLS encryption for the connection to the server.

When enabled, the probe uses an unencrypted TCP connection.  
This is **not recommended** for production deployments.

**Default**  
TLS enabled

**Environment Variable**  
`EDUMDNS_PROBE_NO_TLS` (optional, boolean)

**Examples**

```bash
edumdns_probe --no-tls
```

```bash
export EDUMDNS_PROBE_NO_TLS=true
edumdns_probe
```

---

### `--retry-interval <RETRY_INTERVAL>`

**Description**  
Interval, in seconds, between reconnection attempts after a failure.

**Default**  
`1`

**Environment Variable**  
`EDUMDNS_PROBE_RETRY_INTERVAL` (optional)

**Examples**

```bash
edumdns_probe --retry-interval 5
```

```bash
export EDUMDNS_PROBE_RETRY_INTERVAL=5
edumdns_probe
```

---

### `--global-timeout <GLOBAL_TIMEOUT>`

**Description**  
Global timeout, in seconds, applied to probe operations such as connection attempts and packet handling.

**Note**  
The environment variable name contains a typo and is preserved for compatibility.

**Default**  
`10`

**Environment Variable**  
`EDUMDNS_PROBE_GLOBAL_TIMOUT` (optional)

**Examples**

```bash
edumdns_probe --global-timeout 30
```

```bash
export EDUMDNS_PROBE_GLOBAL_TIMOUT=30
edumdns_probe
```

---

### `--max-retries <MAX_RETRIES>`

**Description**  
Maximum number of consecutive retry attempts before the probe exits with an error.

**Default**  
`5`

**Environment Variable**  
`EDUMDNS_PROBE_MAX_RETRIES` (optional)

**Examples**

```bash
edumdns_probe --max-retries 20
```

```bash
export EDUMDNS_PROBE_MAX_RETRIES=20
edumdns_probe
```

---

### `--max-conn-buffer-capacity <MAX_CONN_BUFFER_CAPACITY>`

**Description**  
Maximum capacity of the internal connection buffer used for queued messages.

This limits memory usage under high traffic or slow network conditions.

**Default**  
`1000`

**Environment Variable**  
`EDUMDNS_PROBE_MAX_CONN_BUFFER_CAPACITY` (optional)

**Examples**

```bash
edumdns_probe --max-conn-buffer-capacity 2000
```

```bash
export EDUMDNS_PROBE_MAX_CONN_BUFFER_CAPACITY=2000
edumdns_probe
```

---

### `-k, --pre-shared-key <PRE_SHARED_KEY>`

**Description**  
Optional pre-shared key used for additional authentication with the server.

This can be used alongside TLS for defense-in-depth.

**Environment Variable**  
`EDUMDNS_PROBE_PRE_SHARED_KEY` (optional)

**Examples**

```bash
edumdns_probe --pre-shared-key your-secret-key
```

```bash
export EDUMDNS_PROBE_PRE_SHARED_KEY=your-secret-key
edumdns_probe
```

---

### `-l, --log-level <LOG_LEVEL>`

**Description**  
Controls the verbosity of probe logging.

**Valid Values**  
`trace`, `debug`, `info`, `warn`, `error`

**Default**  
`info`

**Environment Variable**  
`EDUMDNS_PROBE_LOG_LEVEL` (optional)

**Examples**

```bash
edumdns_probe --log-level debug
```

```bash
export EDUMDNS_PROBE_LOG_LEVEL=debug
edumdns_probe
```

---

## Usage Examples

### Environment-Only Configuration

```bash
export EDUMDNS_PROBE_SERVER_HOST=edumdns.example.com
export EDUMDNS_PROBE_SERVER_PORT=5000
export EDUMDNS_PROBE_UUID_FILE=/var/lib/edumdns-probe/uuid
export EDUMDNS_PROBE_LOG_LEVEL=info

edumdns_probe
```

### Command-Line–Only Configuration

```bash
edumdns_probe \\
--server-host edumdns.example.com \\
--server-port 5000 \\
--log-level debug
```

### Mixed Configuration (CLI Overrides Env)

```bash
export EDUMDNS_PROBE_SERVER_HOST=edumdns.example.com
export EDUMDNS_PROBE_LOG_LEVEL=info

edumdns_probe --log-level trace
```
