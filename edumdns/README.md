# edumdns

The main server binary for the edumDNS system. This crate combines the server, web interface, and database components into a single executable that manages probe connections, handles all commands, provides a user interface, and stores data in a PostgreSQL database.

## Overview

The `edumdns` binary orchestrates three main components:

- **edumdns_server**: Facilitates probe connections and handles all commands from probes
- **edumdns_web**: Provides the web-based user interface for administrators and users
- **edumdns_db**: Manages database interactions with PostgreSQL

The system uses the asynchronous Tokio runtime to handle concurrent operations efficiently.

## Configuration

The edumdns server uses a TOML configuration file for all settings. The configuration file is specified via the `--config` command-line argument (default: `edumdns.toml`). Environment variables with the `APP_` prefix can also override configuration values.

### Configuration File Structure

The configuration file is organized into sections:

- **`[database]`**: Database connection settings
- **`[server]`**: Server component settings (probe connections, packet transmission)
- **`[web]`**: Web interface settings (authentication, sessions, OIDC)

See `edumdns-example.toml` for a complete example configuration file.

### Logging Configuration

- **`app_log_level`** (optional, default: `"info"`)
  - Sets the logging level for the edumdns application only
  - Valid values: `trace`, `debug`, `info`, `warn`, `error`

- **`all_log_level`** (optional, default: `"info"`)
  - Sets the logging level for all crates used by the edumdns application
  - Valid values: `trace`, `debug`, `info`, `warn`, `error`

### Database Configuration (`[database]`)

- **`connection_string`** (required)
  - PostgreSQL connection string for the database
  - Format: `postgres://[user[:password]@][host][:port][/database]`
  - Example: `postgres://edumdns:password@localhost:5432/edumdns`

- **`pool_size`** (optional, default: `20`)
  - Maximum number of database connections in the pool

### Server Component Configuration (`[server]`)

- **`hostnames`** (optional, default: `["[::]:5000"]`)
  - List of hostname:port addresses to bind the server listener
  - Supports IPv4 and IPv6 addresses
  - Example: `hostnames = ["0.0.0.0:5000", "[::]:5000"]`

- **`channel_buffer_capacity`** (optional, default: `1000`)
  - Internal message channel buffer size

- **`[server.connection]`**: Connection settings
  - **`global_timeout`** (optional, default: `10`): Global timeout in seconds for server operations
  - **`buffer_capacity`** (optional, default: `1000`): Connection buffer capacity

- **`[server.transmit]`**: Packet transmission settings
  - **`max_transmit_subnet_size`** (optional, default: `512`): Maximum subnet size for packet transmission
  - **`transmit_repeat_delay_multiplicator`** (optional, default: `5`): Delay multiplicator for packet repetition

- **`[server.ebpf]`** (optional): eBPF proxy configuration
  - **`proxy_ipv4`**: IPv4 address used by the eBPF proxy for packet rewriting
  - **`proxy_ipv6`**: IPv6 address used by the eBPF proxy for packet rewriting
  - **`pin_location`** (optional, default: `"/sys/fs/bpf/edumdns"`): Directory path where eBPF maps are pinned

- **`[server.tls]`** (optional): TLS configuration
  - **`cert_path`**: Path to the TLS certificate file (PEM format)
  - **`key_path`**: Path to the TLS private key file (PEM format)

### Web Component Configuration (`[web]`)

- **`hostnames`** (optional, default: `["[::]:8000"]`)
  - List of hostname:port addresses to bind the web server
  - Example: `hostnames = ["0.0.0.0:8000", "[::]:8000"]`

- **`site_url`** (optional, default: `"localhost"`)
  - Base URL of the web application (used for CORS configuration)

- **`static_files_dir`** (optional, default: `"edumdns_web"`)
  - Directory path containing static files, templates, and web assets

- **`session_cookie`** (required)
  - Secret key for encrypting session cookies
  - Should be a random string of sufficient length (32+ bytes recommended)

- **`[web.session]`**: Session configuration
  - **`session_expiration`** (optional, default: `2592000`): Session expiry time in seconds (30 days)
  - **`last_visit_deadline`** (optional, default: `604800`): Last visit deadline in seconds (7 days)
  - **`use_secure_cookie`** (optional, default: `true`): Enable secure (HTTPS-only) cookies

- **`[web.limits]`**: Request limits
  - **`payload_limit`** (optional, default: `17179869184`): Maximum request payload size in bytes (16 GiB)
  - **`form_limit`** (optional, default: `16777216`): Maximum form submission size in bytes (16 MiB)
  - **`probe_ping_interval`** (optional, default: `1`): Ping interval for probes in seconds (from WebSockets)

- **`[web.oidc]`** (optional): OpenID Connect configuration
  - **`client_id`**: OIDC client ID from your identity provider
  - **`client_secret`**: OIDC client secret from your identity provider
  - **`issuer`**: OIDC issuer URL (base URL of your identity provider)
  - **`callback_url`**: Callback URL for OIDC authentication flow
  - **`new_users_admin`**: Whether new users created via OIDC should have administrator privileges

- **`[web.external_auth_database]`** (optional): External authentication database
  - **`connection_string`**: PostgreSQL connection string for the ACL access point database
  - **`auth_query`**: SQL query template for retrieving access point information (use `$$1` for IP parameter)

- **`[web.tls]`** (optional): TLS configuration
  - **`cert_path`**: Path to the TLS certificate file (PEM format)
  - **`key_path`**: Path to the TLS private key file (PEM format)

## Usage

The binary accepts a `--config` argument to specify the configuration file path:

```bash
edumdns --config /path/to/edumdns.toml
```

If not specified, the application will look for `edumdns.toml` in the current directory.

Configuration values can also be overridden using environment variables with the `APP_` prefix. For example, `APP_DATABASE_CONNECTION_STRING` will override the `database.connection_string` setting.

## Building

```bash
cargo build --release
```

The resulting binary will be located at `target/release/edumdns`.

## Architecture

The application spawns two main tasks:

1. **Server Task**: Handles probe connections and processes commands
2. **Web Task**: Serves the web interface and handles user requests

Both tasks share the same database connection pool and communicate through message channels for coordination.

## Server Functionality

The server component (`edumdns_server`) provides the core functionality for managing the distributed edumDNS system:

### Probe Management

- **Connection Handling**: Accepts TCP connections from remote probes (with optional TLS encryption)
- **Authentication**: Verifies probe identity and manages probe registration
- **Health Monitoring**: Tracks probe connection status and handles timeouts
- **Command Routing**: Sends commands to probes (e.g., reconnect, configuration updates)

### Packet Processing

- **Packet Reception**: Receives captured mDNS packets from probes
- **Packet Storage**: Persists packets and device information to the database
- **Packet Caching**: Maintains in-memory cache of recently seen packets for fast access
- **Deduplication**: Prevents storing duplicate packets from the same device

### Targeted Packet Transmission

One of the key features is **targeted packet transmission**, which enables controlled mDNS discovery by transmitting specific device packets to requesting clients.

#### How It Works

1. **Request Creation**: Users create transmit requests through the web interface, specifying:
   - Target device (identified by probe, MAC address, and IP)
   - Target IP/subnet where packets should be transmitted
   - Duration for the transmission
   - Optional proxy mode for enhanced security

2. **Validation**: Before transmission begins, the server performs several validation checks:
   - **Subnet Size Validation**: Ensures the target subnet doesn't exceed `server.transmit.max_transmit_subnet_size` (default: 512 addresses)
   - **Proxy Configuration**: If proxy mode is enabled, verifies that:
     - eBPF proxy is properly configured (both IPv4 and IPv6 proxy IPs must be set in `server.ebpf`)
     - Target IP is a single host (/32 for IPv4 or /128 for IPv6) - proxy mode requires point-to-point communication
   - **Packet Availability**: Verifies that packets exist for the specified device in the database

3. **Packet Processing**: If validation passes:
   - Loads matching packets from the database
   - Processes packets (rewrites DNS A/AAAA records if proxy mode is enabled)
   - Updates eBPF maps with IP mappings for proxy routing (if applicable)

4. **Transmission**: Spawns a UDP transmitter task that:
   - Periodically transmits the processed packets to the target IP/subnet
   - Supports live updates - newly captured packets are automatically included
   - Can be extended or stopped on demand
   - Automatically cleans up when the duration expires

5. **Cleanup**: When transmission stops:
   - Removes the transmit request from the database
   - Removes IP mappings from eBPF maps (if proxy was used)
   - Frees associated resources

#### Security Features

- **Policy Enforcement**: Transmission can be restricted based on user permissions and device policies
- **Proxy Mode**: When enabled, all traffic is relayed through the eBPF proxy, ensuring no direct client-device communication
- **Subnet Limiting**: Prevents accidental broadcast to overly large subnets

### Message Coordination

The server uses message channels to coordinate between components:

- **Command Channel**: Routes commands from the web interface to probes
- **Data Channel**: Receives captured packets from probes
- **Database Channel**: Queues database write operations
- **WebSocket Channels**: Delivers real-time updates to web clients
