# edumdns

The main server binary for the EduMDNS system. This crate combines the server, web interface, and database components into a single executable that manages probe connections, handles all commands, provides a user interface, and stores data in a PostgreSQL database.

## Overview

The `edumdns` binary orchestrates three main components:

- **edumdns_server**: Facilitates probe connections and handles all commands from probes
- **edumdns_web**: Provides the web-based user interface for administrators and users
- **edumdns_db**: Manages database interactions with PostgreSQL

The system uses the asynchronous Tokio runtime to handle concurrent operations efficiently.

## Environment Variables

The following environment variables are used across all components of the edumdns server:

### Logging

- **`EDUMDNS_LOG_LEVEL`** (optional, default: `"info"`)
  - Sets the logging level for the application
  - Valid values: `trace`, `debug`, `info`, `warn`, `error`
  - Example: `EDUMDNS_LOG_LEVEL=debug`

### Database Configuration

- **`EDUMDNS_DATABASE_URL`** (required)
  - PostgreSQL connection string for the database
  - Format: `postgres://[user[:password]@][host][:port][/database]`
  - Example: `postgres://edumdns:password@localhost:5432/edumdns`

### Server Component (edumdns_server)

- **`EDUMDNS_SERVER_HOSTNAME`** (optional, default: `"localhost"`)
  - Hostname or IP address to bind the server listener
  - Supports IPv4 and IPv6 addresses
  - Example: `EDUMDNS_SERVER_HOSTNAME=0.0.0.0` or `EDUMDNS_SERVER_HOSTNAME=::`

- **`EDUMDNS_SERVER_PORT`** (optional, default: `"5000"`)
  - Port number for the server to listen on
  - Example: `EDUMDNS_SERVER_PORT=5000`

- **`EDUMDNS_SERVER_GLOBAL_TIMEOUT`** (optional, default: `10`)
  - Global timeout in seconds for server operations
  - Used for connection timeouts and packet operations
  - Example: `EDUMDNS_SERVER_GLOBAL_TIMEOUT=30`

- **`EDUMDNS_SERVER_PROXY_IPV4`** (optional)
  - IPv4 address used by the eBPF proxy for packet rewriting
  - Required if eBPF proxy functionality is enabled
  - Example: `EDUMDNS_SERVER_PROXY_IPV4=192.168.0.10`

- **`EDUMDNS_SERVER_PROXY_IPV6`** (optional)
  - IPv6 address used by the eBPF proxy for packet rewriting
  - Required if eBPF proxy functionality is enabled
  - Example: `EDUMDNS_SERVER_PROXY_IPV6=::1`

- **`EDUMDNS_SERVER_MAX_TRANSMIT_SUBNET_SIZE`** (optional, default: `512`)
  - Maximum subnet size for packet transmission operations
  - Example: `EDUMDNS_SERVER_MAX_TRANSMIT_SUBNET_SIZE=1024`

- **`EDUMDNS_SERVER_CERT`** (optional)
  - Path to the TLS certificate file (PEM format)
  - If not set, the server will run without TLS (not recommended for production)
  - Example: `EDUMDNS_SERVER_CERT=/etc/letsencrypt/live/edumdns.eu/fullchain.pem`

- **`EDUMDNS_SERVER_KEY`** (optional)
  - Path to the TLS private key file (PEM format)
  - Must be set together with `EDUMDNS_SERVER_CERT`
  - Example: `EDUMDNS_SERVER_KEY=/etc/letsencrypt/live/edumdns.eu/privkey.pem`

- **`EDUMDNS_SERVER_EBPF_PIN_LOCATION`** (optional, default: `"/sys/fs/bpf/edumdns"`)
  - Directory path where eBPF maps are pinned
  - Must be a BPF filesystem (BPFFS) mount point
  - Example: `EDUMDNS_SERVER_EBPF_PIN_LOCATION=/sys/fs/bpf/edumdns`

### Web Component (edumdns_web)

- **`EDUMDNS_WEB_HOSTNAME`** (optional, default: `"localhost"`)
  - Hostname or IP address to bind the web server
  - Supports IPv4 and IPv6 addresses
  - Example: `EDUMDNS_WEB_HOSTNAME=0.0.0.0` or `EDUMDNS_WEB_HOSTNAME=::`

- **`EDUMDNS_WEB_PORT`** (optional, default: `"8000"`)
  - Port number for the web server to listen on
  - Example: `EDUMDNS_WEB_PORT=8000`

- **`EDUMDNS_SITE_URL`** (optional, default: `"localhost"`)
  - Base URL of the web application
  - Used for CORS configuration and redirects
  - Example: `EDUMDNS_SITE_URL=edumdns.example.com`

- **`EDUMDNS_FILES_DIR`** (optional, default: `"edumdns_web"`)
  - Directory path containing static files, templates, and web assets
  - Example: `EDUMDNS_FILES_DIR=/var/lib/edumdns/web`

- **`EDUMDNS_COOKIE_SESSION_KEY`** (optional, but recommended)
  - Secret key for encrypting session cookies
  - Should be a random string of sufficient length (32+ bytes recommended)
  - If not set, an empty key is used (insecure)
  - Example: `EDUMDNS_COOKIE_SESSION_KEY=your-secret-key-here`

- **`EDUMDNS_USE_SECURE_COOKIE`** (optional, default: `false`)
  - Enable secure (HTTPS-only) cookies
  - Set to `true` for production deployments with TLS
  - Example: `EDUMDNS_USE_SECURE_COOKIE=true`

- **`EDUMDNS_WEB_SESSION_EXPIRY`** (optional, default: `2592000` seconds = 30 days)
  - Session expiry time in seconds
  - Determines how long a user session remains valid after login
  - Example: `EDUMDNS_WEB_SESSION_EXPIRY=2592000`

- **`EDUMDNS_WEB_LAST_VISIT_DEADLINE`** (optional, default: `604800` seconds = 7 days)
  - Last visit deadline in seconds
  - Determines how long a session remains valid after the last activity
  - Example: `EDUMDNS_WEB_LAST_VISIT_DEADLINE=604800`

#### OpenID Connect (OIDC) Configuration

The following variables are required if OIDC authentication is desired. If not set, the system will use local authentication only.

- **`EDUMDNS_OIDC_CLIENT_ID`** (optional, required for OIDC)
  - OIDC client ID from your identity provider
  - Example: `EDUMDNS_OIDC_CLIENT_ID=edumdns-client`

- **`EDUMDNS_OIDC_CLIENT_SECRET`** (optional, required for OIDC)
  - OIDC client secret from your identity provider
  - Example: `EDUMDNS_OIDC_CLIENT_SECRET=your-client-secret`

- **`EDUMDNS_OIDC_CALLBACK_URL`** (optional, required for OIDC)
  - Callback URL for OIDC authentication flow
  - Must match the URL configured in your identity provider
  - Example: `EDUMDNS_OIDC_CALLBACK_URL=https://edumdns.example.com/login/oidc/redirect`

- **`EDUMDNS_OIDC_ISSUER`** (optional, required for OIDC)
  - OIDC issuer URL (base URL of your identity provider)
  - Example: `EDUMDNS_OIDC_ISSUER=https://auth.example.com/realms/edumdns`

- **`EDUMDNS_OIDC_NEW_USERS_ADMIN`** (optional, default: `false`)
  - Whether new users created via OIDC should have administrator privileges
  - Set to `true` to grant admin access to all OIDC-authenticated users
  - Example: `EDUMDNS_OIDC_NEW_USERS_ADMIN=false`

#### Access Control List (ACL) Database Configuration

- **`EDUMDNS_ACL_AP_DATABASE_CONNECTION_STRING`** (optional)
  - PostgreSQL connection string for the ACL access point database
  - Used for querying access point information for device access control
  - Example: `EDUMDNS_ACL_AP_DATABASE_CONNECTION_STRING="host=radius-db user=postgres password=postgres dbname=radius port=5432"`

- **`EDUMDNS_ACL_AP_DATABASE_QUERY`** (optional)
  - SQL query template for retrieving access point information
  - Should use parameterized queries with `$$1` for the IP address parameter
  - Example: `EDUMDNS_ACL_AP_DATABASE_QUERY="SELECT ap FROM log WHERE ip = $$1"`

## Usage

The binary accepts an optional `--env-file` argument to load environment variables from a file:

```bash
edumdns --env-file /path/to/.env
```

If not specified, the application will attempt to load a `.env` file from the current directory.

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

The server component (`edumdns_server`) provides the core functionality for managing the distributed EduMDNS system:

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

1. **Request Creation**: Administrators create transmit requests through the web interface, specifying:
   - Target device (identified by probe, MAC address, and IP)
   - Target IP/subnet where packets should be transmitted
   - Duration for the transmission
   - Optional proxy mode for enhanced security

2. **Validation**: Before transmission begins, the server performs several validation checks:
   - **Subnet Size Validation**: Ensures the target subnet doesn't exceed `EDUMDNS_SERVER_MAX_TRANSMIT_SUBNET_SIZE` (default: 512 addresses)
   - **Proxy Configuration**: If proxy mode is enabled, verifies that:
     - eBPF proxy is properly configured (both IPv4 and IPv6 proxy IPs must be set)
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

This architecture ensures efficient, non-blocking communication between all system components.

