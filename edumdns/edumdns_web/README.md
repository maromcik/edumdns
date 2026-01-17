# edumdns_web

Web interface component of the edumDNS system, providing a user interface for administrators and users to interact with the system.

## Overview

The `edumdns_web` crate provides:

- Web-based user interface using Actix Web
- Public discovery page for requesting device discovery
- User authentication (local and OpenID Connect)
- Device management and discovery controls
- Probe configuration and monitoring
- Packet viewing and management
- User, group, and permission administration
- Real-time WebSocket updates for probe status

The web interface uses Minijinja templates for rendering and supports both local authentication and OIDC integration.

---

## Configuration

The web component is configured through the main `edumdns.toml` configuration file under the `[web]` section. See the main `edumdns` README for the complete configuration structure.

### Server Binding

- **`web.hostnames`** (optional, default: `["[::]:8000"]`)
  - List of hostname:port addresses to bind the web server
  - Supports both IPv4 and IPv6 addresses
  - Use `0.0.0.0:8000` to bind to all IPv4 interfaces or `[::]:8000` for all IPv4 and IPv6 interfaces
  - Example: `hostnames = ["127.0.0.1:8000", "[::1]:8000"]`

### Application Configuration

- **`web.site_url`** (optional, default: `"localhost"`)
  - Base URL of the web application
  - Used for CORS configuration and redirects
  - Should match the actual domain or hostname where the application is accessible
  - Example: `site_url = "edumdns.example.com"`

- **`web.static_files_dir`** (optional, default: `"edumdns_web"`)
  - Directory path containing static files, templates, and web assets
  - Should contain subdirectories: `templates/`, `static/`, and `webroot/`
  - Example: `static_files_dir = "/var/lib/edumdns/web"`

- **`web.session_cookie`** (required)
  - Secret key for encrypting and signing session cookies
  - Should be a random string of sufficient length (32+ bytes recommended)
  - Generate a secure key: `openssl rand -base64 32`
  - Example: `session_cookie = "your-secret-key-here"`

### Session Configuration (`[web.session]`)

- **`web.session.session_expiration`** (optional, default: `2592000` seconds = 30 days)
  - Session expiry time in seconds
  - Determines how long a user session remains valid after login
  - After this duration, users must log in again

- **`web.session.last_visit_deadline`** (optional, default: `604800` seconds = 7 days)
  - Last visit deadline in seconds
  - Determines how long a session remains valid after the last activity
  - If a user doesn't visit the site within this period, the session expires
  - This is separate from the login deadline and helps ensure active sessions

- **`web.session.use_secure_cookie`** (optional, default: `true`)
  - Enable secure (HTTPS-only) cookies
  - When enabled, cookies will only be sent over HTTPS connections

### Request Limits (`[web.limits]`)

- **`web.limits.payload_limit`** (optional, default: `17179869184` bytes = 16 GiB)
  - Maximum request payload size in bytes

- **`web.limits.form_limit`** (optional, default: `16777216` bytes = 16 MiB)
  - Maximum form submission size in bytes

- **`web.limits.probe_ping_interval`** (optional, default: `1` second)
  - Ping interval for probes in seconds (used by WebSocket connections)

### OpenID Connect (OIDC) Configuration (`[web.oidc]`)

OIDC is optional and the system will gracefully fall back to local authentication if OIDC configuration is incomplete.

- **`web.oidc.client_id`** (required for OIDC)
  - OIDC client ID from your identity provider
  - Obtained when registering the application with your OIDC provider

- **`web.oidc.client_secret`** (required for OIDC)
  - OIDC client secret from your identity provider
  - Keep this value secure and do not expose it in version control

- **`web.oidc.callback_url`** (required for OIDC)
  - Callback URL for OIDC authentication flow
  - Must exactly match the redirect URI configured in your identity provider
  - Typically follows the pattern: `https://your-domain/login/oidc/redirect`

- **`web.oidc.issuer`** (required for OIDC)
  - OIDC issuer URL (base URL of your identity provider)
  - This is the base URL where the OIDC provider's discovery endpoint is located

- **`web.oidc.new_users_admin`** (optional, default: `false`)
  - Whether new users created via OIDC should automatically have administrator privileges
  - **Warning**: Use with caution in production environments

### Access Control List (ACL) Database Configuration (`[web.external_auth_database]`)

These settings are used for integrating with an external database (typically a RADIUS database) to determine access point information for device access control.

- **`web.external_auth_database.connection_string`** (optional)
  - PostgreSQL connection string for the ACL access point database
  - Used for querying access point information for device access control
  - If not set, ACL database queries will be disabled
  - Format: `host=hostname user=username password=password dbname=database port=5432`

- **`web.external_auth_database.auth_query`** (optional)
  - SQL query template for retrieving access point information
  - Should use parameterized queries with `$1` for the IP address parameter
  - The query should return a result set with access point information
  - If not set, ACL database queries will be disabled
  - Example: `auth_query = "SELECT ap_name FROM log WHERE client_ip = $1"`

### TLS Configuration (`[web.tls]`)
**Warning**: Running without TLS is not recommended for production use. Alternatively, you can use a reverse proxy like nginx.

- **`web.tls.cert_path`** (optional)
  - Path to the TLS certificate file (PEM format)
  - If not set, the server will run without TLS

- **`web.tls.key_path`** (optional)
  - Path to the TLS private key file (PEM format)
  - Must be set together with `cert_path` to enable TLS

---


