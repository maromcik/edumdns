# edumdns_web

Web interface component of the EduMDNS system, providing a user interface for administrators and users to interact with the system.

## Overview

The `edumdns_web` crate provides:

- Web-based user interface using Actix Web
- User authentication (local and OpenID Connect)
- Device management and discovery controls
- Probe configuration and monitoring
- Packet viewing and management
- User and group administration
- Real-time WebSocket updates for probe status

The web interface uses Minijinja templates for rendering and supports both local authentication and OIDC integration.

---

## Environment Variables

### Server Binding

- **`EDUMDNS_WEB_HOSTNAME`** (optional, default: `"localhost"`)
  - Hostname or IP address to bind the web server
  - Supports both IPv4 and IPv6 addresses
  - Use `0.0.0.0` to bind to all IPv4 interfaces or `::` for all IPv6 interfaces
  - Example: `EDUMDNS_WEB_HOSTNAME=0.0.0.0`

- **`EDUMDNS_WEB_PORT`** (optional, default: `"8000"`)
  - Port number for the web server to listen on
  - Example: `EDUMDNS_WEB_PORT=8000`

### Application Configuration

- **`EDUMDNS_SITE_URL`** (optional, default: `"localhost"`)
  - Base URL of the web application
  - Used for CORS configuration and redirects
  - Should match the actual domain or hostname where the application is accessible
  - Example: `EDUMDNS_SITE_URL=edumdns.example.com`

- **`EDUMDNS_FILES_DIR`** (optional, default: `"edumdns_web"`)
  - Directory path containing static files, templates, and web assets
  - Should contain subdirectories: `templates/`, `static/`, and `webroot/`
  - Example: `EDUMDNS_FILES_DIR=/var/lib/edumdns/web`

### Session Configuration

- **`EDUMDNS_COOKIE_SESSION_KEY`**
  - Secret key for encrypting and signing session cookies
  - Should be a random string of sufficient length (32+ bytes recommended)
  - If not set, an empty key is used, which is insecure
  - Generate a secure key: `openssl rand -base64 32`
  - Example: `EDUMDNS_COOKIE_SESSION_KEY=your-secret-key-here`

- **`EDUMDNS_USE_SECURE_COOKIE`** (optional, default: `false`)
  - Enable secure (HTTPS-only) cookies
  - Set to `true` for production deployments with TLS
  - When enabled, cookies will only be sent over HTTPS connections
  - Example: `EDUMDNS_USE_SECURE_COOKIE=true`

- **`EDUMDNS_WEB_SESSION_EXPIRY`** (optional, default: `2592000` seconds = 30 days)
  - Session expiry time in seconds
  - Determines how long a user session remains valid after login
  - After this duration, users must log in again
  - Example: `EDUMDNS_WEB_SESSION_EXPIRY=2592000` (30 days)

- **`EDUMDNS_WEB_LAST_VISIT_DEADLINE`** (optional, default: `604800` seconds = 7 days)
  - Last visit deadline in seconds
  - Determines how long a session remains valid after the last activity
  - If a user doesn't visit the site within this period, the session expires
  - This is separate from the login deadline and helps ensure active sessions
  - Example: `EDUMDNS_WEB_LAST_VISIT_DEADLINE=604800` (7 days)

### OpenID Connect (OIDC) Configuration

The following variables are required if OIDC authentication is desired. If not set, the system will use local authentication only. OIDC is optional and the system will gracefully fall back to local authentication if OIDC configuration is incomplete.

- **`EDUMDNS_OIDC_CLIENT_ID`** (optional, required for OIDC)
  - OIDC client ID from your identity provider
  - Obtained when registering the application with your OIDC provider
  - Example: `EDUMDNS_OIDC_CLIENT_ID=edumdns-client`

- **`EDUMDNS_OIDC_CLIENT_SECRET`** (optional, required for OIDC)
  - OIDC client secret from your identity provider
  - Keep this value secure and do not expose it in version control
  - Example: `EDUMDNS_OIDC_CLIENT_SECRET=your-client-secret`

- **`EDUMDNS_OIDC_CALLBACK_URL`** (optional, required for OIDC)
  - Callback URL for OIDC authentication flow
  - Must exactly match the redirect URI configured in your identity provider
  - Typically follows the pattern: `https://your-domain/login/oidc/redirect`
  - Example: `EDUMDNS_OIDC_CALLBACK_URL=https://edumdns.example.com/login/oidc/redirect`

- **`EDUMDNS_OIDC_ISSUER`** (optional, required for OIDC)
  - OIDC issuer URL (base URL of your identity provider)
  - This is the base URL where the OIDC provider's discovery endpoint is located
  - Example: `EDUMDNS_OIDC_ISSUER=https://auth.example.com/realms/edumdns`

- **`EDUMDNS_OIDC_NEW_USERS_ADMIN`** (optional, default: `false`)
  - Whether new users created via OIDC should automatically have administrator privileges
  - Set to `true` to grant admin access to all OIDC-authenticated users
  - **Warning**: Use with caution in production environments
  - Example: `EDUMDNS_OIDC_NEW_USERS_ADMIN=false`

### Access Control List (ACL) Database Configuration

These variables are used for integrating with an external database (typically a RADIUS database) to determine access point information for device access control.

- **`EDUMDNS_ACL_AP_DATABASE_CONNECTION_STRING`** (optional)
  - PostgreSQL connection string for the ACL access point database
  - Used for querying access point information for device access control
  - If not set, ACL database queries will be disabled
  - Format: `host=hostname user=username password=password dbname=database port=5432`
  - Example: `EDUMDNS_ACL_AP_DATABASE_CONNECTION_STRING="host=radius-db user=postgres password=postgres dbname=radius port=5432"`

- **`EDUMDNS_ACL_AP_DATABASE_QUERY`** (optional)
  - SQL query template for retrieving access point information
  - Should use parameterized queries with `$$1` for the IP address parameter
  - The query should return a result set with access point information
  - If not set, ACL database queries will be disabled
  - Example: `EDUMDNS_ACL_AP_DATABASE_QUERY="SELECT ap FROM log WHERE ip = $$1"`

---

## Features

### Authentication

- **Local Authentication**: Username/password authentication with session management
- **OpenID Connect**: Integration with OIDC providers for single sign-on (SSO)
- **Session Management**: Configurable session expiry (30 days default) with secure cookie support

### User Interface

- **Template Engine**: Minijinja templates with auto-reload support for development
- **Static Files**: Serves static assets from the configured files directory
- **WebSocket Support**: Real-time updates for probe status and monitoring

### API Endpoints

The web interface provides RESTful endpoints for:

- **Users**: User management, password updates, group assignments
- **Probes**: Probe registration, configuration, monitoring, and control
- **Devices**: Device discovery, publishing, hiding, and packet transmission
- **Packets**: Packet viewing, creation, and management
- **Groups**: Group management and permission assignments

### Middleware

- **CORS**: Configurable CORS support
- **Session**: Cookie-based session management
- **Identity**: User identity tracking and authentication
- **OIDC**: OpenID Connect authentication middleware (when configured)
