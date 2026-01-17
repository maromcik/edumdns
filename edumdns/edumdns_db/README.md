# edumdns_db

Database abstraction layer for the edumDNS system. This crate provides database initialization, migrations, and repository patterns for interacting with PostgreSQL.

## Overview

The `edumdns_db` crate handles all database-related operations for the edumDNS system, including:

- Database connection pooling using `diesel-async` with `deadpool`
- Embedded database migrations using `diesel_migrations`
- Repository pattern for data access
- Models and schema definitions for database tables

## Configuration

The database component is configured through the main `edumdns.toml` configuration file under the `[database]` section. See the main `edumdns` README for the complete configuration structure.

### Database Configuration (`[database]`)

- **`database.connection_string`** (required)
  - PostgreSQL connection string
  - Format: `postgres://[user[:password]@][host][:port][/database]`
  - Used for both running migrations and establishing the connection pool
  - Example: `postgres://edumdns:password@localhost:5432/edumdns`

- **`database.pool_size`** (optional, default: `20`)
  - Maximum number of database connections in the pool

## Features

### Database Initialization

The crate provides a `db_init()` function that:

1. Runs embedded database migrations to ensure the schema is up to date
2. Sets up a connection pool with a maximum of 20 connections
3. Returns a `Pool<AsyncPgConnection>` for use throughout the application

### Migrations

Database migrations are embedded at compile time using `diesel_migrations`. The migrations are automatically applied when `db_init()` is called, ensuring the database schema is always current.

### Repository Pattern

The crate provides repository implementations for:

- **Users**: User management and authentication
- **Probes**: Remote probe registration and configuration
- **Devices**: Smart device discovery and management
- **Packets**: mDNS packet storage and retrieval
- **Groups**: User group management and permissions

Each repository provides an async interface for database operations, abstracting away the details of SQL queries and database interactions.

## Usage

```rust
use edumdns_db::{db_init, config::DbConfig};

let db_config = DbConfig {
    connection_string: "postgres://...".to_string(),
    pool_size: 20,
};
let pool = db_init(db_config).await?;
// Use the pool for database operations
```

## Dependencies

- **diesel**: ORM and query builder
- **diesel-async**: Async database operations
- **diesel_migrations**: Embedded migration support
- **edumdns_core**: Shared types and utilities

