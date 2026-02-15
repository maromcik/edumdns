# Builds the edumdns directory.
# The file was placed here due to the dependency on the edumdns_core crate, and apparently
# files from the parent directory cannot be copied over.

FROM rust:1.91 as base

RUN apt-get update
RUN apt-get install -y postgresql-client zip build-essential autoconf libtool pkg-config libpq-dev libpcap-dev libssl-dev libxdp-dev clang

RUN cargo install cargo-chef --version 0.1.73

WORKDIR /usr/src/app/

FROM base AS planner

COPY ../edumdns_core ./edumdns_core

COPY ./edumdns/edumdns_db/ ./edumdns/edumdns_db
COPY ./edumdns/edumdns_server/ ./edumdns/edumdns_server

COPY ./edumdns/edumdns_web/templates/error.html ./edumdns/edumdns_web/templates/error.html
COPY ./edumdns/edumdns_web/templates/head.html ./edumdns/edumdns_web/templates/head.html
COPY ./edumdns/edumdns_web/src ./edumdns/edumdns_web/src
COPY ./edumdns/edumdns_web/Cargo.toml ./edumdns/edumdns_web/Cargo.toml

COPY ./edumdns/src ./edumdns/src
COPY ./edumdns/Cargo.toml ./edumdns/Cargo.toml
COPY ./edumdns/Cargo.lock ./edumdns/Cargo.lock

RUN cd edumdns && cargo chef prepare --recipe-path recipe.json


FROM base as builder

COPY --from=planner /usr/src/app/edumdns/recipe.json edumdns/recipe.json

COPY ../edumdns_core ./edumdns_core
RUN cd edumdns && cargo chef cook --release --recipe-path recipe.json

COPY ./edumdns/edumdns_db/ ./edumdns/edumdns_db
COPY ./edumdns/edumdns_server/ ./edumdns/edumdns_server

COPY ./edumdns/edumdns_web/templates/error.html ./edumdns/edumdns_web/templates/error.html
COPY ./edumdns/edumdns_web/templates/head.html ./edumdns/edumdns_web/templates/head.html
COPY ./edumdns/edumdns_web/src ./edumdns/edumdns_web/src
COPY ./edumdns/edumdns_web/Cargo.toml ./edumdns/edumdns_web/Cargo.toml

COPY ./edumdns/src ./edumdns/src
COPY ./edumdns/Cargo.toml ./edumdns/Cargo.toml
COPY ./edumdns/Cargo.lock ./edumdns/Cargo.lock

RUN cd edumdns && cargo build --release --bin edumdns


FROM debian:trixie-slim AS runtime
RUN apt-get update
RUN apt-get install -y zip pkg-config libpq-dev libpcap-dev libssl-dev libxdp-dev clang

WORKDIR /usr/src/edumdns
COPY --from=builder /usr/src/app/edumdns/target/release/edumdns /usr/local/bin

COPY ./edumdns/edumdns_web/static ./edumdns_web/static
COPY ./edumdns/edumdns_web/templates ./edumdns_web/templates

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/edumdns"]





