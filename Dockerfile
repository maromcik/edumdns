FROM rust:1.90 as base

RUN apt-get update
RUN apt-get install -y postgresql-client zip build-essential autoconf libtool pkg-config libpq-dev libpcap-dev libssl-dev libxdp-dev clang

RUN cargo install cargo-chef --version 0.1.72


FROM base AS planner

WORKDIR /usr/src/edumdns

COPY ./.env ./.env
COPY ./edumdns_core ./edumdns_core
COPY ./edumdns_core/Cargo.toml ./edumdns_core/Cargo.toml
COPY ./edumdns_probe ./edumdns_probe
COPY ./edumdns_probe/Cargo.toml ./edumdns_probe/Cargo.toml
COPY ./edumdns_db ./edumdns_db
COPY ./edumdns_db/Cargo.toml ./edumdns_db/Cargo.toml
COPY ./edumdns_server ./edumdns_server
COPY ./edumdns_server/Cargo.toml ./edumdns_server/Cargo.toml
COPY ./edumdns_web/src ./edumdns_web/src
COPY ./edumdns_web/Cargo.toml ./edumdns_web/Cargo.toml
COPY ./src ./src
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

RUN cargo chef prepare --recipe-path recipe.json


FROM base as builder
WORKDIR /usr/src/edumdns

COPY --from=planner /usr/src/edumdns/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY ./.env ./.env
COPY ./edumdns_core ./edumdns_core
COPY ./edumdns_core/Cargo.toml ./edumdns_core/Cargo.toml
COPY ./edumdns_probe ./edumdns_probe
COPY ./edumdns_probe/Cargo.toml ./edumdns_probe/Cargo.toml
COPY ./edumdns_db ./edumdns_db
COPY ./edumdns_db/Cargo.toml ./edumdns_db/Cargo.toml
COPY ./edumdns_server ./edumdns_server
COPY ./edumdns_server/Cargo.toml ./edumdns_server/Cargo.toml
COPY ./edumdns_web/src ./edumdns_web/src
COPY ./edumdns_web/Cargo.toml ./edumdns_web/Cargo.toml
COPY ./src ./src
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

RUN cargo build --release --bin edumdns


FROM debian:bookworm-slim AS runtime
RUN apt-get update
RUN apt-get install -y zip pkg-config libpq-dev libpcap-dev libssl-dev libxdp-dev clang

WORKDIR /usr/src/edumdns
COPY --from=builder /usr/src/edumdns/target/release/edumdns /usr/local/bin

COPY ./edumdns_web/static ./edumdns_web/static
COPY ./edumdns_web/templates ./edumdns_web/templates
COPY ./edumdns_web/webroot ./edumdns_web/webroot

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/edumdns"]





