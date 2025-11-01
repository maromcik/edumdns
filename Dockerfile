FROM rust:1.91 as base

RUN apt-get update
RUN apt-get install -y postgresql-client zip build-essential autoconf libtool pkg-config libpq-dev libpcap-dev libssl-dev libxdp-dev clang

RUN cargo install cargo-chef --version 0.1.73

WORKDIR /usr/src/app/

FROM base AS planner

COPY ./edumdns_core ./edumdns_core
COPY ./edumdns/ ./edumdns

RUN cd edumdns && cargo chef prepare --recipe-path recipe.json


FROM base as builder

COPY --from=planner /usr/src/app/edumdns/recipe.json edumdns/recipe.json

COPY ./edumdns_core ./edumdns_core
RUN cd edumdns && cargo chef cook --release --recipe-path recipe.json

COPY ./edumdns/ ./edumdns

RUN cd edumdns && cargo build --release --bin edumdns


FROM debian:trixie-slim AS runtime
RUN apt-get update
RUN apt-get install -y zip pkg-config libpq-dev libpcap-dev libssl-dev libxdp-dev clang

WORKDIR /usr/src/edumdns
COPY --from=builder /usr/src/app/edumdns/target/release/edumdns /usr/local/bin

COPY ./edumdns/edumdns_web/static ./edumdns_web/static
COPY ./edumdns/edumdns_web/templates ./edumdns_web/templates
COPY ./edumdns/edumdns_web/webroot ./edumdns_web/webroot

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/edumdns"]





