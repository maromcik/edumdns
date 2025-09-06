FROM rust:1.89 as base

RUN apt-get update
RUN apt-get install -y postgresql-client zip build-essential autoconf libtool pkg-config libpq-dev libpcap-dev libssl-dev

RUN cargo install cargo-chef --version 0.1.72


FROM base AS planner

WORKDIR /usr/src/edumdns

COPY . .

RUN cargo chef prepare --recipe-path recipe.json


FROM base as builder
WORKDIR /usr/src/edumdns

COPY --from=planner /usr/src/edumdns/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY . .

RUN cargo build --release --bin edumdns


FROM debian:bookworm-slim AS runtime
RUN apt-get update
RUN apt-get install -y zip pkg-config libpq-dev libpcap-dev libssl-dev

WORKDIR /usr/src/edumdns
COPY --from=builder /usr/src/edumdns/target/release/edumdns /usr/local/bin

COPY . .

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/edumdns"]





