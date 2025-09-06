FROM rust:1.88 as base

RUN apt-get update
RUN apt-get install -y postgresql-client zip build-essential autoconf libtool pkg-config libgexiv2-dev

RUN cargo install cargo-chef --version 0.1.68


FROM base AS planner

WORKDIR /usr/src/edumdns

COPY ./.env ./.env
COPY ./migrations ./migrations
COPY ./src ./src
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
RUN cargo chef prepare --recipe-path recipe.json


FROM base as builder
WORKDIR /usr/src/edumdns

RUN mkdir ./media
ENV SQLX_OFFLINE=true

COPY --from=planner /usr/src/edumdns/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY ./.env ./.env
COPY ./.sqlx ./.sqlx
COPY ./migrations ./migrations
COPY ./src ./src
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

RUN cargo build --release --bin edumdns


FROM debian:bookworm-slim AS runtime
RUN apt-get update
RUN apt-get install -y zip pkg-config libgexiv2-dev

WORKDIR /usr/src/edumdns
COPY --from=builder /usr/src/edumdns/target/release/edumdns /usr/local/bin

COPY ./static ./static
COPY ./templates ./templates
COPY ./media ./media
COPY ./webroot ./webroot

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/edumdns"]





