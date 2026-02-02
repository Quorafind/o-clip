# ---- Build stage ----
FROM rust:1.85-bookworm AS builder

WORKDIR /build

# Cache dependencies: copy manifests first, build a dummy main to cache deps
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main(){}" > src/main.rs
RUN cargo build --release && rm -rf src target/release/.fingerprint/fast-copy-server-*

# Copy real source and build
COPY src/ src/
RUN cargo build --release

# ---- Runtime stage ----
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -s /usr/sbin/nologin -m fastcopy

WORKDIR /app

COPY --from=builder /build/target/release/fast-copy-server /app/fast-copy-server

# Data volume for SQLite database and config
RUN mkdir -p /app/data && chown fastcopy:fastcopy /app/data
VOLUME /app/data

USER fastcopy

ENV RUST_LOG=info

EXPOSE 8080

ENTRYPOINT ["/app/fast-copy-server"]
CMD ["/app/data/server.toml"]
