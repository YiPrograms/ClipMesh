FROM rust:1.96-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY server ./server
COPY client ./client
COPY crates ./crates
RUN cargo build --locked --release -p clipmesh-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* && useradd --system --uid 10001 --home /var/lib/clipmesh clipmesh
COPY --from=builder /build/target/release/clipmesh-server /usr/local/bin/clipmesh-server
RUN install -d -o clipmesh -g clipmesh /var/lib/clipmesh /var/lib/clipmesh/blobs
USER clipmesh
WORKDIR /var/lib/clipmesh
ENV CLIPMESH_LISTEN=0.0.0.0:8787 CLIPMESH_DATABASE_URL=sqlite:///var/lib/clipmesh/clipmesh.db CLIPMESH_BLOB_DIR=/var/lib/clipmesh/blobs
EXPOSE 8787
VOLUME ["/var/lib/clipmesh"]
ENTRYPOINT ["/usr/local/bin/clipmesh-server"]
