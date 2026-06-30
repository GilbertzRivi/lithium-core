# syntax=docker/dockerfile:1
#
# Reproducible build check for lithium_core. A library ships no binary, so this
# compiles the `kyberbox` example, which exercises the full hybrid construction,
# including the ML-KEM C code reached through FFI, and the workflow asserts two
# builds are bit-identical. Build context is the repository root:
#
#   docker build -f build/Dockerfile -t lithium-core-repro .
#   docker run --rm lithium-core-repro       # prints sha256 of the example binary
#
# Pin the base image by digest in production (replace the tag with
# rust:1.96.0-bookworm@sha256:<digest>) so a re-pushed tag cannot swap the toolchain.
FROM rust:1.96.0-bookworm

# Determinism: fixed timestamp and path remapping, so absolute build paths do not
# leak into the artifact (debug info, panic strings). The compiler version is
# pinned by the committed rust-toolchain.toml, which the FROM tag above matches.
ENV SOURCE_DATE_EPOCH=1 \
    CARGO_HOME=/usr/local/cargo \
    RUSTFLAGS="--remap-path-prefix=/build=. --remap-path-prefix=/usr/local/cargo=cargo"

WORKDIR /build
COPY . .

# --locked pins the exact dependency set from the committed Cargo.lock.
RUN cargo build --release --locked --example kyberbox

CMD ["sha256sum", "target/release/examples/kyberbox"]
