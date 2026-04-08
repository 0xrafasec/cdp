FROM rust:1.87-slim AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --bin cdp-gate --bin cdp-wrap

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/cdp-gate /usr/bin/cdp-gate
COPY --from=builder /build/target/release/cdp-wrap /usr/bin/cdp-wrap
RUN mkdir -p /run/cdp && chmod 0770 /run/cdp
EXPOSE 9443
VOLUME ["/run/cdp"]
ENTRYPOINT ["/usr/bin/cdp-gate"]
