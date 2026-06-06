FROM rust:1.80-slim as builder

WORKDIR /app
COPY . .

RUN cargo build --release --all-features

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Run as an unprivileged user
RUN useradd --create-home --uid 10001 batin

COPY --from=builder /app/target/release/batin /usr/local/bin/batin

USER batin
WORKDIR /scan

ENTRYPOINT ["batin"]
CMD ["--help"]
