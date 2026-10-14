FROM rust:1.89-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo generate-lockfile && cargo test --locked && cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends gh git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --create-home --home-dir /home/ssh-connector sshconnector
WORKDIR /app
COPY --from=builder /src/target/release/ssh-connector /usr/local/bin/ssh-connector
COPY static /app/static
RUN mkdir -p /app/data && chown -R sshconnector:sshconnector /app
USER sshconnector
ENV SSH_CONNECTOR_BIND_ADDRESS=0.0.0.0
ENV RUST_LOG=info
VOLUME ["/app/data"]
EXPOSE 7600
ENTRYPOINT ["/usr/local/bin/ssh-connector"]
CMD ["--data-dir", "/app/data"]
