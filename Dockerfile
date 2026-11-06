FROM rust:1.89-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo generate-lockfile && cargo test --locked && cargo build --release --locked

# gh 从官方 release 装，锁版本 + SHA256 校验；Debian 仓库的 gh 停在 2.23.0（2023-02）
ARG GH_VERSION=2.103.3
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    curl -fsSL -o /tmp/gh.tgz "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${arch}.tar.gz"; \
    curl -fsSL -o /tmp/gh.sum "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_checksums.txt"; \
    cd /tmp; \
    grep "gh_${GH_VERSION}_linux_${arch}.tar.gz" gh.sum | sha256sum -c -; \
    tar -xzf gh.tgz; \
    mkdir /tmp/ghbin; \
    install -m 0755 "/tmp/gh_${GH_VERSION}_linux_${arch}/bin/gh" /tmp/ghbin/gh; \
    rm -rf /tmp/gh.tgz /tmp/gh.sum "/tmp/gh_${GH_VERSION}_linux_${arch}"

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --create-home --home-dir /home/ssh-connector sshconnector
WORKDIR /app
COPY --from=builder /src/target/release/ssh-connector /usr/local/bin/ssh-connector
COPY --from=builder /tmp/ghbin/gh /usr/local/bin/gh
COPY static /app/static
RUN mkdir -p /app/data && chown -R sshconnector:sshconnector /app
USER sshconnector
ENV SSH_CONNECTOR_BIND_ADDRESS=0.0.0.0
ENV RUST_LOG=info
VOLUME ["/app/data"]
EXPOSE 7600
ENTRYPOINT ["/usr/local/bin/ssh-connector"]
CMD ["--data-dir", "/app/data"]
