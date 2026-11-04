# Kitelon production image: full tool chain via install.sh.
# Build:  docker build -t kitelon:local .
# Run:    docker compose up -d   (see docker-compose.yml)

FROM ubuntu:24.04

# Refresh base packages on each image build (weekly cron rebuild pulls latest base).
RUN apt-get update \
    && apt-get -y full-upgrade \
    && rm -rf /var/lib/apt/lists/*

LABEL org.opencontainers.image.title="Kitelon" \
      org.opencontainers.image.description="Offensive security automation platform" \
      org.opencontainers.image.source="https://github.com/kitelon"

ENV DEBIAN_FRONTEND=noninteractive \
    KITELON_INSTALL_DIR=/usr/share/kitelon \
    KITELON_MSFDB_USER=kitelon \
    KITELON_DOCKER=1 \
    GOPATH=/root/go

# install.sh expects a kitelon.conf in the build tree (non-interactive install).
COPY docker/kitelon.conf /build/kitelon.conf
COPY . /build/

WORKDIR /build
# Drop build-only caches in the same layer so they never land in the image
# (Go module/build caches and pip/apt caches add several GB otherwise).
RUN useradd --create-home --shell /bin/bash kitelon \
    && bash install.sh force -y \
    && (command -v go >/dev/null && go clean -cache -modcache || true) \
    && rm -rf /root/go/pkg /root/.cache /home/kitelon/.cache \
              /var/lib/apt/lists/* /var/cache/apt/archives/*.deb /tmp/*

COPY docker/entrypoint.sh /usr/local/bin/kitelon-entrypoint.sh
RUN chmod 755 /usr/local/bin/kitelon-entrypoint.sh \
    && rm -rf /build

VOLUME ["/usr/share/kitelon/loot", "/var/log/kitelon"]
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/kitelon-entrypoint.sh"]
CMD ["help"]
