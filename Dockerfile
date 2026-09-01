# Kitelon production image: full tool chain via install.sh.
# Build:  docker build -t kitelon:local .
# Run:    docker compose up -d   (see docker-compose.yml)

FROM ubuntu:24.04

LABEL org.opencontainers.image.title="Kitelon" \
      org.opencontainers.image.description="Offensive security automation platform" \
      org.opencontainers.image.source="https://github.com/kitelon"

ENV DEBIAN_FRONTEND=noninteractive \
    KITELON_INSTALL_DIR=/usr/share/kitelon \
    GOPATH=/root/go

# install.sh expects a kitelon.conf in the build tree (non-interactive install).
COPY docker/kitelon.conf /build/kitelon.conf
COPY . /build/

WORKDIR /build
RUN bash install.sh force -y

COPY docker/entrypoint.sh /usr/local/bin/kitelon-entrypoint.sh
RUN chmod 755 /usr/local/bin/kitelon-entrypoint.sh \
    && rm -rf /build

VOLUME ["/usr/share/kitelon/loot", "/var/log/kitelon"]
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/kitelon-entrypoint.sh"]
CMD ["help"]
