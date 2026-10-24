# E2E test client: kernel-mode tailscaled plus probing tools.
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
ARG TS_VERSION=1.104.2
ARG TS_SHA256=512f613ed7d04fc7282f7dc5bd76aa105aae28168fbb9357eb749ebcbc29f0ae
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl jq iproute2 nftables dnsutils iputils-ping procps \
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSLo /tmp/ts.tgz "https://pkgs.tailscale.com/stable/tailscale_${TS_VERSION}_amd64.tgz" \
 && echo "${TS_SHA256}  /tmp/ts.tgz" | sha256sum -c - \
 && tar -xzf /tmp/ts.tgz -C /tmp \
 && install -m 0755 /tmp/tailscale_${TS_VERSION}_amd64/tailscale /tmp/tailscale_${TS_VERSION}_amd64/tailscaled /usr/local/bin/ \
 && rm -rf /tmp/ts.tgz /tmp/tailscale_*
ENTRYPOINT ["tailscaled", "--state=/var/lib/tailscale/tailscaled.state", "--tun=tailscale0"]
