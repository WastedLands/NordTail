# E2E stand-in for a VPN provider: a WireGuard server that NATs tunnel traffic
# out of its own address, so "came through the VPN" is visible at the echo service.
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 wireguard-tools nftables procps \
 && rm -rf /var/lib/apt/lists/*
COPY e2e/images/fakevpn/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
