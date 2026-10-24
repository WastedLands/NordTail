# NordTail image: the controller plus a pinned, checksum-verified tailscaled.
# Multi-arch without emulation: Go cross-compiles, and tailscaled is fetched
# for the target architecture; no build step runs on the target platform.
FROM --platform=$BUILDPLATFORM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/nordtail ./cmd/nordtail

ARG TS_VERSION=1.104.2
ARG TS_SHA256_amd64=512f613ed7d04fc7282f7dc5bd76aa105aae28168fbb9357eb749ebcbc29f0ae
ARG TS_SHA256_arm64=5776aaa901b5ef1916e66be5bb54b9f481cd399c9c28db123a8cab620efa237b
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) sum="$TS_SHA256_amd64" ;; \
      arm64) sum="$TS_SHA256_arm64" ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/ts.tgz "https://pkgs.tailscale.com/stable/tailscale_${TS_VERSION}_${TARGETARCH}.tgz"; \
    echo "$sum  /tmp/ts.tgz" | sha256sum -c -; \
    tar -xzf /tmp/ts.tgz -C /tmp; \
    install -m 0755 "/tmp/tailscale_${TS_VERSION}_${TARGETARCH}/tailscaled" /out/tailscaled

FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY --from=build /out/nordtail /out/tailscaled /usr/local/bin/
VOLUME /data
ENTRYPOINT ["/usr/local/bin/nordtail"]
