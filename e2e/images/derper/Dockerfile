# Harness relay: Tailscale's own DERP server with STUN, same version as the
# bundled tailscaled. It generates a self-signed certificate for its IP; the
# harness DERP map marks the node InsecureForTests.
FROM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
RUN CGO_ENABLED=0 GOBIN=/out go install tailscale.com/cmd/derper@v1.104.2

FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY --from=build /out/derper /usr/local/bin/derper
ENTRYPOINT ["/usr/local/bin/derper"]
