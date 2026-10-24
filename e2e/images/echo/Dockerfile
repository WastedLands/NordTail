# E2E stand-in for "the internet": reports request source addresses (HTTP + DNS).
FROM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY e2e/echo ./e2e/echo
RUN CGO_ENABLED=0 go build -trimpath -o /echo ./e2e/echo

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /echo /echo
USER 0:0
ENTRYPOINT ["/echo"]
