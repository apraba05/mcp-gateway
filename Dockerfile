# syntax=docker/dockerfile:1

FROM docker.io/library/golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY gateway ./gateway
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/mcp-gateway ./cmd/mcp-gateway

FROM scratch
LABEL org.opencontainers.image.source="https://github.com/apraba05/mcp-gateway" \
      org.opencontainers.image.description="Policy enforcement gateway for MCP HTTP traffic"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/mcp-gateway /mcp-gateway
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/mcp-gateway"]
