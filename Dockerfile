# syntax=docker/dockerfile:1
# EdgeCat pure-static scratch container image (CGO_ENABLED=0, non-root, zero shell)

FROM golang:1.26-alpine AS builder

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /out/edgecat ./cmd/edgecat && \
    mkdir -p /out/data

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /out/edgecat /edgecat
COPY configs/edgecat.docker.yaml /etc/edgecat/edgecat.yaml
COPY --from=builder --chown=65532:65532 /out/data /var/lib/edgecat

USER 65532:65532
VOLUME ["/var/lib/edgecat"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/edgecat", "ping", "-config", "/etc/edgecat/edgecat.yaml"]

ENTRYPOINT ["/edgecat"]
CMD ["-config", "/etc/edgecat/edgecat.yaml"]
