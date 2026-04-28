FROM golang:1.26 AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
ARG VERSION=dev
ARG COMMIT=
COPY . .

# Build for linux/amd64 and linux/arm64 so both are available for self-hosted download.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -ldflags="-s -w -X github.com/rinseaid/identree/internal/server.version=${VERSION} -X github.com/rinseaid/identree/internal/server.commit=${COMMIT}" \
    -o /app/identree-linux-amd64 ./cmd/identree/ && \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
    -ldflags="-s -w -X github.com/rinseaid/identree/internal/server.version=${VERSION} -X github.com/rinseaid/identree/internal/server.commit=${COMMIT}" \
    -o /app/identree-linux-arm64 ./cmd/identree/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r identree && useradd -r -g identree -s /sbin/nologin identree && \
    mkdir -p /data /config && chown identree:identree /data /config

ARG TARGETARCH
COPY --from=builder /app/identree-linux-${TARGETARCH} /usr/local/bin/identree
RUN chmod 755 /usr/local/bin/identree

USER identree
EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget --spider -q http://localhost:8090/healthz || exit 1

ENTRYPOINT ["identree", "serve"]
