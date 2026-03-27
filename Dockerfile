FROM golang:1.26 AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
ARG VERSION=dev
ARG COMMIT=
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=$(echo ${COMMIT} | cut -c1-8)" -o /app/identree ./cmd/identree/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r identree && useradd -r -g identree -s /sbin/nologin identree && \
    mkdir -p /data && chown identree:identree /data

COPY --from=builder /app/identree /usr/local/bin/identree

USER identree
EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget --spider -q http://localhost:8090/healthz || exit 1

ENTRYPOINT ["identree", "serve"]
