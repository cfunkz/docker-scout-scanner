# syntax=docker/dockerfile:1
# Scanner backend: Go API + scheduler, with Trivy and Grype as matchers.
ARG GO_IMAGE=golang:1.26-alpine
ARG TRIVY_IMAGE=aquasec/trivy:latest
ARG GRYPE_IMAGE=anchore/grype:latest
ARG BASE_IMAGE=alpine:3.22

FROM ${TRIVY_IMAGE} AS trivy
FROM ${GRYPE_IMAGE} AS grype

FROM ${GO_IMAGE} AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go test ./... && go build -ldflags="-s -w" -o /out/scanner ./cmd/scanner

FROM ${BASE_IMAGE}
# Alpine already ships the CA bundle; tzdata is embedded in the Go binary,
# so the runtime stage needs no package downloads.
RUN addgroup -S -g 10001 scanner && adduser -S -D -H -u 10001 -G scanner scanner \
 && mkdir -p /data /certs && chown scanner:scanner /data /certs
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=grype /grype /usr/local/bin/grype
COPY --from=build /out/scanner /usr/local/bin/scanner
USER 10001:10001
ENV DATA_DIR=/data CERT_DIR=/certs HOME=/data
VOLUME ["/data", "/certs"]
EXPOSE 8000 8001
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["scanner", "healthcheck"]
ENTRYPOINT ["scanner"]
