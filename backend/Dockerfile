# syntax=docker/dockerfile:1
# Scanner backend: Go API + scheduler, with Trivy and Grype as matchers.
#
# Trivy and Grype are compiled from source here instead of copied out of their
# release images: that lets us build them with the newest Go toolchain and bump
# their crypto/network libraries to the latest patch releases, so the scanner
# image itself does not show up in its own CVE list. The runtime image is
# `scratch` - no shell, no package manager, no OS packages to patch.
ARG GO_IMAGE=golang:1.27-alpine

# Build stages run on the build machine and cross-compile, so multi-arch
# images (amd64 + arm64) build fast without emulation.
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS gobase
ARG TARGETOS=linux
ARG TARGETARCH
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
# Libraries bumped past what the upstream release pins (space separated,
# set to "" to build the tools exactly as released).
ARG TOOL_BUMPS="golang.org/x/crypto@latest golang.org/x/net@latest github.com/go-jose/go-jose/v4@latest"
WORKDIR /build

FROM gobase AS trivy
ARG TRIVY_VERSION=v0.76.1
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    dir=$(go mod download -json github.com/aquasecurity/trivy@${TRIVY_VERSION} | sed -n 's/.*"Dir": "\(.*\)",$/\1/p') \
 && cp -r "$dir" src && chmod -R u+w src && cd src \
 && if [ -n "$TOOL_BUMPS" ]; then go get $TOOL_BUMPS && go mod tidy; fi \
 && GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w -X github.com/aquasecurity/trivy/pkg/version/app.ver=${TRIVY_VERSION}" -o /out/trivy ./cmd/trivy

# WITH_GRYPE=false leaves Grype out (the scanner then uses Trivy only).
FROM gobase AS grype
ARG GRYPE_VERSION=v0.121.0
ARG WITH_GRYPE=true
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    mkdir -p /out && [ "$WITH_GRYPE" != "true" ] || { dir=$(go mod download -json github.com/anchore/grype@${GRYPE_VERSION} | sed -n 's/.*"Dir": "\(.*\)",$/\1/p') \
 && cp -r "$dir" src && chmod -R u+w src && cd src \
 && if [ -n "$TOOL_BUMPS" ]; then go get $TOOL_BUMPS && go mod tidy; fi \
 && GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w -X main.version=${GRYPE_VERSION}" -o /out/grype ./cmd/grype; }

FROM gobase AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go test ./... && GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w -X main.version=${VERSION}" -o /out/scanner ./cmd/scanner

# Minimal root filesystem: CA bundle, passwd entries and writable dirs.
FROM gobase AS rootfs
RUN mkdir -p /rootfs/etc/ssl/certs /rootfs/tmp /owned/data /owned/certs \
 && cp /etc/ssl/certs/ca-certificates.crt /rootfs/etc/ssl/certs/ \
 && printf 'root:x:0:0:root:/:/sbin/nologin\nscanner:x:10001:10001:scanner:/data:/sbin/nologin\n' > /rootfs/etc/passwd \
 && printf 'root:x:0:\nscanner:x:10001:\n' > /rootfs/etc/group \
 && chmod 1777 /rootfs/tmp && chmod 0750 /owned/data && chmod 0755 /owned/certs

FROM scratch
# Copy directory contents (not the dirs themselves) so modes like /tmp's 1777 survive.
COPY --from=rootfs /rootfs/ /
COPY --from=rootfs --chown=10001:10001 /owned/ /
COPY --from=trivy /out/trivy /usr/local/bin/trivy
COPY --from=grype /out/ /usr/local/bin/
COPY --from=build /out/scanner /usr/local/bin/scanner
USER 10001:10001
ENV PATH=/usr/local/bin DATA_DIR=/data CERT_DIR=/certs HOME=/data TMPDIR=/tmp
VOLUME ["/data", "/certs"]
EXPOSE 8000 8001
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["scanner", "healthcheck"]
ENTRYPOINT ["scanner"]
