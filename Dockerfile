# syntax=docker/dockerfile:1

# The build stage runs on the builder's own platform and cross-compiles, so a
# multi-platform build needs no emulation. The SQLite driver is pure Go, so
# cgo stays off.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-s -w -X tule.dev/functions/internal/util/buildinfo.Version=${VERSION}" \
    -o /out/tule-functions ./cmd \
 && mkdir -p /out/data

# Alpine rather than distroless, for a shell to debug in and wget for the
# health check.
FROM alpine:3.24
# 65532 is the distroless nonroot user's UID and GID, which keeps a volume
# written by this image usable by the other tule service images.
RUN addgroup -S -g 65532 nonroot && adduser -S -u 65532 -G nonroot nonroot
# gas/config reads .env from the working directory and refuses to when that is
# /, so the server must not start there.
WORKDIR /home/nonroot
LABEL org.opencontainers.image.source=https://github.com/tulehq/functions \
      org.opencontainers.image.description="AWS Lambda-compatible service that runs container-image functions through Docker, for local development and end-to-end tests" \
      org.opencontainers.image.licenses=MIT
COPY --from=build /out/tule-functions /tule-functions
COPY --from=build --chown=nonroot:nonroot /out/data /data

# TULE_Auth_AccessKeyID and TULE_Auth_SecretAccessKey must be set at run time;
# every request is verified against them, and the image ships no default so it
# cannot come up accepting a key everyone knows. The functions, mappings and
# invocation history live in one SQLite file on the /data volume. The
# functions run on the Docker daemon whose socket is mounted at
# /var/run/docker.sock; the nonroot user needs the socket's group
# (docker run --group-add). Port 9061 is the Runtime API the function
# containers call back on, through the Docker host, so it is published too,
# and the Runtime API listens on every interface of this container.
ENV TULE_GasEnv=development \
    TULE_Store_Path=/data/functions.db \
    TULE_Functions_RuntimeAPIBind=0.0.0.0

USER nonroot
EXPOSE 9060 9061
VOLUME /data
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${TULE_Server_Port:-9060}/_ready" || exit 1
ENTRYPOINT ["/tule-functions"]
