# Builds ONE Go program from ./cmd/<CMD> into a tiny, locked-down image.
#
#   docker build --build-arg CMD=mockvendor -t configbridge-mockvendor .
#   docker build --build-arg CMD=api        -t configbridge-api .        (Member B, later)
#
# Two stages:
#   1. "build": full Go toolchain compiles the binary.
#   2. final:   only the binary is copied into a distroless image. No shell,
#               no package manager, nothing an attacker could use after
#               breaking in. Runs as a non-root user.
#
# TODO before production: pin both base images by digest (@sha256:...) so a
# changed upstream image can't silently change what we ship.

# ---- Stage 1: compile ----
FROM golang:1.27 AS build
# Which program under ./cmd to build (mockvendor, api, ...)
ARG CMD
WORKDIR /src
# Copy only what the build needs (see .dockerignore for what's excluded)
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
# CGO_ENABLED=0  -> fully static binary (needed for the distroless/static image)
# -trimpath      -> no local file paths embedded in the binary
# -ldflags=-s -w -> strip debug symbols (smaller binary)
# test -n "$CMD" -> fail loudly if CMD wasn't given
RUN test -n "$CMD" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/${CMD}

# ---- Stage 2: run ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
# UID 65532, never root
USER nonroot:nonroot
ENTRYPOINT ["/app"]
