# Builds one binary from ./cmd/<CMD> into a distroless, non-root image.
#   docker build --build-arg CMD=mockvendor -t configbridge-mockvendor .
# TODO before production: pin both base images by digest (@sha256:...).
FROM golang:1.27 AS build
ARG CMD
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN test -n "$CMD" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/${CMD}

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
