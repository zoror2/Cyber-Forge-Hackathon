FROM golang:1.27.3 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/configbridge ./cmd/configbridge && CGO_ENABLED=0 go build -trimpath -o /out/fixturevendor ./cmd/fixturevendor

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ /app/
EXPOSE 8080 8090
ENTRYPOINT ["/app/configbridge"]
