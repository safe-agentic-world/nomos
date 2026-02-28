FROM golang:1.24.13-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/janus ./cmd/janus

FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --from=builder /out/janus /app/janus
USER nonroot:nonroot
ENTRYPOINT ["/app/janus"]
