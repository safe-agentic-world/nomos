FROM golang:1.24.13-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/nomos ./cmd/nomos

FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --from=builder /out/nomos /app/nomos
USER nonroot:nonroot
ENTRYPOINT ["/app/nomos"]
