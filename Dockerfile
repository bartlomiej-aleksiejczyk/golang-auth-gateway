# Build stage
FROM golang:1.17-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o server ./cmd/server

# Run stage
FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/server .

CMD ["./server"]
