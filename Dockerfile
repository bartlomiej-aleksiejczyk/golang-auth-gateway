# Build stage
FROM golang:1.17-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

RUN go build -o server ./

# Run stage
FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/server .

CMD ["./server"]
