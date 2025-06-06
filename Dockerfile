FROM golang:1.24-alpine

WORKDIR /app
RUN apk add --no-cache make && go install github.com/air-verse/air@latest \
    && go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest

COPY . .

RUN make build

EXPOSE 8080

# CMD ["./tmp/main"]
CMD ["air", "-c", ".air.toml"]
