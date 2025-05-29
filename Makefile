.PHONY: build, run

build:
	@go mod tidy
	@mkdir -p tmp
	@go build -o tmp/ ./...

run:
	@./tmp/gobackend