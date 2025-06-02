.PHONY: build, run

build:
	@go mod tidy
	@mkdir -p tmp
	@go build -o tmp/main main.go

run:
	@./tmp/main