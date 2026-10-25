.PHONY: build test run system-test
build:
	go build -o bin/armo-mcp ./cmd/armo-mcp
test:
	go test ./...
run:
	go run ./cmd/armo-mcp
system-test:
	go test -tags systemtest ./test/system/... -v
