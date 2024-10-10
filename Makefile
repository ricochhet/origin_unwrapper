.PHONY: fmt mod lint test deadcode

fmt:
	gofumpt -l -w .

mod:
	go get -u
	go mod tidy


lint:
	golangci-lint run

test:
	go test ./...

deadcode:
	deadcode ./...