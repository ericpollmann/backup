.PHONY: test build install run clean

BINARY=backup
INSTALL_DIR=~/bin

test:
	go fmt ./...
	go test -v

build:
	go build -o $(BINARY) main.go

install: build
	mkdir -p $(INSTALL_DIR)
	cp $(BINARY) $(INSTALL_DIR)/
	@echo "Installed $(BINARY) to $(INSTALL_DIR)"

run: build
	./$(BINARY)

clean:
	rm -f $(BINARY)
	go clean

# Run benchmarks
bench:
	go test -bench=. -benchmem

# Run tests with coverage
coverage:
	go test -cover -coverprofile=coverage.out
	go tool cover -html=coverage.out