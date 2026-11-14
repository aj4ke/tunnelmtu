BINARY  := tunnelmtu
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
ARCHES  := amd64 arm64

LDFLAGS := -s -w -X main.version=$(VERSION)

HOST ?= root@10.0.0.240
ARCH ?= amd64

.PHONY: tidy fmt lint build clean dist deploy

tidy:
	go mod tidy

fmt:
	go fmt ./...

lint:
	go vet ./...
	uvx ruff check test_mtu.py

build:
	@for arch in $(ARCHES); do \
		echo "building linux/$$arch"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY)-linux-$$arch . || exit 1; \
	done

dist: tidy fmt build

deploy: build
	scp dist/$(BINARY)-linux-$(ARCH) $(HOST):~/$(BINARY)

clean:
	rm -rf dist
