NAME := mitmengine
GIT_VERSION := $(shell git describe --tags --always --dirty="-dev")
TIMESTAMP := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ UTC')
VERSION_FLAGS := -ldflags='-X "main.BuildVersion=$(GIT_VERSION)" -X "main.BuildTime=$(DATE)"'

BIN_DIR := ./bin
CMDS := $(notdir $(wildcard cmd/*))
TARGETS = $(addprefix $(BIN_DIR)/,$(CMDS))

$(BIN_DIR)/%:
	@if [ ! -d cmd/$* ]; then echo "Error: No directory at cmd/$*." && exit 1; fi
	go build -o bin/$* $(VERSION_FLAGS) ./cmd/$*
	@if [ $* = "webserver_integration_demo" ]; then openssl genrsa -out bin/private.key 2048; openssl req -new -x509 -sha256 -key bin/private.key -out bin/cert.crt -days 3650 -subj "/C=AA/ST=Tranquility/L=Eagle/O=Foo/CN=localhost"; fi

.PHONY: build
build: $(TARGETS)

.PHONY: test unit
test unit:
	go vet ./...
	go test ./... -cover -timeout=15s -run=Unit -race -count=1

.PHONY: cover
cover: TMPFILE := $(shell mktemp)
cover:
	go test -coverprofile=$(TMPFILE) ./...
	go tool cover -func=$(TMPFILE) && rm $(TMPFILE)

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)/*
