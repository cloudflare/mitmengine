SHELL=/bin/bash

# Build

NAME :=mitmengine
VERSION := $(shell git rev-list --count HEAD)-$(shell git rev-parse --short HEAD)
TIMESTAMP := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := "-X main.Version=$(VERSION) -X main.BuildTime=$(TIMESTAMP)"
BUILD := build
IMPORT_PATH := github.com/cloudflare/$(NAME)
GO := go
GOPATH = ./.GOPATH
export GOPATH = $(CURDIR)/.GOPATH
DEP := $(GOPATH)/bin/dep
BIN_DIR := ./bin
GOFILES := $(shell find . -name "*\.go")
CMDS := $(notdir $(wildcard cmd/*))
TARGETS = $(addprefix $(BIN_DIR)/,$(CMDS))

.PHONY: vendor
vendor: $(DEP)
	cd .GOPATH/src/$(IMPORT_PATH) && $(DEP) ensure

$(DEP): .GOPATH/.ok
	$(GO) get -u github.com/golang/dep/cmd/dep

.PHONY: init
init: .GOPATH/.ok
	cd .GOPATH/src/$(IMPORT_PATH) && $(DEP) init

$(BIN_DIR)/%: .GOPATH/.ok $(GOFILES)
	@if [ ! -d cmd/$* ]; then echo "Error: No directory at cmd/$*." && exit 1; fi
	$(GO) install -ldflags $(LDFLAGS) $(IMPORT_PATH)/cmd/$*

.PHONY: install build
install build: $(TARGETS)

.GOPATH/.ok:
	mkdir -p "$(dir .GOPATH/src/$(IMPORT_PATH))"
	ln -s ../../../.. ".GOPATH/src/$(IMPORT_PATH)"
	mkdir -p .GOPATH/test .GOPATH/cover
	mkdir -p bin
	ln -s ../bin .GOPATH/bin
	touch $@

# Test

.PHONY: test unit
test unit: .GOPATH/.ok
	cd $(GOPATH)/src/$(IMPORT_PATH) && $(GO) test -cover -v ./...

# Misc

.PHONY: clean
clean:
	rm -rf build $(GOPATH) bin/*

.PHONY: vet
vet:
	$(GO) vet -v $(addprefix $(IMPORT_PATH)/,$(wildcard cmd/*))

.PHONY: godoc
godoc:
	godoc $(IMPORT_PATH)/$(PKG)

.PHONY: lint
lint:
	cd $(GOPATH)/src/$(IMPORT_PATH) &&  (golint ./... | grep -v vendor || true)

.PHONY: cover
cover:
	cd $(GOPATH)/src/$(IMPORT_PATH) && $(GO) test -coverprofile=cover.out ./...
	cd $(GOPATH)/src/$(IMPORT_PATH) && $(GO) tool cover -func=cover.out && rm cover.out
