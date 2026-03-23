# Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
# SPDX-License-Identifier: MIT
#
# NOTE: Parallel builds (make -j) are NOT supported. The build number file
# (version/build_number.txt) is updated non-atomically; concurrent make
# processes would produce duplicate build numbers or a corrupted file.
# Always run make without the -j flag.
.PHONY: build test clean all linux windows darwin cross vet coverage test-short
.NOTPARALLEL:

BINARY=spk
VERSION?=$(shell if [ -f version/version_base.txt ]; then head -1 version/version_base.txt | tr -cd '0-9.'; else echo "1.0.0"; fi)
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
BUILD_NUMBER_FILE=version/build_number.txt
BUILD_NUMBER=$(shell if [ -f $(BUILD_NUMBER_FILE) ]; then cat $(BUILD_NUMBER_FILE); else echo 0; fi)
NEXT_BUILD=$(shell echo $$(( $(BUILD_NUMBER) + 1 )))
FULL_VERSION=$(VERSION).$(NEXT_BUILD)
LDFLAGS_BASE=-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildNumber=$(NEXT_BUILD) -s -w
BUILD_DIR=build

# pcap is dynamically loaded at runtime -- no SDK or headers needed.
# Windows: always pure Go (CGO_ENABLED=0), pcap via wpcap.dll at runtime.
# Linux/macOS: CGO_ENABLED=1 for dlfcn.h (dlopen), pcap via libpcap.so at runtime.
# Set NOPCAP=1 to build Linux/macOS without pcap (CGO_ENABLED=0).

all: test build

build:
	@echo $(NEXT_BUILD) > $(BUILD_NUMBER_FILE)
ifdef NOPCAP
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS_BASE)" -o $(BINARY)_$(FULL_VERSION) ./cmd/spk/
else
	CGO_ENABLED=1 go build -ldflags "$(LDFLAGS_BASE)" -o $(BINARY)_$(FULL_VERSION)p ./cmd/spk/ || \
		(echo "CGO build failed, falling back to no-pcap"; CGO_ENABLED=0 go build -ldflags "$(LDFLAGS_BASE)" -o $(BINARY)_$(FULL_VERSION) ./cmd/spk/)
endif

test:
	go test $(shell go list ./... | grep -v /sniffer) -v -count=1

test-short:
	go test $(shell go list ./... | grep -v /sniffer) -count=1

coverage:
	go test $(shell go list ./... | grep -v /sniffer) -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

vet:
	go vet ./...

clean:
	rm -f $(BINARY) $(BINARY).exe $(BINARY)_*
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Cross-compilation (delegates to build.sh for full logic)
cross:
	./build.sh -all

linux:
	./build.sh -linux

windows:
	./build.sh -windows

darwin:
	./build.sh -darwin
