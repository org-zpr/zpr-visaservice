VERSION ?= "0.6.0"
OUT_DIR := build
GFLAGS:=


# If $BUILD=release then strip binaries.
ifeq ($(BUILD), release)
  $(info *BUILD=release)
  GFLAGS := $(GFLAGS) -ldflags="-s -w -X main.BuildVersion=$(VERSION)"
else
  GFLAGS := $(GFLAGS) -ldflags="-X main.BuildVersion=$(VERSION)"
endif


.PHONY: all build test clean dist-clean

all: build

build:
	go build $(GFLAGS) -o $(OUT_DIR)/vs-conform

test:
	go test -short

clean:
	rm -rf $(OUT_DIR)

dist-clean: clean

.DEFAULT_GOAL := all


