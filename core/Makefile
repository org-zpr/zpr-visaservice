VERSION ?= "0.2.1"
PROJECT_NAME := vs
PKG := "zpr.org/$(PROJECT_NAME)"
PKG_LIST := $(shell go list ${PKG}/... | grep -v /vendor/)

OUT_DIR := build
PKG_VSERVICE := $(PKG)/cmd/vservice
GFLAGS:=


# If $BUILD=release then strip binaries.
ifeq ($(BUILD), release)
  $(info *BUILD=release)
  GFLAGS := $(GFLAGS) -ldflags="-s -w -X main.BuildVersion=$(VERSION)"
else
  GFLAGS := $(GFLAGS) -ldflags="-X main.BuildVersion=$(VERSION)"
endif


.PHONY: all build vservice test clean dist-clean

all: build


build: vservice


vservice:
	go build $(GFLAGS) -o $(OUT_DIR)/vservice -v $(PKG_VSERVICE)


test:
	go test -short ${PKG_LIST}


clean:
	rm -rf $(OUT_DIR)

dist-clean: clean


.DEFAULT_GOAL := all


