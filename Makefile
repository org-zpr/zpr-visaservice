RELEASE_DIR := build-release
ARCH := $(shell uname -m)
RELEASE_TGZ := "release-linux-$(ARCH).tar.gz"

all: build

all-rs: build-rs

all-go: build-go

test: test-rs test-go

clean:
	rm -rf $(RELEASE_DIR)
	$(MAKE) -C core $@
	$(MAKE) -C vs-admin $@
	$(MAKE) -C vs-conform $@

build:
	$(MAKE) -C core all
	$(MAKE) -C vs-admin all
	$(MAKE) -C vs-conform all

build-go:
	$(MAKE) -C core all
	$(MAKE) -C vs-conform all

build-rs:
	$(MAKE) -C vs-admin all

test-go:
	$(MAKE) -C core test
	$(MAKE) -C vs-conform test

test-rs:
	$(MAKE) -C vs-admin test

release:
	$(MAKE) clean
	$(MAKE) build
	mkdir -p $(RELEASE_DIR)
	cp core/build/vservice $(RELEASE_DIR)
	cp vs-admin/target/debug/vs-admin $(RELEASE_DIR)
	cp vs-conform/build/vs-conform $(RELEASE_DIR)
	cd $(RELEASE_DIR) && tar zcvf ../$(RELEASE_TGZ) .

.PHONY: all all-rs all-go test clean build build-go build-rs test-go test-rs release
