RELEASE_DIR := build-release
ARCH := $(shell uname -m)
RELEASE_TGZ := "release-linux-$(ARCH).tar.gz"

all: build

clean:
	rm -rf $(RELEASE_DIR)
	cargo clean

check:
	cargo fmt --check
	$(MAKE) -C admin-api-types $@
	$(MAKE) -C vs $@
	$(MAKE) -C vs-admin $@
	$(MAKE) -C zpt $@

build:
	cargo build --all-targets

test:
	cargo test

release:
	$(MAKE) clean
	$(MAKE) build
	mkdir -p $(RELEASE_DIR)
	./tools/sysinfo > $(RELEASE_DIR)/vs_sysinfo.txt
	cp ./target/debug/zpt $(RELEASE_DIR)
	cp ./target/debug/vs $(RELEASE_DIR)
	cp ./target/debug/vs-admin $(RELEASE_DIR)
	cd $(RELEASE_DIR) && tar zcvf ../$(RELEASE_TGZ) .

pregen:
	$(MAKE) -C integration-test/pregen rebuild

sysinfo:
	tools/sysinfo

.PHONY: all clean check build test release pregen sysinfo

.DEFAULT_GOAL := build
