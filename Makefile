RELEASE_DIR := build-release
ARCH := $(shell uname -m)
RELEASE_TGZ := "release-linux-$(ARCH).tar.gz"

all: build

clean:
	rm -rf $(RELEASE_DIR)
	$(MAKE) -C libeval $@
	$(MAKE) -C zpt $@
	$(MAKE) -C vs-admin $@
	$(MAKE) -C vs $@

build:
	$(MAKE) -C libeval all
	$(MAKE) -C zpt all
	$(MAKE) -C vs all
	$(MAKE) -C vs-admin all

test:
	$(MAKE) -C libeval test
	$(MAKE) -C zpt test
	$(MAKE) -C vs test
	$(MAKE) -C vs-admin test

release:
	$(MAKE) clean
	$(MAKE) build
	mkdir -p $(RELEASE_DIR)
	./tools/sysinfo > $(RELEASE_DIR)/vs_sysinfo.txt
	cp zpt/target/debug/zpt $(RELEASE_DIR)
	cp vs/target/debug/vs $(RELEASE_DIR)
	cp vs-admin/target/debug/vs-admin $(RELEASE_DIR)
	cd $(RELEASE_DIR) && tar zcvf ../$(RELEASE_TGZ) .

pregen:
	$(MAKE) -C integration-test/pregen rebuild

sysinfo:
	tools/sysinfo

.PHONY: all clean build test release pregen sysinfo

.DEFAULT_GOAL := build
