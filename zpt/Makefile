.PHONY: all build test clean check

all: build

build:
	cargo build --all-targets

test: build
	cargo test

check:
	cargo fmt --check 

clean:
	cargo clean

.DEFAULT_GOAL := all
