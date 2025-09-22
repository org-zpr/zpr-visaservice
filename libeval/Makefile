.PHONY: all build test clean check

all: build

build:
	cargo build --all-targets

test: build
	cargo test

check:
	cargo fmt --check && cargo rustc --lib -- -D warnings

clean:
	cargo clean

.DEFAULT_GOAL := all
