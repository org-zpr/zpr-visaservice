.PHONY: all build test check

all: build

build:
	cargo build --all-targets

test: build
	cargo test

check:
	cargo fmt --check && cargo rustc --lib -- -D warnings

.DEFAULT_GOAL := all
