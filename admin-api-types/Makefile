
.PHONY: all build test check

all: build

build:
	cargo build --all-targets

test: build
	cargo test --verbose

check:
	cargo fmt --check && cargo rustc -- -D warnings

.DEFAULT_GOAL := all
