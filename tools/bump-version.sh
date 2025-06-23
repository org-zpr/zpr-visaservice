#!/bin/bash

# Usage: ./bump-version.sh 1.2.3

set -e

if [ -z "$1" ]; then
  echo "Usage: $0 <version>"
  echo "Example: $0 1.2.3"
  exit 1
fi

VERSION="$1"


# --- Update Go version constants ---
VS_MKFILE="../core/Makefile"

if [ ! -f "$VS_MKFILE" ]; then
  echo "Error: Go file $VS_GO_FILE not found."
  exit 3
fi

sed -i \
  -e "s/^VERSION ?= .*/VERSION ?= \"$VERSION\"/" \
  "$VS_MKFILE"

echo "Updated Go version constants in $VS_MKFILE"

VSC_MKFILE="../vs-conform/Makefile"
if [ ! -f "$VSC_MKFILE" ]; then
  echo "Error: Go file $VSC_GO_FILE not found."
  exit 4
fi

sed -i \
  -e "s/^VERSION ?= .*/VERSION ?= \"$VERSION\"/" \
  "$VSC_MKFILE"

echo "Updated Go version constant in $VSC_MKFILE"

# --- Update Cargo.toml version ---
CARGO_FILE="../vs-admin/Cargo.toml"

if [ ! -f "$CARGO_FILE" ]; then
  echo "Error: Cargo file $CARGO_FILE not found."
  exit 4
fi

sed -i.bak \
  -e "s/^version = \".*\"/version = \"$VERSION\"/" \
  "$CARGO_FILE"

echo "Updated Rust crate version in $CARGO_FILE"

# --- Done ---
echo "Version bump to $VERSION completed successfully."
