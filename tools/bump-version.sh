#!/bin/bash

# Usage: ./bump-version.sh 1.2.3

set -e

if [ -z "$1" ]; then
  echo "Usage: $0 <version>"
  echo "Example: $0 1.2.3"
  exit 1
fi

VERSION="$1"

# Split version string into components
IFS='.' read -r MAJOR MINOR PATCH <<<"$VERSION"

# Validate that each part is a number
if ! [[ "$MAJOR" =~ ^[0-9]+$ && "$MINOR" =~ ^[0-9]+$ && "$PATCH" =~ ^[0-9]+$ ]]; then
  echo "Invalid version number format. Use MAJOR.MINOR.PATCH (e.g., 1.2.3)"
  exit 2
fi

# --- Update Go version constants ---
VS_GO_FILE="../core/cmd/vservice/main.go"

if [ ! -f "$VS_GO_FILE" ]; then
  echo "Error: Go file $VS_GO_FILE not found."
  exit 3
fi

sed -i \
  -e "s/^\tversionMajor = .*/\tversionMajor = $MAJOR/" \
  -e "s/^\tversionMinor = .*/\tversionMinor = $MINOR/" \
  -e "s/^\tversionPatch = .*/\tversionPatch = $PATCH/" \
  "$VS_GO_FILE"

echo "Updated Go version constants in $VS_GO_FILE"

VSC_GO_FILE="../vs-conform/main.go"
if [ ! -f "$VSC_GO_FILE" ]; then
  echo "Error: Go file $VSC_GO_FILE not found."
  exit 4
fi

sed -i \
  -e "s/\t\tVersion:   .*/\t\tVersion:   \"$MAJOR.$MINOR.$PATCH\",/" \
  "$VSC_GO_FILE"

echo "Updated Go version constant in $VSC_GO_FILE"

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
