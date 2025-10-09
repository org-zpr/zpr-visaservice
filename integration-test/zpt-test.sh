#!/usr/bin/env bash
set -euo pipefail

ZPT_BIN=$(realpath "$(dirname $0)/../zpt/target/debug/zpt")
INPUT=$(realpath "$(dirname $0)/../zpt/test-data/test-signal.zpt")


"$ZPT_BIN" -i "$INPUT" | grep 'eval 1: Decision ALLOW'
PASS=$?

echo
if [[ "$PASS" -ne 0 ]]; then
  echo "FAILURE on eval 1"
  exit "$PASS"
fi


"$ZPT_BIN" -i "$INPUT" | grep 'eval 2: Decision NO MATCH'

echo
if [[ "$PASS" == 0 ]]; then
  echo "SUCCESS"
else
  echo "FAILURE on eval 2"
  exit "$PASS"
fi




