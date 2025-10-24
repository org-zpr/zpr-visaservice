#!/usr/bin/env bash
set -euo pipefail

ZPT_BIN=$(realpath "$(dirname $0)/../zpt/target/debug/zpt")
INPUT=$(realpath "$(dirname $0)/../zpt/test-data/test-signal.zpt")


# Verify there are two EVAL+ALLOW objects for instruction=1
result=$("$ZPT_BIN" -i "$INPUT" --json | jq -s '[.[] | select(.kind=="EVAL" and .instruction==1 and .decision=="ALLOW")] | length == 2')

if [ "$result" = "false" ]; then
  echo "FAILED ON EVAL 1"
  exit 1
fi

# Verify there is one EVAL+NO_MATCH object for instruction=2
result=$("$ZPT_BIN" -i "$INPUT" --json | jq -s '[.[] | select(.kind=="EVAL" and .instruction==2 and .decision=="NO_MATCH")] | length == 1')

if [ "$result" = "false" ]; then
  echo "FAILED ON EVAL 2"
  exit 1
fi

# Verify that it picks up the signal clause for instruction 1, match 0
if "$ZPT_BIN" -i "$INPUT" --json | jq -e -s '
  any(.[];
    .kind=="EVAL"
    and .instruction==1
    and .hit.match_idx==0
    and (.hit.signal // {} | .message=="red employee" and .service=="signalService")
  )
'; then
  echo "found signal"
else
  echo "FAILED ON SIGNAL CHECK"
  exit 1
fi




echo "SUCCESS"
