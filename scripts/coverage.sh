#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
exec cargo llvm-cov --workspace --fail-under-lines 95 -- --test-threads=1
