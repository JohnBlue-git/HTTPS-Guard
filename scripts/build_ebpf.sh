#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT_DIR/build"
BPF_SRC="$ROOT_DIR/ebpf/https_guard.bpf.c"
BPF_OBJ="$OUT_DIR/https_guard.bpf.o"
ARCH_INCLUDE="/usr/include/$(uname -m)-linux-gnu"

mkdir -p "$OUT_DIR"

clang \
  -target bpf \
  -D__TARGET_ARCH_x86 \
  -O2 \
  -g \
  -I"$ARCH_INCLUDE" \
  -I"$ROOT_DIR/include" \
  -I/usr/include \
  -c "$BPF_SRC" \
  -o "$BPF_OBJ"

echo "Built $BPF_OBJ"
