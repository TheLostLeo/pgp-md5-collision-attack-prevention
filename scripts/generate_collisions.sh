#!/bin/bash

# Get project root (where script is called from)
ROOT_DIR="$(pwd)"

BIN="$ROOT_DIR/hashclash/bin/md5_fastcoll"
OUTDIR="$ROOT_DIR/collisions"

mkdir -p "$OUTDIR"

echo "Generating 23 collision pairs..."

for i in {1..23}
do
  echo "Collision $i"
  "$BIN" -o "$OUTDIR/msg${i}_A.bin" "$OUTDIR/msg${i}_B.bin"
done

echo "Generating 2 NON-collision pairs..."

echo "normal file 24 A" > "$OUTDIR/msg24_A.bin"
echo "different file 24 B" > "$OUTDIR/msg24_B.bin"

echo "normal file 25 A" > "$OUTDIR/msg25_A.bin"
echo "different file 25 B" > "$OUTDIR/msg25_B.bin"

echo "Done."