#!/bin/sh
# Builds the native library for the host platform and copies it to where the Maven build
# bundles it (src/main/resources/<os>-<arch>/). Extra arguments are passed to cargo.
set -eu
cd "$(dirname "$0")"
cargo build --release "$@"

case "$(uname -s)" in
  Linux) os=linux; lib=libcurve25519.so ;;
  Darwin) os=darwin; lib=libcurve25519.dylib ;;
  MINGW* | MSYS* | CYGWIN*) os=win32; lib=curve25519.dll ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86-64 ;;
  aarch64 | arm64) arch=aarch64 ;;
  i?86) arch=x86 ;;
  *) echo "unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac

dest=../src/main/resources/$os-$arch
mkdir -p "$dest"
cp "target/release/$lib" "$dest/"
echo "installed $dest/$lib"
