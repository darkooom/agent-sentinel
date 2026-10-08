#!/bin/sh
# Install agent-sentinel from GitHub Releases.
#
#   curl -fsSL https://raw.githubusercontent.com/darkooom/agent-sentinel/main/install.sh | sh
#
# Yes, sentinel's default policy blocks exactly this pattern for agents. Read
# this script first; it is short. It downloads a release archive, verifies it
# against the published SHA256SUMS, and copies one binary to
# $SENTINEL_INSTALL_DIR (default ~/.local/bin). It never uses sudo.
#
# Environment:
#   SENTINEL_VERSION      tag to install (default: latest release)
#   SENTINEL_INSTALL_DIR  destination directory (default: ~/.local/bin)

set -eu

repo="darkooom/agent-sentinel"
dir="${SENTINEL_INSTALL_DIR:-$HOME/.local/bin}"
version="${SENTINEL_VERSION:-latest}"

fail() { echo "install: $*" >&2; exit 1; }

case "$(uname -s)" in
  Linux) os="unknown-linux-gnu" ;;
  Darwin) os="apple-darwin" ;;
  *) fail "unsupported OS $(uname -s); build from source: cargo install --path crates/sentinel-cli" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch="x86_64" ;;
  arm64 | aarch64) arch="aarch64" ;;
  *) fail "unsupported architecture $(uname -m)" ;;
esac

asset="agent-sentinel-${arch}-${os}.tar.gz"
if [ "$version" = "latest" ]; then
  base="https://github.com/${repo}/releases/latest/download"
else
  base="https://github.com/${repo}/releases/download/${version}"
fi

command -v curl >/dev/null || fail "curl is required"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "downloading ${asset}"
curl -fsSL -o "$tmp/$asset" "$base/$asset" || fail "no release asset at $base/$asset (has a release been published?)"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" || fail "could not download SHA256SUMS"

expected="$(grep " ${asset}\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)"
[ -n "$expected" ] || fail "${asset} is not listed in SHA256SUMS"
if command -v sha256sum >/dev/null; then
  actual="$(sha256sum "$tmp/$asset" | cut -d' ' -f1)"
else
  actual="$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1)"
fi
[ "$expected" = "$actual" ] || fail "checksum mismatch for ${asset}"

tar -xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$dir"
cp "$tmp/agent-sentinel-${arch}-${os}/sentinel" "$dir/sentinel"
chmod 755 "$dir/sentinel"

echo "installed $("$dir/sentinel" --version) to $dir/sentinel"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "note: $dir is not on your PATH" ;;
esac
echo "next: cd your-project && sentinel init"
