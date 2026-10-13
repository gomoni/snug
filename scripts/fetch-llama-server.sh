#!/bin/sh
# Fetch the llama.cpp release snug-setup is tested against and unpack it where
# snug-setup looks: ~/.cache/snug-setup/llama.cpp/b11541/llama-b11541/llama-server.
#
# snug-setup never downloads anything itself. This is the one place the pin
# lives: the release, its URL and the sha256 of the asset, taken from the file
# that was downloaded and hashed (GitHub's own digest for the asset agrees). A
# download whose hash differs is deleted and nothing is unpacked.
#
# Linux x86_64 only: it is the one asset pinned. Elsewhere install llama.cpp
# your own way; snug-setup finds llama-server on PATH first, or takes
# --llama-server PATH.
#
# Not a check (no NNNN-, no pass/fail of its own): it is the helper that
# scripts/0041 and the setup workflow's integration test rely on to have a
# llama-server. Set SNUG_SETUP_CACHE to unpack elsewhere than
# ~/.cache/snug-setup.
set -eu

tag=b11541
asset=llama-$tag-bin-ubuntu-x64.tar.gz
url=https://github.com/ggml-org/llama.cpp/releases/download/$tag/$asset
sha256=36ca310be4405acb7ba59b32dbdce32bb9cd7b1ef95358997b7eaed2c6f0188b

[ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || {
	echo "fetch-llama-server: the pinned asset $asset is Linux x86_64 only; install llama.cpp for this machine and put llama-server on PATH, or pass --llama-server PATH" >&2
	exit 1
}
cache=${SNUG_SETUP_CACHE:-$HOME/.cache/snug-setup}/llama.cpp
dest=$cache/$tag
if [ -x "$dest/llama-$tag/llama-server" ]; then
	echo "already unpacked: $dest/llama-$tag/llama-server"
	exit 0
fi

mkdir -p "$cache"
work=$(mktemp -d "$cache/.fetch.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM
echo "downloading $url"
curl -fsSL --proto '=https' --tlsv1.2 -o "$work/$asset" "$url"
got=$(sha256sum "$work/$asset" | cut -d' ' -f1)
[ "$got" = "$sha256" ] || {
	echo "fetch-llama-server: $asset has sha256 $got, not the pinned $sha256; nothing was unpacked" >&2
	exit 1
}
mkdir "$work/x"
tar -xzf "$work/$asset" -C "$work/x"
[ -x "$work/x/llama-$tag/llama-server" ] || {
	echo "fetch-llama-server: $asset has no llama-$tag/llama-server" >&2
	exit 1
}
mv "$work/x" "$dest"
echo "installed $dest/llama-$tag/llama-server (sha256 $sha256 verified)"
