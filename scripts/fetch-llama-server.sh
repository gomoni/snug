#!/bin/sh
# Fetch the llama.cpp release snug-setup is tested against and unpack it where
# snug-setup looks: ~/.cache/snug-setup/llama.cpp/b11541/llama-b11541/llama-server.
#
# snug-setup never downloads anything itself. This is the one place the pin
# lives: the release, its URL and the sha256 of the asset, taken from the file
# that was downloaded and hashed (GitHub's own digest for the asset agrees). A
# download whose hash differs is deleted and nothing is unpacked.
#
# An existing unpack is not trusted either: every run, before saying "already
# unpacked", it hashes the files in setup/internal/llm/llama-server.manifest
# (llama-server and the libraries it loads; the same file snug-setup embeds and
# checks before it runs the binary) and refuses on any difference.
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

manifest=$(dirname "$0")/../setup/internal/llm/llama-server.manifest

# verify DIR checks the files of the manifest under DIR, and that DIR holds no
# libggml-*.so backend the manifest does not name (ggml loads every one it finds
# next to the binary).
verify() {
	vdir=$1
	grep -qx "tag $tag" "$manifest" || {
		echo "fetch-llama-server: $manifest is for another release than $tag" >&2
		return 1
	}
	bad=0
	while read -r kind a b; do
		case $kind in
		sha256)
			[ -f "$vdir/$b" ] && [ ! -L "$vdir/$b" ] && [ "$(sha256sum "$vdir/$b" | cut -d' ' -f1)" = "$a" ] || {
				echo "fetch-llama-server: $vdir/$b is missing or is not the file of release $tag (sha256 $a)" >&2
				bad=1
			}
			;;
		link)
			[ -L "$vdir/$a" ] && [ "$(readlink "$vdir/$a")" = "$b" ] || {
				echo "fetch-llama-server: $vdir/$a is missing or is not a link to $b" >&2
				bad=1
			}
			;;
		esac
	done <"$manifest"
	for f in "$vdir"/libggml-*.so*; do
		[ -e "$f" ] || [ -L "$f" ] || continue
		grep -qE "^(sha256 [0-9a-f]+|link) ${f##*/}( |$)" "$manifest" || {
			echo "fetch-llama-server: $f is not part of release $tag" >&2
			bad=1
		}
	done
	[ "$bad" = 0 ] || {
		echo "fetch-llama-server: $vdir does not match release $tag; delete it (rm -rf ${vdir%/*}) and run this again" >&2
		return 1
	}
}

[ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || {
	echo "fetch-llama-server: the pinned asset $asset is Linux x86_64 only; install llama.cpp for this machine and put llama-server on PATH, or pass --llama-server PATH" >&2
	exit 1
}
cache=${SNUG_SETUP_CACHE:-$HOME/.cache/snug-setup}/llama.cpp
dest=$cache/$tag
if [ -e "$dest/llama-$tag/llama-server" ] || [ -L "$dest/llama-$tag/llama-server" ]; then
	verify "$dest/llama-$tag" || exit 1
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
verify "$work/x/llama-$tag" || {
	echo "fetch-llama-server: $asset does not hold the files of the manifest; nothing was installed" >&2
	exit 1
}
mv "$work/x" "$dest"
echo "installed $dest/llama-$tag/llama-server (sha256 $sha256 verified)"
