#!/bin/sh
# Merged HF model -> GGUF (f16) -> quantized GGUF.
#
# Uses llama.cpp's own converter and quantizer at ONE pinned build, so the
# GGUF this produces and the llama-server that loads it agree on the format.
# No C++ toolchain is needed: the converter is Python, the quantizer is the
# prebuilt release binary.
#
#   ./export_gguf.sh out/qwen2.5-1.5b Q4_K_M
set -eu
out=${1:?usage: export_gguf.sh OUTDIR [QUANT]}
quant=${2:-Q4_K_M}
tag=${LLAMA_CPP_TAG:-b11541}
root=${LLAMA_CPP_ROOT:-$HOME/.cache/snug-setup/llama.cpp/$tag}
src=$root/src
bin=$root/llama-$tag

[ -f "$src/convert_hf_to_gguf.py" ] || {
	echo "export_gguf: no llama.cpp source at $src (gh api repos/ggml-org/llama.cpp/tarball/$tag | tar xz --strip-components=1 -C $src)" >&2
	exit 1
}
[ -x "$bin/llama-quantize" ] || {
	echo "export_gguf: no llama-quantize at $bin (gh release download -R ggml-org/llama.cpp $tag -p llama-$tag-bin-ubuntu-x64.tar.gz)" >&2
	exit 1
}

here=$(cd "$(dirname "$0")" && pwd)
f16=$out/snug-setup-f16.gguf
PYTHONPATH=$src/gguf-py nice -n 19 uv run --project "$here" python "$src/convert_hf_to_gguf.py" \
	"$out/merged" --outtype f16 --outfile "$f16"
q=$out/snug-setup-$(echo "$quant" | tr 'A-Z' 'a-z').gguf
LD_LIBRARY_PATH=$bin nice -n 19 "$bin/llama-quantize" "$f16" "$q" "$quant" "$(( $(nproc) > 2 ? $(nproc) - 2 : 1 ))"
ls -l "$f16" "$q"
