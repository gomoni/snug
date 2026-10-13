"""LoRA fine-tune of the intent model on CPU or an NVIDIA GPU, then merge.

Unsloth was the first choice and does not run here: past its import gate
(UNSLOTH_ALLOW_CPU=1) its RMSNorm, RoPE and cross-entropy are Triton kernels,
and Triton has no CPU driver ("0 active drivers ([]). There should only be
one."). Unsloth wraps exactly this stack — transformers + peft + TRL — so on a
GPU host the same data trains under Unsloth unchanged; on CPU this is the
stack without the kernels.

Loss is on the assistant reply only: prompt tokens are labelled -100. TRL's
SFTTrainer is not used — from 1.x it always installs a Triton fused LM-head
loss, which is the same missing CPU driver again.

    uv run python train.py --base Qwen/Qwen2.5-1.5B-Instruct --out out/qwen1.5b

On a GPU (--device cuda) the base loads in bf16 with gradient checkpointing,
which is what fits a 1.5B LoRA in 8 GB of VRAM; float32, the CPU path, is
6.2 GB of weights alone. The only GPU host tested against is Windows with
WSL2 (Ubuntu), where the Windows NVIDIA driver is all the GPU needs: no Linux
driver and no CUDA toolkit inside WSL, the torch wheel carries its runtime.
pyproject.toml pins torch to the CPU index, so the CUDA wheel replaces it
after the sync, and from then on the venv's python runs things: `uv run`
would sync the CPU wheel back.

    curl -LsSf https://astral.sh/uv/install.sh | sh     # WSL's Ubuntu has git and python3, not uv
    git clone -b feat/30-snug-setup https://github.com/gomoni/snug && cd snug/setup/model
    uv sync
    .venv/bin/python gen_dataset.py --n 3200 --seed 404 --single 0.47 --combo 0.27 --out data/train-v4.jsonl
    uv pip install --reinstall 'torch>=2.9' --index-url https://download.pytorch.org/whl/cu128
    .venv/bin/python -c 'import torch; print(torch.cuda.get_device_name())'
    .venv/bin/python train.py --device cuda --train data/train-v4.jsonl --epochs 1.5 --out out/qwen1.5b-v4

Copy out/qwen1.5b-v4/merged back and run export_gguf.sh there as on CPU.
"""

import argparse
import json
import os
import time
from pathlib import Path

import torch
from datasets import Dataset
from peft import LoraConfig, get_peft_model
from transformers import (AutoModelForCausalLM, AutoTokenizer, DataCollatorForSeq2Seq, Trainer, TrainerCallback,
                          TrainingArguments)

import prompt

HERE = Path(__file__).parent


def load(path, tok, max_len):
    rows = [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]
    data = []
    for r in rows:
        m = prompt.messages(r["context"], r["request"], r["actions"])
        head = tok.apply_chat_template(m[:2], tokenize=False, add_generation_prompt=True)
        full = tok.apply_chat_template(m, tokenize=False)
        assert full.startswith(head), "chat template does not extend the prompt"
        p = tok(head, add_special_tokens=False)["input_ids"]
        c = tok(full[len(head):], add_special_tokens=False)["input_ids"]
        ids = (p + c)[:max_len]
        labels = ([-100] * len(p) + c)[:max_len]
        data.append({"input_ids": ids, "attention_mask": [1] * len(ids), "labels": labels})
    return Dataset.from_list(data)


class Progress(TrainerCallback):
    def __init__(self):
        self.t0 = time.time()

    def on_log(self, args, state, control, logs=None, **kw):
        el = time.time() - self.t0
        eta = el / max(state.global_step, 1) * (state.max_steps - state.global_step)
        print(json.dumps({"step": state.global_step, "of": state.max_steps, "elapsed_min": round(el / 60, 1),
                          "eta_min": round(eta / 60, 1), **(logs or {})}), flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="Qwen/Qwen2.5-1.5B-Instruct")
    ap.add_argument("--train", default=str(HERE / "data" / "train.jsonl"))
    ap.add_argument("--out", default=str(HERE / "out" / "qwen2.5-1.5b"))
    ap.add_argument("--epochs", type=float, default=1.0)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--rank", type=int, default=16)
    ap.add_argument("--batch", type=int, default=4)
    ap.add_argument("--accum", type=int, default=2)
    ap.add_argument("--max-len", type=int, default=768)
    # Two CPUs stay free so the machine remains usable while a run takes hours,
    # and never more threads than the CPUs this process may run on: OpenMP
    # threads oversubscribed onto a taskset-narrowed mask spin against each other.
    ap.add_argument("--threads", type=int, default=max(1, min(len(os.sched_getaffinity(0)), os.cpu_count() - 2)))
    ap.add_argument("--limit", type=int, default=0, help="train on the first N rows only (smoke runs)")
    ap.add_argument("--device", choices=["cpu", "cuda"], default="cpu")
    a = ap.parse_args()
    gpu = a.device == "cuda"
    if gpu and not torch.cuda.is_available():
        raise SystemExit(f"--device cuda: torch {torch.__version__} sees no CUDA device. A +cpu build is the "
                         "pyproject default; install the CUDA wheel (see the top of train.py), and on WSL2 check "
                         "that nvidia-smi lists the GPU.")
    if gpu and not torch.cuda.is_bf16_supported():
        raise SystemExit(f"--device cuda: {torch.cuda.get_device_name()} has no bf16, which this run assumes.")

    os.nice(19)
    torch.set_num_threads(a.threads)
    torch.manual_seed(30)
    tok = AutoTokenizer.from_pretrained(a.base)
    model = AutoModelForCausalLM.from_pretrained(a.base, dtype=torch.bfloat16 if gpu else torch.float32)
    if gpu:
        # Checkpointing recomputes activations instead of keeping them; with a
        # frozen base, peft needs the embedding output to require grad or the
        # recomputed graph has nothing to backpropagate into.
        model.enable_input_require_grads()

    train = load(a.train, tok, a.max_len)
    if a.limit:
        train = train.select(range(min(a.limit, len(train))))

    peft_cfg = LoraConfig(r=a.rank, lora_alpha=2 * a.rank, lora_dropout=0.0, target_modules="all-linear",
                          task_type="CAUSAL_LM")
    model = get_peft_model(model, peft_cfg)
    model.print_trainable_parameters()

    cfg = TrainingArguments(
        output_dir=str(Path(a.out) / "ckpt"),
        num_train_epochs=a.epochs,
        per_device_train_batch_size=a.batch,
        gradient_accumulation_steps=a.accum,
        learning_rate=a.lr,
        lr_scheduler_type="cosine",
        warmup_steps=10,
        logging_steps=5,
        # Checkpoint often: a run is hours long on CPU and can be killed by memory
        # pressure from elsewhere on the machine; train.py resumes from the last one.
        save_steps=25,
        save_total_limit=2,
        # No mid-run eval: a batch of full-vocabulary logits is gigabytes, and the
        # score that matters is evaluate.py on the gold set afterwards.
        eval_strategy="no",
        train_sampling_strategy="group_by_length",
        use_cpu=not gpu,
        bf16=gpu,
        gradient_checkpointing=gpu,
        fp16=False,
        dataloader_num_workers=0,
        report_to=[],
        seed=30,
    )
    trainer = Trainer(model=model, args=cfg, train_dataset=train,
                      data_collator=DataCollatorForSeq2Seq(tok, padding=True, label_pad_token_id=-100),
                      callbacks=[Progress()])
    resume = any((Path(a.out) / "ckpt").glob("checkpoint-*")) if (Path(a.out) / "ckpt").exists() else False
    trainer.train(resume_from_checkpoint=resume or None)

    adapter = Path(a.out) / "adapter"
    trainer.model.save_pretrained(adapter)
    merged = trainer.model.merge_and_unload()
    merged.save_pretrained(Path(a.out) / "merged", safe_serialization=True)
    tok.save_pretrained(Path(a.out) / "merged")
    print("merged ->", Path(a.out) / "merged")


if __name__ == "__main__":
    main()
