"""A real, pinned, open-source guard with complete overlapping token coverage."""
from __future__ import annotations

import hashlib
import json
import math
import pathlib
import threading
import time
from dataclasses import asdict, dataclass

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

ROOT = pathlib.Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class ScanConfig:
    threshold: float = 0.5  # Publisher default; frozen before test scoring.
    window_tokens: int = 1024
    overlap_tokens: int = 128
    max_chars: int = 100_000
    max_windows: int = 64
    deadline_seconds: float = 20.0


class Guard:
    def __init__(self, model_dir: pathlib.Path | None = None, config: ScanConfig | None = None):
        started = time.perf_counter()
        self.config = config or ScanConfig()
        if not math.isfinite(self.config.threshold) or not 0 <= self.config.threshold <= 1:
            raise ValueError("Threshold must be finite and between zero and one")
        if self.config.max_chars < 1 or self.config.max_windows < 1 or not math.isfinite(self.config.deadline_seconds) or self.config.deadline_seconds <= 0:
            raise ValueError("Scanning limits must be positive and finite")
        if not 4 <= self.config.window_tokens <= 8192 or not 0 <= self.config.overlap_tokens < self.config.window_tokens - 2:
            raise ValueError("Invalid window configuration")
        self.model_dir = model_dir or ROOT / "models" / "guard"
        self.manifest = json.loads((self.model_dir / "manifest.json").read_text(encoding="utf-8"))
        # Integrity binds the measured runtime to the downloaded revision.
        for name in ["tokenizer.json", "config.json", "onnx/model_quantized.onnx"]:
            with (self.model_dir / name).open("rb") as handle:
                if hashlib.file_digest(handle, "sha256").hexdigest() != self.manifest["files"][name]["sha256"]:
                    raise ValueError(f"Model artifact integrity failed: {name}")
        labels = json.loads((self.model_dir / "config.json").read_text())["id2label"]
        if labels != {"0": "SAFE", "1": "INJECTION"}:
            raise ValueError("Unknown model label mapping")
        self.tokenizer = Tokenizer.from_file(str(self.model_dir / "tokenizer.json"))
        self.tokenizer.no_truncation()
        self.tokenizer.no_padding()
        self._lock = threading.Lock()
        options = ort.SessionOptions()
        options.intra_op_num_threads = 4
        options.inter_op_num_threads = 1
        options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        self.session = ort.InferenceSession(str(self.model_dir / "onnx" / "model_quantized.onnx"), options, providers=["CPUExecutionProvider"])
        self.inputs = {x.name for x in self.session.get_inputs()}
        self.cold_start_ms = (time.perf_counter() - started) * 1000

    @property
    def identity(self):
        return {"repo": self.manifest["repo"], "revision": self.manifest["revision"], "runtime": "onnxruntime CPU", "config": asdict(self.config), "cold_start_ms": round(self.cold_start_ms, 2)}

    def scan(self, text: str) -> dict:
        started = time.perf_counter()
        common = {"threshold": self.config.threshold, "model_revision": self.manifest["revision"], "windows": [], "complete": False}
        def finish(action, reason, score=None):
            return dict(common, action=action, reason=reason, score=score, latency_ms=round((time.perf_counter() - started) * 1000, 3))
        if not isinstance(text, str) or not text.strip():
            return finish("ERROR", "EMPTY_INPUT")
        if len(text) > self.config.max_chars:
            return finish("ERROR", "INPUT_LIMIT")
        try:
            with self._lock:
                encoded = self.tokenizer.encode(text, add_special_tokens=False)
            ids = encoded.ids
            size = self.config.window_tokens - 2
            step = size - self.config.overlap_tokens
            starts = list(range(0, max(1, len(ids) - self.config.overlap_tokens), step))
            if len(starts) > self.config.max_windows:
                return finish("ERROR", "WINDOW_LIMIT")
            common["token_count"] = len(ids)
            scores = []
            for start in starts:
                if time.perf_counter() - started > self.config.deadline_seconds:
                    return finish("ERROR", "SCAN_DEADLINE")
                end = min(start + size, len(ids))
                # Match the pinned tokenizer's <bos> text <eos> template exactly.
                window = np.asarray([[self.tokenizer.token_to_id("<bos>")] + ids[start:end] + [self.tokenizer.token_to_id("<eos>")]], dtype=np.int64)
                inputs = {"input_ids": window, "attention_mask": np.ones_like(window), "token_type_ids": np.zeros_like(window)}
                logits = self.session.run(None, {k: v for k, v in inputs.items() if k in self.inputs})[0]
                prob = np.exp(logits[0] - np.max(logits[0]))
                score = float(prob[1] / prob.sum())
                if not np.isfinite(score):
                    return finish("ERROR", "INVALID_MODEL_SCORE")
                scores.append(score)
                offsets = encoded.offsets[start:end]
                common["windows"].append({"token_start": start, "token_end": end, "char_start": offsets[0][0] if offsets else 0, "char_end": offsets[-1][1] if offsets else 0, "score": round(score, 7)})
            if time.perf_counter() - started > self.config.deadline_seconds:
                return finish("ERROR", "SCAN_DEADLINE")
            common["complete"] = True
            score = max(scores, default=0.0)
            return finish("QUARANTINE" if score >= self.config.threshold else "ALLOW", "MODEL_INJECTION" if score >= self.config.threshold else "MODEL_BELOW_THRESHOLD", round(score, 7))
        except Exception:
            # Never place raw exception text / source text into operational logs.
            return finish("ERROR", "MODEL_FAILURE")
