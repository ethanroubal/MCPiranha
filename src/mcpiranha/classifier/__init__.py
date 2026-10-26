"""Local prompt-injection classifier (`pip install 'mcpiranha[ml]'`, enabled with --classifier).

Scores every piece of text the model will read with a small fine-tuned transformer, run locally
through ONNX Runtime: no LLM, no network after the one-time model download. It catches reworded
injections that phrase rules miss.

Model: protectai/deberta-v3-base-prompt-injection-v2 (Apache-2.0), pinned to one revision. Its
files (about 750 MB) are downloaded on first use into ~/.cache/mcpiranha/models (or
$MCPIRANHA_MODEL_DIR) and checked against hashes recorded here, so a changed upload can't swap the
model underneath.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import tempfile
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO = "protectai/deberta-v3-base-prompt-injection-v2"
REVISION = "90c9989b1a342275dd0d1a95aad283c04e075671"
# file -> ("sha256" | "gitblob", hex digest). LFS files publish a SHA-256; small files are
# stored as git blobs, identified by the blob's SHA-1.
FILES: dict[str, tuple[str, str]] = {
    "onnx/model.onnx": (
        "sha256", "f0ea7f239f765aedbde7c9e163a7cb38a79c5b8853d3f76db5152172047b228c"
    ),
    "onnx/tokenizer.json": ("gitblob", "00c50710453478105265c838bfb3bad69b410891"),
    "onnx/config.json": ("gitblob", "3366690a064655366dd7dd57f9b3cf1e8ba8e78f"),
}  # fmt: skip
MAX_TOKENS = 512
WINDOW_CHARS = 1500  # comfortably under 512 tokens of English text
WINDOW_STEP = 1000

Progress = Callable[[str], None]


class ClassifierUnavailable(Exception):
    pass


def model_dir() -> Path:
    base = os.environ.get("MCPIRANHA_MODEL_DIR")
    root = Path(base) if base else Path.home() / ".cache" / "mcpiranha" / "models"
    return root / f"{REPO.replace('/', '--')}@{REVISION[:12]}"


def _digest(path: Path, kind: str) -> str:
    h = hashlib.sha256() if kind == "sha256" else hashlib.sha1()  # git's blob id
    if kind == "gitblob":
        h.update(f"blob {path.stat().st_size}\0".encode())
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_model(progress: Progress | None = None) -> Path:
    """Download and verify any missing model file; return the model directory."""
    directory = model_dir()
    for name, (kind, expected) in FILES.items():
        target = directory / name
        if target.is_file() and _digest(target, kind) == expected:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        url = f"https://huggingface.co/{REPO}/resolve/{REVISION}/{name}"
        if progress:
            progress(f"downloading {name} from huggingface.co/{REPO} (one time)")
        with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as tmp:
            try:
                with urllib.request.urlopen(url, timeout=60) as response:
                    while chunk := response.read(1 << 20):
                        tmp.write(chunk)
            except OSError as exc:
                Path(tmp.name).unlink(missing_ok=True)
                raise ClassifierUnavailable(f"could not download {name}: {exc}") from exc
        downloaded = Path(tmp.name)
        if _digest(downloaded, kind) != expected:
            downloaded.unlink()
            raise ClassifierUnavailable(f"{name} doesn't match the pinned hash; not using it")
        downloaded.replace(target)
    return directory


def windows(text: str) -> list[tuple[int, int]]:
    """Overlapping character windows covering `text`, each short enough for one model pass."""
    if len(text) <= WINDOW_CHARS:
        return [(0, len(text))]
    spans = [(i, min(i + WINDOW_CHARS, len(text))) for i in range(0, len(text), WINDOW_STEP)]
    return [s for s in spans if s[1] - s[0] > 50 or s == spans[0]]


@dataclass(frozen=True, slots=True)
class Score:
    probability: float  # of INJECTION, for the highest-scoring window
    start: int
    end: int


class InjectionClassifier:
    def __init__(self, directory: Path) -> None:
        try:  # untyped libraries, so loaded as Any
            np: Any = importlib.import_module("numpy")
            ort: Any = importlib.import_module("onnxruntime")
            tokenizers: Any = importlib.import_module("tokenizers")
        except ImportError as exc:
            raise ClassifierUnavailable(
                "the classifier needs the ml extra: pip install 'mcpiranha[ml]'"
            ) from exc
        self._np: Any = np
        config: dict[str, Any] = json.loads(
            (directory / "onnx" / "config.json").read_text(encoding="utf-8")
        )
        labels = {int(k): v for k, v in config["id2label"].items()}
        self._injection = next(i for i, label in labels.items() if label == "INJECTION")
        self._tokenizer: Any = tokenizers.Tokenizer.from_file(
            str(directory / "onnx" / "tokenizer.json")
        )
        self._tokenizer.enable_truncation(max_length=MAX_TOKENS)
        self._tokenizer.enable_padding()
        options: Any = ort.SessionOptions()
        options.log_severity_level = 3
        self._session: Any = ort.InferenceSession(str(directory / "onnx" / "model.onnx"), options,
                                             providers=["CPUExecutionProvider"])  # fmt: skip
        self._inputs: set[str] = {i.name for i in self._session.get_inputs()}
        self._cache: dict[str, float] = {}

    def _probabilities(self, texts: Sequence[str], batch: int = 16) -> list[float]:
        np = self._np
        todo = [t for t in dict.fromkeys(texts) if t not in self._cache]
        for start in range(0, len(todo), batch):
            chunk = todo[start : start + batch]
            encoded = self._tokenizer.encode_batch(list(chunk))
            feed = {
                "input_ids": np.array([e.ids for e in encoded], dtype=np.int64),
                "attention_mask": np.array([e.attention_mask for e in encoded], dtype=np.int64),
            }
            if "token_type_ids" in self._inputs:
                feed["token_type_ids"] = np.array([e.type_ids for e in encoded], dtype=np.int64)
            logits = self._session.run(None, {k: v for k, v in feed.items() if k in self._inputs})[
                0
            ]
            exp = np.exp(logits - logits.max(axis=1, keepdims=True))
            probs = exp / exp.sum(axis=1, keepdims=True)
            for text, p in zip(chunk, probs[:, self._injection], strict=True):
                self._cache[text] = float(p)
        return [self._cache[t] for t in texts]

    def score(self, texts: Sequence[str]) -> list[Score]:
        """The highest-scoring window of each text."""
        spans = [windows(t) for t in texts]
        flat = [t[s:e] for t, ws in zip(texts, spans, strict=True) for s, e in ws]
        probs = iter(self._probabilities(flat))
        scores: list[Score] = []
        for ws in spans:
            best = max(((next(probs), s, e) for s, e in ws), key=lambda x: x[0])
            scores.append(Score(*best))
        return scores


_loaded: InjectionClassifier | None = None


def load(progress: Progress | None = None) -> InjectionClassifier:
    """The process-wide classifier, downloading the model on first use."""
    global _loaded
    if _loaded is None:
        _loaded = InjectionClassifier(ensure_model(progress))
    return _loaded
