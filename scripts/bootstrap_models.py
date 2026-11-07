"""Download only data artifacts; never execute code from a model repository."""
import hashlib
import json
import pathlib
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO = "Horizon-Labs/prompt-injection-guard-small"
REVISION = "359521fbaf8a9fe551a87f562669a08b1a26773b"
FILES = ["config.json", "tokenizer.json", "tokenizer_config.json", "special_tokens_map.json",
         "onnx/model_quantized.onnx", "README.md", "LICENSE", "NOTICE", "SHA256SUMS"]


def main():
    destination = ROOT / "models" / "guard"
    manifest = {"repo": REPO, "revision": REVISION, "format": "ONNX publisher quantized", "files": {}}
    for name in FILES:
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            url = f"https://huggingface.co/{REPO}/resolve/{REVISION}/{name}"
            print(f"Downloading {name}", flush=True)
            with urllib.request.urlopen(url, timeout=120) as response, path.with_suffix(path.suffix + ".part").open("wb") as target:
                while block := response.read(1024 * 1024):
                    target.write(block)
            path.with_suffix(path.suffix + ".part").replace(path)
        manifest["files"][name] = {"sha256": hashlib.file_digest(path.open("rb"), "sha256").hexdigest(), "bytes": path.stat().st_size}
    destination.joinpath("manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (ROOT / "artifacts").mkdir(exist_ok=True)
    (ROOT / "artifacts" / "model_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"model": REPO, "revision": REVISION, "total_bytes": sum(f["bytes"] for f in manifest["files"].values())}))


if __name__ == "__main__":
    main()
