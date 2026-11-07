"""Import an existing public policy as attributed assessment data, not our code."""
import json
from pathlib import Path

from promptguard.common import ROOT, digest, utcnow


def main():
    source = Path(r"C:\Users\abraa\Downloads\agent-guard\policy.example.yaml")
    if not source.exists():
        print("Optional local Agent Guard policy unavailable; no source invented.")
        return
    text = source.read_text(encoding="utf-8")
    target = ROOT / "data" / "imported"
    target.mkdir(exist_ok=True)
    (target / "agent-guard-policy.example.yaml").write_text(text, encoding="utf-8")
    license_path = source.parent / "LICENSE"
    if license_path.exists():
        (target / "AGENT_GUARD_LICENSE").write_bytes(license_path.read_bytes())
    manifest = {"name": "Existing Agent Guard example policy", "kind": "real_existing_open_source_configuration", "origin": str(source),
                "retrieved_at": utcnow(), "sha256": digest(text), "license": "Apache-2.0; preserved in data/imported/AGENT_GUARD_LICENSE", "attribution": "Agent Guard authors; original example configuration, not PROMPTGUARD source code.",
                "observations": {"explicit_default_allow": "default: allow" in text, "rule_count": text.count("  - id:"), "scope": "Example policy settings only; not evidence of a deployed system's permissions."}}
    (ROOT / "data" / "upstream_policy_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest["observations"]))


if __name__ == "__main__":
    main()
