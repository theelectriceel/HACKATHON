# Third-party sources and attribution

PROMPTGUARD's application modules are original code created in this workspace. The project draws on published methods; the research map and design identify those sources and the limits of our claims.

Agent Guard's dispatch, approval and audit design informed this implementation. Its source was reviewed at the user-supplied local path. No Agent Guard implementation modules were copied or renamed into PROMPTGUARD. An existing example policy is retained as attributed assessment data in `data/imported/agent-guard-policy.example.yaml`, with the supplied Apache-2.0 license in `data/imported/AGENT_GUARD_LICENSE` and a source/hash manifest in `data/upstream_policy_manifest.json`.

Horizon Guard Small's model artifacts and tokenizer are downloaded from the pinned revision in `scripts/bootstrap_models.py`. The downloaded LICENSE, NOTICE, model card and integrity manifest are retained with those artifacts. Its model performance claims are not PROMPTGUARD measurements.

Public dataset revisions, attribution, transformations and rights caveats are retained in `data/manifest.json` and raw source cards. The deepset dataset card contains conflicting license metadata, which is disclosed rather than resolved by assumption. SEC structured records are identified by original URLs, hashes and JSON pointers. Two views of one fact are correlated, not independent sources.

Python libraries and the optional browser verification dependency retain their respective upstream licenses. `requirements.lock.txt` records the installed Python versions. No project-wide licensing decision for the original application is made by this notice.
