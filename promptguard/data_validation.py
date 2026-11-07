"""Verify the retained SEC bytes and exact numeric source pointers before use."""
from __future__ import annotations

import hashlib
import json
from decimal import Decimal

from .common import ROOT


def financial_records() -> list[dict]:
    facts=json.loads((ROOT/"data"/"financial_facts.json").read_text(encoding="utf-8"))
    sources=json.loads((ROOT/"data"/"sources.json").read_text(encoding="utf-8"))
    raw={}
    revisions={}
    for source in sources:
        path=(ROOT/source["raw_path"]).resolve()
        if not path.is_relative_to((ROOT/"data"/"raw").resolve()):
            raise ValueError("Source path escapes the retained data directory")
        body=path.read_bytes()
        sha=hashlib.sha256(body).hexdigest()
        if sha!=source["sha256"]:
            raise ValueError("Retained source integrity failed")
        raw[source["source_id"]]=json.loads(body)
        revisions[source["source_id"]]=sha
    for fact in facts:
        row=raw[fact["source_id"]]
        for part in fact["source_location"].strip("/").split("/"):
            row=row[int(part)] if isinstance(row,list) else row[part.replace("~1","/").replace("~0","~")]
        if (Decimal(str(row["val"]))!=Decimal(fact["value"]) or row["start"]!=fact["period_start"] or row["end"]!=fact["period_end"] or
            row["accn"]!=fact["accession"] or fact["unit"]!="USD" or fact["source_revision"]!=revisions[fact["source_id"]]):
            raise ValueError("Fact does not resolve to the retained source record")
    return facts
