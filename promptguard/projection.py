"""Bounded data preservation for quarantined support tickets.

Extracts an unambiguous order/amount candidate, never authorization. Every candidate
still passes the frozen contract, verified order lookup and executor checks.
No surrounding source prose is promoted into model instructions.
"""
from decimal import Decimal
import re

from .common import digest


def project_refund_request(text: str) -> dict | None:
    orders = list(re.finditer(r"\bord-\d{4}\b", text))
    amounts = list(re.finditer(r"(?<![-\w])\$(\d{1,5}(?:\.\d{1,2})?)(?![\d.])", text))
    if len({m.group() for m in orders}) != 1 or len(amounts) != 1:
        return None
    cents = int(Decimal(amounts[0].group(1))*100)
    if not 0 < cents <= 1_000_000:
        return None
    return {"order_id": orders[0].group(), "requested_amount_cents": cents, "currency": "USD",
            "source_digest": digest(text), "source_spans": [{"start":orders[0].start(),"end":orders[0].end()},{"start":amounts[0].start(),"end":amounts[0].end()}],
            "authority": "Untrusted request candidate only. Verify ownership, eligibility, original payment and task authority independently."}
