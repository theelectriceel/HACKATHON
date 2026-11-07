"""Typed policy and a small, explicit permission comparison grammar."""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace


@dataclass(frozen=True)
class Policy:
    id: str = "recommended"
    bind_customer: bool = True
    original_destination: bool = True
    verify_eligibility: bool = True
    cumulative_limit_cents: int = 7500
    require_approval: bool = False
    refunds_enabled: bool = True
    enforce_sequence: bool = True
    per_call_limit_cents: int = 7500

    def __post_init__(self):
        if type(self.cumulative_limit_cents) is not int or type(self.per_call_limit_cents) is not int:
            raise ValueError("Currency limits must be integer cents")
        if min(self.cumulative_limit_cents, self.per_call_limit_cents) < 0:
            raise ValueError("Limits cannot be negative")

    def public(self):
        return asdict(self)


POLICIES = {
    "recommended": Policy(),
    "approval": Policy(id="approval", require_approval=True),
    "disabled": Policy(id="disabled", refunds_enabled=False),
    "per_call": Policy(id="per_call", cumulative_limit_cents=100_000, enforce_sequence=False),
}


def compare_policy(old: Policy, new: Policy) -> dict:
    """Exact structural inclusion for this conjunction-only policy grammar.

    Does not establish safety of business rules or compare arbitrary shell/regex policies.
    Approval changes are evaluated with approval absent; approval cannot override hard rules.
    """
    expansions = []
    if not old.refunds_enabled and new.refunds_enabled:
        expansions.append("refunds_enabled")
    if new.refunds_enabled:
        for field in ("bind_customer", "original_destination", "verify_eligibility", "require_approval", "enforce_sequence"):
            if getattr(old, field) and not getattr(new, field):
                expansions.append(field)
        for field in ("cumulative_limit_cents", "per_call_limit_cents"):
            if getattr(new, field) > getattr(old, field):
                expansions.append(field)
    return {"relationship": "expansion" if expansions else "narrowing_or_equivalent", "requires_review": bool(expansions), "expanded_fields": expansions,
            "method": "structural inclusion in the supported conjunction-only grammar", "scope": "Policies over the same authenticated task and ledger semantics; not a proof about model behavior."}
