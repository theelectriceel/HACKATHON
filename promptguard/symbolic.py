"""SMT comparison for the explicitly supported abstract refund-policy language."""
from __future__ import annotations

import z3

from .policies import Policy


def compare_symbolically(before: Policy, after: Policy) -> dict:
    context = z3.Context()
    amount, spent = z3.Ints("amount_cents spent_cents", ctx=context)
    owner, original, eligible, verified, approved = z3.Bools("customer_matches original_destination eligible verified_current_state approved", ctx=context)
    def allows(policy):
        return z3.And(z3.BoolVal(policy.refunds_enabled,ctx=context), amount <= policy.per_call_limit_cents, spent + amount <= policy.cumulative_limit_cents,
                      owner if policy.bind_customer else z3.BoolVal(True,ctx=context), original if policy.original_destination else z3.BoolVal(True,ctx=context),
                      eligible if policy.verify_eligibility else z3.BoolVal(True,ctx=context), verified if policy.enforce_sequence else z3.BoolVal(True,ctx=context),
                      approved if policy.require_approval else z3.BoolVal(True,ctx=context))
    solver = z3.Solver(ctx=context)
    solver.set(timeout=1500)
    solver.add(amount > 0, spent >= 0, allows(after), z3.Not(allows(before)))
    status = solver.check()
    witness = None
    if status == z3.sat:
        model = solver.model()
        witness = {str(v):str(model.eval(v,model_completion=True)) for v in (amount,spent,owner,original,eligible,verified,approved)}
    return {"method":"Z3 SMT permission inclusion", "solver_version":z3.get_version_string(), "relationship":"expansion" if status == z3.sat else "narrowing_or_equivalent" if status == z3.unsat else "unknown",
            "requires_review":status != z3.unsat, "expansion_witness":witness, "formula":solver.sexpr(),
            "scope":"All abstract states of the supported conjunction-only refund policy grammar. Shared identity, task and ledger validity constraints are held constant. Does not prove model behavior, arbitrary policy code, or remote service correctness."}
