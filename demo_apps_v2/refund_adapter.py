"""Authoritative cumulative-limit adapter reusing V1's tested SQLite ledger.

The remote service does not reserve or transfer money. This application executes
its balance, cumulative-budget and idempotency checks together with the ledger
write. Policy snapshots can race a concurrent publication; the task's frozen
budget still applies. This is deliberately not a distributed transaction claim.
"""
from promptguard.common import local_key
from promptguard.enforcement import execute_refund
from promptguard.policies import Policy as LedgerPolicy
from promptguard.store import Store as LedgerStore
from promptguard_v2.storage import V2
from demo_apps.scenarios import contract


class BusinessActionDenied(RuntimeError):
    pass


class RefundAdapter:
    def __init__(self, pg, path=None):
        self.pg = pg
        self.store = LedgerStore(path or V2 / "refund-ledger.sqlite3", local_key())
        self.contract = contract("clean")
        self.run_id = self.store.create_run("v2-cumulative-limit", "v2-sdk", self.contract)

    def issue_refund(self, customer_id: str, amount_cents: int, idempotency_key: str):
        if customer_id != self.contract["customer_id"]:
            raise BusinessActionDenied("CUSTOMER_MISMATCH")
        policy = self.pg.policy()  # Signed, pinned, online snapshot; caching disabled here.
        self.store.order(self.run_id, "ord-1001", verify=True)
        result = execute_refund(self.store, self.run_id, self.contract,
            {"order_id":"ord-1001", "amount_cents":amount_cents, "destination":"pay-original-alex", "idempotency_key":idempotency_key},
            LedgerPolicy(cumulative_limit_cents=policy["refund_cumulative_limit_cents"]))
        if result["status"] not in ("applied", "already_applied"):
            raise BusinessActionDenied(result["reason"])
        return result
