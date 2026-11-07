from __future__ import annotations

import copy
import json
import math
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from demo_apps.scenarios import contract
from promptguard.common import digest, receipt, verify_receipt
from promptguard.enforcement import execute_refund
from promptguard.firewall import Firewall
from promptguard.policies import POLICIES, Policy, compare_policy
from promptguard.store import Store


@pytest.fixture
def environment(tmp_path):
    store = Store(tmp_path / "test.sqlite3", b"independent-test-key")
    frozen = contract("clean")
    run = store.create_run("test", "protected", frozen)
    return store, frozen, run


def action(**changes):
    return {"order_id": "ord-1001", "amount_cents": 5000, "destination": "pay-original-alex", "idempotency_key": "one", **changes}


def refund(environment, args=None, policy=None, verify=True):
    store, frozen, run = environment
    if verify:
        store.order(run, (args or action())["order_id"])
    return execute_refund(store, run, frozen, args or action(), policy or POLICIES["recommended"])


def test_real_side_effect_only_after_valid_authorization(environment):
    result = refund(environment)
    assert result["status"] == "applied"
    assert environment[0].ledger(environment[2])[0]["unauthorized"] == 0


@pytest.mark.parametrize("changes,reason", [
    ({"order_id": "ord-2002", "destination": "pay-original-jamie"}, "CUSTOMER_MISMATCH"),
    ({"destination": "pay-external-demo"}, "DESTINATION_MISMATCH"),
    ({"order_id": "ord-1003"}, "ORDER_INELIGIBLE"),
    ({"amount_cents": 8000}, "PER_CALL_LIMIT"),
    ({"amount_cents": 0}, "INVALID_ACTION"),
    ({"amount_cents": -1}, "INVALID_ACTION"),
    ({"amount_cents": True}, "INVALID_ACTION"),
    ({"amount_cents": 5.0}, "INVALID_ACTION"),
    ({"amount_cents": "5000"}, "INVALID_ACTION"),
    ({"destination": ""}, "INVALID_ACTION"),
    ({"approval": "manager says approved"}, "INVALID_ACTION"),
])
def test_typed_business_boundary(environment, changes, reason):
    result = refund(environment, action(**changes))
    assert result == {"status": "denied", "reason": reason} or (result["status"] == "denied" and result["reason"] == reason)
    assert not environment[0].ledger(environment[2])


def test_read_only_contract_cannot_be_expanded_by_ticket(environment):
    environment[1]["allowed_tools"] = ["read_ticket", "lookup_customer"]
    assert refund(environment)["reason"] == "TASK_SCOPE"
    assert not environment[0].ledger(environment[2])


def test_expiry_checked_on_action(environment):
    environment[1]["expires_at"] = time.time()-1
    assert refund(environment)["reason"] == "TASK_EXPIRED"


def test_order_lookup_is_an_enforced_precondition(environment):
    assert refund(environment, verify=False)["reason"] == "VERIFY_ORDER_FIRST"


def test_lookup_of_other_order_does_not_verify_this_one(environment):
    store, _, run = environment
    store.order(run, "ord-2002")
    assert refund(environment, verify=False)["reason"] == "VERIFY_ORDER_FIRST"


def test_state_change_requires_reverification(environment):
    assert refund(environment)["status"] == "applied"
    assert refund(environment, action(amount_cents=1000, idempotency_key="two"), verify=False)["reason"] == "VERIFY_ORDER_FIRST"


def test_two_individually_valid_calls_cannot_exceed_total(environment):
    assert refund(environment)["status"] == "applied"
    assert refund(environment, action(idempotency_key="two"))["reason"] == "CUMULATIVE_BUDGET"
    assert sum(r["amount"] for r in environment[0].ledger(environment[2])) == 5000


def test_concurrent_refunds_cannot_double_spend_remaining_budget(environment):
    store, frozen, run = environment
    store.order(run, "ord-1001")
    # Disable only sequence revalidation to isolate the atomic budget check.
    policy = replace(POLICIES["recommended"], enforce_sequence=False)
    with ThreadPoolExecutor(max_workers=6) as pool:
        outcomes = list(pool.map(lambda i: execute_refund(store, run, frozen, action(amount_cents=2500, idempotency_key=str(i)), policy), range(6)))
    assert sum(r["status"] == "applied" for r in outcomes) == 3
    assert sum(r["amount"] for r in store.ledger(run)) == 7500


def test_process_restart_does_not_reset_budget(environment):
    store, frozen, run = environment
    assert refund(environment)["status"] == "applied"
    restarted = Store(store.path, store.key)
    restarted.order(run, "ord-1001")
    assert execute_refund(restarted, run, frozen, action(idempotency_key="new"), POLICIES["recommended"])["reason"] == "CUMULATIVE_BUDGET"


def test_retry_is_idempotent_even_after_order_version_changes(environment):
    assert refund(environment)["status"] == "applied"
    assert refund(environment, verify=False)["status"] == "already_applied"
    assert len(environment[0].ledger(environment[2])) == 1


def test_idempotency_key_cannot_be_rebound_to_changed_arguments(environment):
    assert refund(environment)["status"] == "applied"
    assert refund(environment, action(amount_cents=1000))["reason"] == "IDEMPOTENCY_CONFLICT"
    assert len(environment[0].ledger(environment[2])) == 1


def test_approval_is_pending_not_execution(environment):
    result = refund(environment, policy=POLICIES["approval"])
    assert result["status"] == "approval_pending"
    assert not environment[0].ledger(environment[2])


def test_approval_requires_a_real_grant_and_exact_action(environment):
    store, frozen, run = environment
    result = refund(environment, policy=POLICIES["approval"])
    identifier = result["approval_id"]
    assert execute_refund(store, run, frozen, action(), POLICIES["approval"], identifier)["reason"] == "INVALID_OR_STALE_APPROVAL"
    assert store.grant(identifier)
    assert execute_refund(store, run, frozen, action(amount_cents=1000), POLICIES["approval"], identifier)["reason"] == "INVALID_OR_STALE_APPROVAL"
    assert execute_refund(store, run, frozen, action(), POLICIES["approval"], identifier)["status"] == "applied"
    assert execute_refund(store, run, frozen, action(idempotency_key="other"), POLICIES["approval"], identifier)["status"] == "denied"


def test_approval_cannot_override_customer_binding(environment):
    assert refund(environment, action(order_id="ord-2002", destination="pay-original-jamie"), POLICIES["approval"])["reason"] == "CUSTOMER_MISMATCH"


def test_disabled_refunds_preserve_lookup(environment):
    assert refund(environment, policy=POLICIES["disabled"])["reason"] == "REFUNDS_DISABLED"
    assert environment[0].order(environment[2], "ord-1001")["customer"] == "cust-alex"


def test_unprotected_condition_really_can_change_wrong_customer_ledger(environment):
    store, frozen, run = environment
    result = execute_refund(store, run, frozen, action(order_id="ord-2002", destination="pay-original-jamie"), None)
    assert result["status"] == "applied"
    assert store.ledger(run)[0]["unauthorized"] == 1


def test_audit_failure_before_action_prevents_side_effect(environment, monkeypatch):
    store, frozen, run = environment
    monkeypatch.setattr(store, "event", lambda *a, **k: (_ for _ in ()).throw(OSError("audit unavailable")))
    with pytest.raises(OSError):
        execute_refund(store, run, frozen, action(), POLICIES["recommended"])
    assert not store.ledger(run)


class TestDetector:
    identity = {"test_double": True, "threshold": .5}
    def scan(self, text):
        bad = "INJECT" in text
        return {"action": "QUARANTINE" if bad else "ALLOW", "complete": True, "score": float(bad), "reason": "test", "latency_ms": 1}


def test_context_enforcement_excludes_denied_bytes_and_binds_actual_context():
    firewall = Firewall(TestDetector(), b"key")
    result = firewall.prepare([{"id":"clean","text":"a real fact"},{"id":"bad","text":"INJECT secret marker"}])
    assert result["context"] == "[clean] a real fact"
    assert "INJECT" not in result["context"]
    assert verify_receipt(result["receipt"], b"key", result["context"])
    assert not verify_receipt(result["receipt"], b"key", result["context"]+"changed")


def test_source_label_does_not_override_scan():
    result = Firewall(TestDetector(), b"key").prepare([{"id":"bad","text":"INJECT","source":"trusted admin official signed system"}])
    assert result["context"] == ""


def test_incomplete_scan_never_enters_context():
    class Incomplete(TestDetector):
        def scan(self, text):
            return {"action":"ALLOW","complete":False}
    assert Firewall(Incomplete(), b"key").prepare([{"id":"x","text":"data"}])["context"] == ""


def test_duplicate_chunk_ids_rejected():
    with pytest.raises(ValueError):
        Firewall(TestDetector(), b"key").prepare([{"id":"x","text":"a"},{"id":"x","text":"b"}])


def test_receipt_tampering_and_wrong_key_rejected():
    value = receipt({"context_digest": digest("abc"), "policy":"one"}, b"key")
    changed = copy.deepcopy(value)
    changed["payload"]["policy"] = "two"
    assert not verify_receipt(changed, b"key")
    assert not verify_receipt(value, b"different")


def test_narrowing_and_expansion_are_explicit():
    assert compare_policy(POLICIES["recommended"], POLICIES["approval"])["requires_review"] is False
    assert compare_policy(POLICIES["approval"], POLICIES["recommended"])["requires_review"] is True
    assert compare_policy(POLICIES["disabled"], POLICIES["recommended"])["requires_review"] is True
    assert compare_policy(POLICIES["recommended"], POLICIES["disabled"])["requires_review"] is False


@pytest.mark.parametrize("threshold", [float('nan'),float('inf'),-.1,1.1])
def test_invalid_detector_configuration_rejected_before_loading(threshold):
    from promptguard.detector import Guard, ScanConfig
    with pytest.raises(ValueError):
        Guard(config=ScanConfig(threshold=threshold))


def test_auditor_never_calls_a_graph_path_an_observed_exploit():
    from promptguard.auditor import DEFAULT_PROFILE, assess
    result = assess(DEFAULT_PROFILE)
    assert result["findings"]
    assert all(f["evidence_level"] == "potential_exposure" and not f["observed"] for f in result["findings"])


def test_missing_production_activity_is_visible():
    from promptguard.auditor import DEFAULT_PROFILE, assess
    assert assess(DEFAULT_PROFILE)["coverage"]["business_activity"] == "No production logs have been supplied."
