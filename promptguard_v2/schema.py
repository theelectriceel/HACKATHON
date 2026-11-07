"""Strict, bounded policy language. No expression evaluation or inferred intent."""
from __future__ import annotations

import math
import re
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Effect = Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]
IDENTIFIER = r"^[a-zA-Z0-9_.:@-]{1,120}$"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class Condition(Strict):
    field: str = Field(pattern=r"^(args|resource|identity)\.[a-zA-Z0-9_]{1,80}$")
    op: Literal["eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in"]
    value: Any
    unit: Literal["cents", "count"] | None = None

    @model_validator(mode="after")
    def values(self):
        values = self.value if isinstance(self.value, list) else [self.value]
        if not values or len(values) > 100 or any(type(v) not in (str, int, float, bool) for v in values):
            raise ValueError("Use scalar values or a bounded scalar list")
        if any(type(v) is float and not math.isfinite(v) for v in values):
            raise ValueError("Finite values required")
        if self.op in ("in", "not_in") and not isinstance(self.value, list):
            raise ValueError("Membership requires a list")
        if self.op in ("gt", "gte", "lt", "lte") and (type(self.value) not in (int, float) or not self.unit):
            raise ValueError("Numeric comparisons require a number and explicit unit")
        if self.field.endswith("_cents") and (self.unit != "cents" or any(type(v) is not int for v in values)):
            raise ValueError("Currency fields require integer cents and unit=cents")
        if self.unit == "cents" and not self.field.endswith("_cents"):
            raise ValueError("Cents comparisons require an explicitly named _cents field")
        return self


class Pathway(Strict):
    after: list[str] = Field(min_length=1, max_length=8)
    basis: Literal["attempted", "completed"] = "completed"
    same_resource: bool = True

    @field_validator("after")
    @classmethod
    def identifiers(cls, value):
        if any(not re.fullmatch(IDENTIFIER, name) for name in value):
            raise ValueError("Invalid tool identifier")
        return value


class Rule(Strict):
    id: str = Field(pattern=IDENTIFIER)
    tool: str = Field(pattern=IDENTIFIER)
    effect: Effect
    enabled: bool = True
    conditions: list[Condition] = Field(default_factory=list, max_length=20)
    pathway: Pathway | None = None
    reason: str = Field(min_length=1, max_length=300)


class Policy(Strict):
    policy_id: str = Field(pattern=IDENTIFIER)
    version: int = Field(ge=1)
    default_effect: Literal["ALLOW", "DENY"] = "DENY"
    rules: list[Rule] = Field(max_length=100)
    cache_ttl_seconds: int = Field(default=0, ge=0, le=30)
    # Enforced only by the explicit authoritative-ledger adapter, not generic middleware.
    refund_cumulative_limit_cents: int = Field(default=7500, ge=0, le=1000000)

    @model_validator(mode="after")
    def unique_rules(self):
        if len({r.id for r in self.rules}) != len(self.rules):
            raise ValueError("Rule IDs must be unique")
        return self


class ToolSpec(Strict):
    name: str = Field(pattern=IDENTIFIER)
    arguments_schema: dict = Field(default_factory=lambda: {"type": "object"})
    sensitive: bool = True
    capabilities: list[str] = Field(default_factory=list,max_length=12)
    amount_field: str | None = None
    currency_field: str | None = None
    amount_unit: Literal["major","minor"] = "major"
    integration: Literal["unverified","sdk","mcp"] = "unverified"
    resource_arg: str | None = Field(default=None, pattern=IDENTIFIER)
    resource_type: str | None = Field(default=None, pattern=IDENTIFIER)
    identity_bindings: list[Literal["tenant_id", "customer_id"]] = Field(default_factory=list, max_length=2)
    scan_fields: list[str] = Field(default_factory=list, max_length=5)
    log_arguments: list[str] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def consistent(self):
        if bool(self.resource_arg) != bool(self.resource_type):
            raise ValueError("Resource argument and type are required together")
        if self.identity_bindings and not self.resource_arg:
            raise ValueError("Identity binding requires a registered resource")
        from jsonschema import Draft202012Validator
        Draft202012Validator.check_schema(self.arguments_schema)
        if self.arguments_schema.get("type") != "object":
            raise ValueError("Tool argument schema must describe an object")
        return self


class AgentRegistration(Strict):
    agent_id: str = Field(pattern=IDENTIFIER)
    principal_id: str = Field(pattern=IDENTIFIER)
    policy_id: str = Field(pattern=IDENTIFIER)
    tenant_id: str = Field(pattern=IDENTIFIER)
    customer_id: str | None = Field(default=None, pattern=IDENTIFIER)
    tools: list[ToolSpec] = Field(min_length=1, max_length=50)
    groups: list[str] = Field(default_factory=list,max_length=20)
    roles: list[str] = Field(default_factory=list,max_length=20)

    @model_validator(mode="after")
    def unique_tools(self):
        if len({t.name for t in self.tools}) != len(self.tools):
            raise ValueError("Tool names must be unique")
        return self


class Resource(Strict):
    resource_id: str = Field(pattern=IDENTIFIER)
    resource_type: str = Field(pattern=IDENTIFIER)
    tenant_id: str = Field(pattern=IDENTIFIER)
    customer_id: str | None = Field(default=None, pattern=IDENTIFIER)
    sensitivity: Literal["public", "internal", "confidential"] = "internal"
    environment: Literal["production","development","test"] | None = None


class Authorization(Strict):
    execution_id: str = Field(pattern=IDENTIFIER)
    agent_id: str = Field(pattern=IDENTIFIER)
    session_id: str = Field(pattern=IDENTIFIER)
    tool_name: str = Field(pattern=IDENTIFIER)
    arguments: dict[str, Any]
    approval_id: str | None = Field(default=None, pattern=IDENTIFIER)


class Outcome(Strict):
    execution_status: Literal["completed", "failed"]
    execution_latency_ms: float = Field(ge=0, le=86_400_000)
    error_type: str | None = Field(default=None, pattern=IDENTIFIER)


class Inspection(Strict):
    text: str = Field(min_length=1, max_length=100_000)
    session_id: str = Field(pattern=IDENTIFIER)
    direction: Literal["input", "output"] = "input"
