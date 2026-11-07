"""Developer-facing interception. Authorization is always online and fail closed."""
from __future__ import annotations

import asyncio
import base64
import contextlib
import contextvars
import functools
import inspect
import time
import uuid
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from promptguard.common import canonical


class PromptGuardError(RuntimeError):
    pass


class ServiceUnavailable(PromptGuardError):
    pass


class AuthorizationDenied(PromptGuardError):
    def __init__(self, response):
        self.response = response
        self.execution_id = response["execution_id"]
        super().__init__("PROMPTGUARD denied execution: " + "; ".join(response.get("reasons", [])))


class ApprovalRequired(AuthorizationDenied):
    pass


class ExecutionReportError(PromptGuardError):
    """The tool ran; reporting failed. Retrying the tool may duplicate its effect."""
    executed = True


class PromptGuard:
    def __init__(self, api_key, endpoint="http://127.0.0.1:8775", agent_id="support-agent", *, timeout=5.0,
                 session_id=None, client=None, policy_cache_seconds=0, policy_public_key=None):
        parsed = urlparse(endpoint)
        if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1", "testserver")):
            raise ValueError("Use HTTPS for remote services")
        if not 0 < timeout <= 30 or not 0 <= policy_cache_seconds <= 30:
            raise ValueError("Invalid timeout or cache lifetime")
        self.agent_id, self.endpoint, self.api_key = agent_id, endpoint.rstrip("/"), api_key
        self.timeout = timeout
        self.client = client or httpx.Client(timeout=timeout, trust_env=False)
        self._owns_client = client is None
        self._session = contextvars.ContextVar("pg_session_"+uuid.uuid4().hex, default=session_id or uuid.uuid4().hex)
        self._approval = contextvars.ContextVar("pg_approval_"+uuid.uuid4().hex, default=None)
        self.cache_seconds, self.public_key, self._cache = policy_cache_seconds, policy_public_key, None

    @contextlib.contextmanager
    def session(self, session_id=None, approval_id=None):
        token = self._session.set(session_id or uuid.uuid4().hex)
        approval = self._approval.set(approval_id)
        try:
            yield self._session.get()
        finally:
            self._session.reset(token); self._approval.reset(approval)

    def _request(self, method, path, body=None):
        try:
            response = self.client.request(method, self.endpoint + path, json=body,
                                           headers={"Authorization": "Bearer " + self.api_key}, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError, OSError) as exc:
            raise ServiceUnavailable("PROMPTGUARD did not return a valid response; execution stopped ("+type(exc).__name__+")") from None

    def _authorize(self, tool, arguments, session_id=None):
        canonical(arguments)
        execution_id = uuid.uuid4().hex
        response = self._request("POST", "/v1/authorize", {"execution_id": execution_id, "agent_id": self.agent_id,
            "session_id": session_id or self._session.get(), "tool_name": tool, "arguments": arguments, "approval_id": self._approval.get()})
        if not isinstance(response, dict) or response.get("execution_id") != execution_id or response.get("decision") not in ("ALLOW", "DENY", "REQUIRE_APPROVAL"):
            raise ServiceUnavailable("Malformed authorization response; execution stopped")
        if response.get("decision") == "REQUIRE_APPROVAL":
            raise ApprovalRequired(response)
        if response.get("decision") != "ALLOW":
            if "execution_id" not in response:
                raise ServiceUnavailable("Malformed authorization response; execution stopped")
            raise AuthorizationDenied(response)
        return response

    def _report(self, authorization, started, error=None):
        try:
            result = self._request("POST", "/v1/executions/"+authorization["execution_id"]+"/outcome",
                          {"execution_status": "failed" if error else "completed", "execution_latency_ms": (time.perf_counter()-started)*1000,
                           "error_type": type(error).__name__ if error else None})
            if not isinstance(result, dict) or result.get("recorded") is not True or result.get("execution_id") != authorization["execution_id"]:
                raise ServiceUnavailable("Invalid execution acknowledgement")
        except ServiceUnavailable:
            raise ExecutionReportError("Tool executed, but its outcome could not be recorded. Do not retry automatically; reconcile this session.") from None

    def protect(self, name=None, *, capability=None, capabilities=None, amount_field=None, currency_field=None):
        def decorate(function):
            signature = inspect.signature(function)
            hints = [capability] if isinstance(capability,str) else list(capability or capabilities or [])
            def verify_metadata():
                if not hints and amount_field is None and currency_field is None: return
                registered = self._request('GET','/v1/universal/metadata/'+(name or function.__name__))
                if not set(hints)<=set(registered.get('capabilities',[])) or (amount_field is not None and amount_field!=registered.get('amount_field')) or (currency_field is not None and currency_field!=registered.get('currency_field')):
                    raise ServiceUnavailable('Decorator metadata has not been confirmed by a policy administrator; execution stopped')
            def arguments(args, kwargs):
                bound = signature.bind(*args, **kwargs); bound.apply_defaults()
                return dict(bound.arguments)
            if inspect.iscoroutinefunction(function):
                @functools.wraps(function)
                async def async_wrapped(*args, **kwargs):
                    await asyncio.to_thread(verify_metadata)
                    auth = await asyncio.to_thread(self._authorize, name or function.__name__, arguments(args, kwargs))
                    started = time.perf_counter()
                    try:
                        result = await function(*args, **kwargs)
                    except BaseException as exc:
                        try:
                            await asyncio.shield(asyncio.to_thread(self._report, auth, started, exc))
                        except ExecutionReportError as report_error:
                            exc.add_note(str(report_error))
                        raise
                    await asyncio.to_thread(self._report, auth, started)
                    return result
                return async_wrapped
            @functools.wraps(function)
            def sync_wrapped(*args, **kwargs):
                verify_metadata()
                auth = self._authorize(name or function.__name__, arguments(args, kwargs))
                started = time.perf_counter()
                try:
                    result = function(*args, **kwargs)
                except BaseException as exc:
                    try:
                        self._report(auth, started, exc)
                    except ExecutionReportError as report_error:
                        exc.add_note(str(report_error))
                    raise
                self._report(auth, started)
                return result
            return sync_wrapped
        return decorate

    def inspect(self, text, direction="input"):
        result = self._request("POST", "/v1/inspect", {"text": text, "direction": direction, "session_id": self._session.get()})
        return result

    def policy(self):
        """Verified snapshots for diagnostics; NEVER used to authorize offline execution."""
        if not self.public_key:
            raise ValueError("Pin the control plane's policy_public_key before caching policies")
        if self._cache and time.time() < self._cache[0]:
            return self._cache[1]
        envelope = self._request("GET", "/v1/sdk/policy")
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(self.public_key)).verify(base64.b64decode(envelope["signature"]), canonical(envelope["payload"]).encode())
            payload = envelope["payload"]
            if payload["issued_at"] > time.time()+5 or not time.time() <= payload["expires_at"] <= payload["issued_at"]+30:
                raise ValueError("Invalid validity window")
        except Exception:
            raise ServiceUnavailable("Policy signature or validity verification failed") from None
        expiry = min(payload["expires_at"], time.time()+self.cache_seconds, time.time()+payload["policy"]["cache_ttl_seconds"])
        self._cache = (expiry, payload["policy"])
        return payload["policy"]

    def wrap(self, server, *, session_resolver=None):
        """Protect FastMCP call_tool requests through its documented middleware hook.

        Direct calls to underlying Python functions are outside this boundary.
        A trusted server callback may resolve business sessions; tool arguments cannot.
        """
        from fastmcp import FastMCP
        from fastmcp.server.middleware import Middleware
        from fastmcp.exceptions import ToolError
        if not isinstance(server, FastMCP):
            raise TypeError("Server-wide wrapping supports the installed FastMCP, not arbitrary MCP implementations")
        owner = self
        class GuardMiddleware(Middleware):
            async def on_call_tool(self, context, call_next):
                try:
                    if session_resolver:
                        session = session_resolver(context)
                        if inspect.isawaitable(session): session = await session
                    else:
                        session = context.fastmcp_context.session_id
                    if not session:
                        raise ServiceUnavailable("MCP session identity unavailable; supply a trusted session_resolver")
                    auth = await asyncio.to_thread(owner._authorize, context.message.name, context.message.arguments or {}, session)
                except PromptGuardError as exc:
                    raise ToolError(str(exc)) from None
                started = time.perf_counter()
                try:
                    result = await call_next(context)
                except BaseException as exc:
                    try: await asyncio.shield(asyncio.to_thread(owner._report, auth, started, exc))
                    except ExecutionReportError as report_error: exc.add_note(str(report_error))
                    raise
                try:
                    await asyncio.to_thread(owner._report, auth, started)
                except ExecutionReportError as exc:
                    raise ToolError(str(exc)) from None
                return result
        server.add_middleware(GuardMiddleware())
        return server

    def close(self):
        if self._owns_client:
            self.client.close()
