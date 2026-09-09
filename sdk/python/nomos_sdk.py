from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import urllib.request
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Callable, Generic, TypeVar

InputT = TypeVar("InputT")
OutputT = TypeVar("OutputT")


def _generate_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


@dataclass
class ActionRequest:
    action_type: str
    resource: str
    params: dict[str, Any]
    action_id: str | None = None
    trace_id: str | None = None
    schema_version: str = "v1"
    context: dict[str, Any] = field(default_factory=lambda: {"extensions": {}})

    def as_dict(self) -> dict[str, Any]:
        # Keep correlation stable when the same request is retried after review.
        if not self.action_id:
            self.action_id = _generate_id("sdk_act")
        if not self.trace_id:
            self.trace_id = _generate_id("sdk_trace")
        return {
            "schema_version": self.schema_version,
            "action_id": self.action_id,
            "action_type": self.action_type,
            "resource": self.resource,
            "params": self.params,
            "trace_id": self.trace_id,
            "context": self.context or {"extensions": {}},
        }


@dataclass
class GuardResult(Generic[OutputT]):
    decision_response: dict[str, Any]
    executed: bool = False
    value: OutputT | None = None

    def is_allowed(self) -> bool:
        return self.decision_response.get("decision") == "ALLOW"

    def is_denied(self) -> bool:
        return self.decision_response.get("decision") == "DENY"

    def requires_approval(self) -> bool:
        return self.decision_response.get("decision") == "REQUIRE_APPROVAL"


class NomosClient:
    def __init__(self, *, base_url: str, bearer_token: str, agent_id: str, agent_secret: str, timeout: float = 5.0):
        if not base_url or not bearer_token or not agent_id or not agent_secret:
            raise ValueError("base_url, bearer_token, agent_id, and agent_secret are required")
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.agent_id = agent_id
        self.agent_secret = agent_secret
        self.timeout = timeout

    def run_action(self, request: ActionRequest) -> dict[str, Any]:
        return self._post("/action", request.as_dict())

    def decide_approval(self, approval_id: str, decision: str) -> dict[str, Any]:
        return self._post("/approvals/decide", {"approval_id": approval_id, "decision": decision})

    def explain_action(self, request: ActionRequest) -> dict[str, Any]:
        return self._post("/explain", request.as_dict())

    def report_external_outcome(self, payload: dict[str, Any]) -> dict[str, Any]:
        report = dict(payload)
        report.setdefault("schema_version", "v1")
        return self._post("/actions/report", report)

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload, allow_nan=False).encode("utf-8")
        signature = hmac.new(self.agent_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        req = urllib.request.Request(
            self.base_url + path,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.bearer_token}",
                "X-Nomos-Agent-Id": self.agent_id,
                "X-Nomos-Agent-Signature": signature,
                "Content-Type": "application/json",
                "X-Nomos-SDK-Contract": "v1",
            },
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            if not isinstance(result, dict):
                raise ValueError("Nomos returned a non-object response")
            return result


class GuardedCallable(Generic[InputT, OutputT]):
    def __init__(
        self,
        *,
        client: NomosClient,
        build_request: Callable[[InputT], ActionRequest],
        execute: Callable[[InputT], OutputT],
    ):
        self.client = client
        self.build_request = build_request
        self.execute = execute

    def invoke(self, value: InputT) -> GuardResult[OutputT]:
        value = deepcopy(value)
        request = self.build_request(value)
        _require_custom_action(request.action_type)
        decision = self.client.run_action(request)
        if decision.get("decision") != "ALLOW":
            return GuardResult(decision_response=decision)
        _require_external_authorization(decision)
        return GuardResult(
            decision_response=decision,
            executed=True,
            value=self.execute(value),
        )

    def invoke_and_report(
        self,
        value: InputT,
        report_builder: Callable[[InputT, OutputT, dict[str, Any]], dict[str, Any]] | None,
    ) -> GuardResult[OutputT]:
        result = self.invoke(value)
        if not result.executed or report_builder is None or result.value is None:
            return result
        self.client.report_external_outcome(report_builder(value, result.value, result.decision_response))
        return result


def guard_callable(
    *,
    client: NomosClient,
    build_request: Callable[[InputT], ActionRequest],
    execute: Callable[[InputT], OutputT],
) -> GuardedCallable[InputT, OutputT]:
    return GuardedCallable(client=client, build_request=build_request, execute=execute)


def guard_http_tool(
    *,
    client: NomosClient,
    resource_fn: Callable[[InputT], str],
    params_fn: Callable[[InputT], dict[str, Any]],
    execute_fn: Callable[[InputT], OutputT],
) -> GuardedCallable[InputT, OutputT]:
    return guard_callable(
        client=client,
        build_request=lambda value: ActionRequest(
            action_type="net.http_request",
            resource=resource_fn(value),
            params=params_fn(value),
        ),
        execute=execute_fn,
    )


def guard_subprocess_tool(
    *,
    client: NomosClient,
    resource_fn: Callable[[InputT], str],
    params_fn: Callable[[InputT], dict[str, Any]],
    execute_fn: Callable[[InputT], OutputT],
) -> GuardedCallable[InputT, OutputT]:
    return guard_callable(
        client=client,
        build_request=lambda value: ActionRequest(
            action_type="process.exec",
            resource=resource_fn(value),
            params=params_fn(value),
        ),
        execute=execute_fn,
    )


def guard_file_read_tool(
    *,
    client: NomosClient,
    resource_fn: Callable[[InputT], str],
    params_fn: Callable[[InputT], dict[str, Any]],
    execute_fn: Callable[[InputT], OutputT],
) -> GuardedCallable[InputT, OutputT]:
    return guard_callable(
        client=client,
        build_request=lambda value: ActionRequest(
            action_type="fs.read",
            resource=resource_fn(value),
            params=params_fn(value),
        ),
        execute=execute_fn,
    )


def guard_file_write_tool(
    *,
    client: NomosClient,
    resource_fn: Callable[[InputT], str],
    params_fn: Callable[[InputT], dict[str, Any]],
    execute_fn: Callable[[InputT], OutputT],
) -> GuardedCallable[InputT, OutputT]:
    return guard_callable(
        client=client,
        build_request=lambda value: ActionRequest(
            action_type="fs.write",
            resource=resource_fn(value),
            params=params_fn(value),
        ),
        execute=execute_fn,
    )


_BUILTIN_ACTIONS = {
    "fs.read", "fs.write", "repo.apply_patch", "process.exec",
    "net.http_request", "secrets.checkout",
}


def _require_custom_action(action_type: str) -> None:
    if action_type.strip() in _BUILTIN_ACTIONS:
        raise ValueError(
            "Built-in actions execute inside Nomos and cannot wrap a local callback. "
            "Use client.run_action for built-ins or a custom action such as email.send."
        )


def _require_external_authorization(decision: dict[str, Any]) -> None:
    if decision.get("execution_mode") != "external_authorized":
        raise ValueError("Missing external authorization; local tool was not executed")


class OutcomeReportError(RuntimeError):
    """The tool ran, but recording its outcome failed. Do not blindly rerun it."""

    def __init__(self, result: GuardResult[Any], report: dict[str, Any]):
        super().__init__("Tool completed, but outcome reporting failed; retry the report, not the tool")
        self.result = result
        self.report = report


class CustomTool:
    """Authorize a JSON tool input, run it in the trusted backend, report its outcome.

    This is not a sandbox or an exactly-once execution mechanism. Real providers
    must use stable business-operation idempotency keys and reconcile ambiguity.
    """

    def __init__(self, *, client: NomosClient, action_type: str,
                 resource: Callable[[dict[str, Any]], str],
                 execute: Callable[[dict[str, Any]], Any]):
        _require_custom_action(action_type)
        self.client = client
        self.action_type = action_type
        self.resource = resource
        self.execute = execute

    def prepare(self, params: dict[str, Any], *, action_id: str | None = None,
                trace_id: str | None = None) -> ActionRequest:
        if not isinstance(params, dict):
            raise ValueError("Custom tool params must be a JSON object")
        snapshot = json.loads(json.dumps(params, allow_nan=False))
        request = ActionRequest(self.action_type, self.resource(snapshot), snapshot,
                                action_id=action_id, trace_id=trace_id)
        request.as_dict()
        return request

    def invoke(self, params: dict[str, Any]) -> GuardResult[Any]:
        return self.run(self.prepare(params))

    def run(self, request: ActionRequest, *, approval_id: str | None = None) -> GuardResult[Any]:
        request = deepcopy(request)
        if request.action_type != self.action_type or request.resource != self.resource(deepcopy(request.params)):
            raise ValueError("Request does not belong to this custom tool")
        if approval_id is not None:
            request.context.setdefault("extensions", {})["approval"] = {"approval_id": approval_id}
        decision = self.client.run_action(request)
        result = GuardResult(decision_response=decision)
        if decision.get("decision") not in {"ALLOW", "DENY", "REQUIRE_APPROVAL"}:
            raise ValueError("Invalid Nomos decision; tool was not executed")
        if decision["decision"] != "ALLOW":
            return result
        _require_external_authorization(decision)
        report = {
            "action_id": decision["action_id"], "trace_id": decision["trace_id"],
            "action_type": request.action_type, "resource": request.resource,
            "approval_fingerprint": decision["approval_fingerprint"],
        }
        try:
            result.value = self.execute(deepcopy(request.params))
            result.executed = True
        except Exception:
            # An exception may follow a real side effect. Never retry automatically
            # or put exception text / sensitive tool output into the audit stream.
            try:
                self.client.report_external_outcome({**report, "outcome": "FAILED"})
            except Exception:
                pass  # Preserve the original execution error.
            raise
        report["outcome"] = "SUCCEEDED"
        try:
            recorded = self.client.report_external_outcome(report)
            if recorded.get("recorded") is not True:
                raise ValueError("Outcome was not recorded")
        except Exception as exc:
            raise OutcomeReportError(result, report) from exc
        return result
