"""Optional LangGraph integration. Approval decisions stay outside agent nodes."""

from typing import Any, TypedDict

from nomos_sdk import ActionRequest, CustomTool


class ToolState(TypedDict, total=False):
    params: dict[str, Any]
    request: dict[str, Any]
    decision: dict[str, Any]
    executed: bool
    value: Any


def tool_graph(tool: CustomTool, *, checkpointer: Any):
    """Build a checkpointed graph for one trusted custom tool.

    The caller reviews the interrupt and records a decision with a separately
    authorized reviewer. Command(resume=True) only resumes the graph: it does
    not grant approval. Final execution always rechecks Nomos authorization.
    Use durable checkpoints and provider idempotency outside the local demo.
    """
    from langgraph.graph import END, START, StateGraph
    from langgraph.types import interrupt

    if checkpointer is None:
        raise ValueError("A checkpointer is required for approval resume")

    def prepare(state: ToolState):
        return {"request": tool.prepare(state["params"]).as_dict(), "executed": False, "value": None}

    def authorize(state: ToolState):
        return {"decision": tool.client.run_action(ActionRequest(**state["request"]))}

    def route(state: ToolState):
        decision = state["decision"].get("decision")
        if decision == "REQUIRE_APPROVAL":
            return "review"
        return "execute" if decision == "ALLOW" else END

    def review(state: ToolState):
        interrupt({
            "approval_id": state["decision"]["approval_id"],
            "action_type": state["request"]["action_type"],
            "resource": state["request"]["resource"],
            "params": state["request"]["params"],
        })
        return {}

    def execute(state: ToolState):
        result = tool.run(ActionRequest(**state["request"]), approval_id=state["decision"].get("approval_id"))
        return {"decision": result.decision_response, "executed": result.executed, "value": result.value}

    graph = StateGraph(ToolState)
    graph.add_node("prepare", prepare)
    graph.add_node("authorize", authorize)
    graph.add_node("review", review)
    graph.add_node("execute", execute)
    graph.add_edge(START, "prepare")
    graph.add_edge("prepare", "authorize")
    graph.add_conditional_edges("authorize", route)
    graph.add_edge("review", "execute")
    graph.add_edge("execute", END)
    return graph.compile(checkpointer=checkpointer)
