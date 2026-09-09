"""Integration tests use a real Go gateway and real LangGraph, never an LLM."""
import json
import http.client
import os
from pathlib import Path
import sqlite3
import unittest
import urllib.error
import urllib.request
from uuid import uuid4

os.environ["LANGSMITH_TRACING"] = "false"
os.environ["LANGCHAIN_TRACING_V2"] = "false"

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command
from nomos_langgraph import tool_graph
from nomos_sdk import CustomTool
from demo import LocalGateway, deliver, find_binary


class InboxIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gateway = LocalGateway(find_binary(os.environ.get("NOMOS_TEST_BINARY")))

    @classmethod
    def tearDownClass(cls):
        cls.gateway.close()

    def setUp(self):
        self.calls = []
        self.params = {"message_id": uuid4().hex, "recipient": "reader@example.test", "body": "Hello"}
        self.tool = CustomTool(client=self.gateway.client, action_type="email.send",
                              resource=lambda p: "inbox://local/messages/" + p["message_id"],
                              execute=lambda p: self.calls.append(p) or deliver(self.gateway.directory / "inbox.db", p))

    def pending(self):
        request = self.tool.prepare(self.params)
        result = self.tool.run(request)
        self.assertTrue(result.requires_approval())
        self.assertFalse(self.calls)
        return request, result.decision_response["approval_id"]

    def test_allow_deny_and_audited_outcome(self):
        draft = CustomTool(client=self.gateway.client, action_type="email.draft",
                           resource=self.tool.resource, execute=lambda p: p)
        result = draft.invoke(self.params)
        self.assertTrue(result.executed)
        with sqlite3.connect(self.gateway.directory / "audit.db") as connection:
            count = connection.execute("SELECT COUNT(*) FROM audit_events WHERE event_type='action.external_reported' AND action_id=?",
                                       (result.decision_response["action_id"],)).fetchone()[0]
        self.assertEqual(count, 1)
        denied = self.tool.invoke({**self.params, "recipient": "blocked@example.net"})
        self.assertTrue(denied.is_denied())
        self.assertFalse(self.calls)

    def test_langgraph_pause_review_resume_and_delivery(self):
        graph = tool_graph(self.tool, checkpointer=InMemorySaver())
        config = {"configurable": {"thread_id": uuid4().hex}}
        result = graph.invoke({"params": self.params}, config)
        self.assertFalse(self.calls)
        approval_id = result["__interrupt__"][0].value["approval_id"]
        self.gateway.reviewer.decide_approval(approval_id, "APPROVE")
        result = graph.invoke(Command(resume=True), config)
        self.assertTrue(result["executed"])
        self.assertEqual(len(self.calls), 1)

    def test_resume_is_not_authorization(self):
        graph = tool_graph(self.tool, checkpointer=InMemorySaver())
        config = {"configurable": {"thread_id": uuid4().hex}}
        graph.invoke({"params": self.params}, config)
        result = graph.invoke(Command(resume=True), config)
        self.assertFalse(result["executed"])
        self.assertFalse(self.calls)

    def test_rejected_and_expired_approvals_cannot_execute(self):
        request, approval_id = self.pending()
        self.gateway.reviewer.decide_approval(approval_id, "DENY")
        self.assertFalse(self.tool.run(request, approval_id=approval_id).executed)
        request, approval_id = self.pending()
        self.gateway.reviewer.decide_approval(approval_id, "APPROVE")
        with sqlite3.connect(self.gateway.directory / "approvals.db") as connection:
            connection.execute("UPDATE approvals SET expires_at = ? WHERE approval_id = ?", ("2000-01-01T00:00:00Z", approval_id))
        self.assertFalse(self.tool.run(request, approval_id=approval_id).executed)
        self.assertFalse(self.calls)

    def test_changed_arguments_need_new_approval(self):
        request, approval_id = self.pending()
        self.gateway.reviewer.decide_approval(approval_id, "APPROVE")
        request.params["body"] = "Different message"
        self.assertFalse(self.tool.run(request, approval_id=approval_id).executed)
        self.assertFalse(self.calls)

    def test_agent_and_unauthenticated_callers_cannot_approve(self):
        _, approval_id = self.pending()
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.gateway.client.decide_approval(approval_id, "APPROVE")
        self.assertEqual(error.exception.code, 403)
        error.exception.close()
        for path, status in [("/approvals/decide", 401), ("/api/ui/approvals/decide", 401),
                             ("/webhooks/approvals", 404), ("/webhooks/slack/approvals", 404), ("/webhooks/teams/approvals", 404)]:
            with self.subTest(path=path):
                connection = http.client.HTTPConnection(self.gateway.url.removeprefix("http://"), timeout=5)
                try:
                    connection.request("POST", path,
                        body=json.dumps({"approval_id": approval_id, "decision": "APPROVE"}),
                        headers={"Content-Type": "application/json"})
                    response = connection.getresponse()
                    self.assertEqual(response.status, status)
                    response.read()
                finally:
                    connection.close()

    def test_local_provider_deduplicates_replayed_execution(self):
        request, approval_id = self.pending()
        self.gateway.reviewer.decide_approval(approval_id, "APPROVE")
        self.assertTrue(self.tool.run(request, approval_id=approval_id).executed)
        self.assertTrue(self.tool.run(request, approval_id=approval_id).executed)
        with sqlite3.connect(self.gateway.directory / "inbox.db") as connection:
            count = connection.execute("SELECT COUNT(*) FROM messages WHERE message_id=?", (self.params["message_id"],)).fetchone()[0]
        self.assertEqual(count, 1)
        with self.assertRaises(ValueError):
            deliver(self.gateway.directory / "inbox.db", {**self.params, "body": "different"})


if __name__ == "__main__":
    unittest.main()
