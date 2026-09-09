import unittest
from copy import deepcopy

from nomos_sdk import ActionRequest, CustomTool, OutcomeReportError, guard_http_tool


class FakeClient:
    def __init__(self):
        self.decision = {"decision": "ALLOW", "execution_mode": "external_authorized",
                         "action_id": "action-1", "trace_id": "trace-1", "approval_fingerprint": "fp-1"}
        self.requests = []
        self.reports = []
        self.report_error = False

    def run_action(self, request):
        self.requests.append(deepcopy(request))
        return deepcopy(self.decision)

    def report_external_outcome(self, report):
        self.reports.append(report)
        if self.report_error:
            raise OSError("unavailable")
        return {"recorded": True}


class CustomToolTests(unittest.TestCase):
    def setUp(self):
        self.client = FakeClient()
        self.calls = []
        self.tool = CustomTool(client=self.client, action_type="email.send",
                               resource=lambda p: "inbox://local/messages/" + p["id"],
                               execute=lambda p: self.calls.append(p))

    def test_success_reports_even_none_return_value(self):
        result = self.tool.invoke({"id": "1"})
        self.assertTrue(result.executed)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.client.reports[-1]["outcome"], "SUCCEEDED")

    def test_fail_closed_on_non_allow_and_missing_execution_mode(self):
        for decision in ["DENY", "REQUIRE_APPROVAL", "UNKNOWN"]:
            self.client.decision["decision"] = decision
            if decision == "UNKNOWN":
                with self.assertRaises(ValueError):
                    self.tool.invoke({"id": "1"})
            else:
                self.assertFalse(self.tool.invoke({"id": "1"}).executed)
        self.client.decision = {"decision": "ALLOW"}
        with self.assertRaises(ValueError):
            self.tool.invoke({"id": "1"})
        self.assertEqual(self.calls, [])

    def test_snapshot_and_correlation_stay_stable(self):
        empty_ids = ActionRequest("email.send", "inbox://local/messages/1", {}, action_id="", trace_id="")
        self.assertEqual(empty_ids.as_dict(), empty_ids.as_dict())
        params = {"id": "1", "body": "original"}
        request = self.tool.prepare(params)
        params["body"] = "changed"
        self.assertEqual(request.params["body"], "original")
        self.assertEqual(request.as_dict(), request.as_dict())
        self.tool.run(request, approval_id="reviewed")
        self.assertNotIn("approval", request.context["extensions"])
        self.assertEqual(self.client.requests[-1].context["extensions"]["approval"]["approval_id"], "reviewed")

    def test_wrong_tool_or_resource_never_calls_gateway(self):
        request = self.tool.prepare({"id": "1"})
        request.resource = "inbox://other/messages/1"
        with self.assertRaises(ValueError):
            self.tool.run(request)
        self.assertEqual(self.client.requests, [])

    def test_non_json_params_rejected(self):
        for params in [[], {"id": "1", "value": float("nan")}, {"id": "1", "value": object()}]:
            with self.assertRaises((ValueError, TypeError)):
                self.tool.prepare(params)

    def test_builtins_never_execute_locally_or_remotely(self):
        with self.assertRaises(ValueError):
            CustomTool(client=self.client, action_type="fs.write", resource=lambda p: "file://workspace/x", execute=self.calls.append)
        old = guard_http_tool(client=self.client, resource_fn=lambda p: "url://example.com/x",
                              params_fn=lambda p: {}, execute_fn=self.calls.append)
        with self.assertRaises(ValueError):
            old.invoke({})
        self.assertEqual(self.calls, [])
        self.assertEqual(self.client.requests, [])

    def test_tool_failure_reports_without_secret_exception_text(self):
        def fail(_):
            raise RuntimeError("secret-provider-response")
        self.tool.execute = fail
        with self.assertRaisesRegex(RuntimeError, "secret-provider-response"):
            self.tool.invoke({"id": "1"})
        self.assertEqual(self.client.reports[-1]["outcome"], "FAILED")
        self.assertNotIn("secret-provider-response", str(self.client.reports))

    def test_report_failure_preserves_result_and_does_not_retry_execution(self):
        self.client.report_error = True
        with self.assertRaises(OutcomeReportError) as error:
            self.tool.invoke({"id": "1"})
        self.assertTrue(error.exception.result.executed)
        self.assertEqual(error.exception.report["outcome"], "SUCCEEDED")
        self.assertEqual(len(self.calls), 1)

    def test_execution_error_survives_a_second_reporting_error(self):
        def fail(_):
            raise RuntimeError("provider failed after possible side effect")
        self.tool.execute = fail
        self.client.report_error = True
        with self.assertRaisesRegex(RuntimeError, "provider failed"):
            self.tool.invoke({"id": "1"})
        self.assertEqual(len(self.client.requests), 1)
        self.assertEqual(len(self.client.reports), 1)

    def test_transport_error_cannot_execute(self):
        def offline(_):
            raise OSError("gateway unavailable")
        self.client.run_action = offline
        with self.assertRaises(OSError):
            self.tool.invoke({"id": "1"})
        self.assertFalse(self.calls)
        self.assertFalse(self.client.reports)
