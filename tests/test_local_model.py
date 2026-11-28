import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from watchdog import analysis, common


class LocalModelTests(unittest.TestCase):
    def test_sends_a_structured_chat_request_only_to_the_local_service(self):
        context = {
            "risk": 55,
            "deviations": [{"metric": "tx", "observed": 700_000}],
            "vulnerabilities": {
                "unresolved": 11317,
                "known_exploited": 5,
                "sources": {"kev": {"status": "ready", "freshness": "stale", "reference": "omitted"}},
                "priority_findings": [{"component": "omitted"}],
            },
            "sensor_health": {"Traffic": "ready", "SSH journal": "degraded"},
            "network_window": {"at": 9999},
        }
        with patch.object(analysis.http.client, "HTTPConnection") as factory:
            connection = factory.return_value
            response = connection.getresponse.return_value
            response.status = 200
            response.read.return_value = json.dumps({"message": {"content": '{"detail":"cisa_kev"}'}}).encode()
            self.assertEqual(
                "11317 unresolved vulnerability findings, including 5 known-exploited findings. "
                "Watchdog reported the CISA KEV feed status as stale.",
                analysis.local_review("test:local", context, prompt_mode="compact"),
            )
            factory.assert_called_once_with("127.0.0.1", 11434, timeout=15)
            method, path, body, headers = connection.request.call_args.args
            self.assertEqual(("POST", "/api/chat", "application/json"), (method, path, headers["Content-Type"]))
            request = json.loads(body)
            self.assertEqual("test:local", request["model"])
            self.assertFalse(request["stream"])
            self.assertEqual(32, request["options"]["num_predict"])
            self.assertEqual(
                ["risk", "deviations", "cisa_kev"], request["format"]["properties"]["detail"]["enum"],
            )
            findings, facts = request["messages"][-1]["content"].split("\n", 1)
            self.assertEqual("11317 unresolved vulnerability findings, including 5 known-exploited findings.", findings)
            self.assertEqual({
                "risk": "Watchdog recorded a risk score of 55.",
                "deviations": "The baseline deviation count was 1.",
                "cisa_kev": "Watchdog reported the CISA KEV feed status as stale.",
            }, json.loads(facts))
            connection.close.assert_called_once()

    def test_default_prompt_includes_full_assessment_evidence(self):
        context = {"vulnerabilities": {"priority_findings": [{"component": "kernel"}]}}
        with patch.object(analysis.http.client, "HTTPConnection") as factory:
            connection = factory.return_value
            response = connection.getresponse.return_value
            response.status = 200
            response.read.return_value = json.dumps({"message": {"content": '{"summary":"Kernel finding."}'}}).encode()
            analysis.local_review("test:local", context)
            request = json.loads(connection.request.call_args.args[2])
        self.assertEqual(context, json.loads(request["messages"][-1]["content"]))
        self.assertEqual(200, request["options"]["num_predict"])
        self.assertTrue(request["messages"][0]["content"].startswith("Summarize this host security assessment"))

    def test_configuration_defaults_to_full_and_validates_prompt_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"ollama_model": "test:local"}))
            self.assertEqual("full", common.configuration(path)["ollama_prompt_mode"])
            for mode in ("full", "compact"):
                with self.subTest(mode=mode):
                    path.write_text(json.dumps({"ollama_prompt_mode": mode}))
                    self.assertEqual(mode, common.configuration(path)["ollama_prompt_mode"])
            for invalid in ("typo", None, []):
                with self.subTest(invalid=invalid):
                    path.write_text(json.dumps({"ollama_prompt_mode": invalid}))
                    with self.assertRaisesRegex(ValueError, "ollama_prompt_mode"):
                        common.configuration(path)

    def test_distinguishes_missing_and_zero_vulnerability_counts(self):
        self.assertEqual(
            "Vulnerability findings are unavailable.",
            analysis.vulnerability_overview({"vulnerabilities": {"status": "not-checked"}}),
        )
        self.assertEqual(
            "0 unresolved vulnerability findings, including 0 known-exploited findings.",
            analysis.vulnerability_overview({"vulnerabilities": {"unresolved": 0, "known_exploited": 0}}),
        )

    def test_compact_rejects_unoffered_details_and_model_written_prose(self):
        for content in (
            {"detail": "failed_ssh"},
            {"detail": "risk", "summary": "No vulnerabilities."},
            {"detail": ["risk"]},
            {"summary": "No vulnerabilities."},
        ):
            with self.subTest(content=content), patch.object(analysis.http.client, "HTTPConnection") as factory:
                response = factory.return_value.getresponse.return_value
                response.status = 200
                response.read.return_value = json.dumps({"message": {"content": json.dumps(content)}}).encode()
                with self.assertRaisesRegex(ValueError, "Unexpected compact model output"):
                    analysis.local_review("test:local", {"risk": 55}, prompt_mode="compact")

    def test_rejects_remote_or_malformed_replies(self):
        options = (
            (503, {}),
            (200, {"remote_host": "elsewhere.test", "message": {"content": '{"summary":"valid"}'}}),
            (200, {"message": {"content": '{"summary":"valid","action":"isolate"}'}}),
            (200, {"message": {"content": '{"summary":42}'}}),
            (200, {"message": {"content": '{"summary":""}'}}),
        )
        for code, body in options:
            with self.subTest(code=code, body=body), patch.object(analysis.http.client, "HTTPConnection") as factory:
                connection = factory.return_value
                response = connection.getresponse.return_value
                response.status = code
                response.read.return_value = json.dumps(body).encode()
                with self.assertRaises(ValueError):
                    analysis.local_review("test:local", {})
                connection.close.assert_called_once()
