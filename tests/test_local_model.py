import json
import unittest
from unittest.mock import patch

from watchdog import analysis


class LocalModelTests(unittest.TestCase):
    def test_sends_a_structured_chat_request_only_to_the_local_service(self):
        context = {"risk": 55, "deviations": [{"metric": "tx", "observed": 700_000}]}
        with patch.object(analysis.http.client, "HTTPConnection") as factory:
            connection = factory.return_value
            response = connection.getresponse.return_value
            response.status = 200
            response.read.return_value = b'{"message":{"content":"{\\"summary\\": \\"Outbound activity exceeded the baseline.\\"}"}}'
            self.assertEqual("Outbound activity exceeded the baseline.", analysis.local_review("test:local", context))
            factory.assert_called_once_with("127.0.0.1", 11434, timeout=15)
            method, path, body, headers = connection.request.call_args.args
            self.assertEqual(("POST", "/api/chat", "application/json"), (method, path, headers["Content-Type"]))
            request = json.loads(body)
            self.assertEqual("test:local", request["model"])
            self.assertFalse(request["stream"])
            self.assertEqual(analysis.OLLAMA_SCHEMA, request["format"])
            self.assertEqual(context, json.loads(request["messages"][-1]["content"]))
            connection.close.assert_called_once()

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
