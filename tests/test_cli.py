import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from cli import main


class CLITests(unittest.TestCase):
    def test_version_without_input(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as exit_status:
            main(["--version"])
        self.assertEqual(exit_status.exception.code, 0)
        self.assertTrue(output.getvalue().strip().endswith(" 0.1.4"))

    def test_finding_json_and_invalid_path(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input"
            payload = '{"log": {"entries": [{"request": {"url": "https://owned.invalid/"}, "response": {"headers": [{"name": "Content-Type", "value": "text/html"}]}}]}}'
            path.write_bytes(payload if isinstance(payload, bytes) else payload.encode())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main([str(path), "--json"]), 1)
            self.assertTrue(json.loads(output.getvalue()))
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(path) + ".missing"]), 2)
