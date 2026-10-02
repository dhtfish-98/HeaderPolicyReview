import json
import plistlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from review import review_text


class RegressionTests(unittest.TestCase):

    def test_empty_csp_and_duplicate_hsts(self):
        headers=[{"name":"Content-Type","value":"text/html"},{"name":"Content-Security-Policy","value":""},{"name":"Strict-Transport-Security","value":"max-age=12"},{"name":"Strict-Transport-Security","value":"max-age=0"},{"name":"X-Content-Type-Options","value":"nosniff"}]
        har={"log":{"entries":[{"request":{"url":"https://owned.invalid/"},"response":{"headers":headers}}]}}
        self.assertEqual({x["rule"] for x in review_text(json.dumps(har))},{"csp-review","duplicate-security-header","hsts-review"})
    def test_html_mime_fallback_and_invalid_header(self):
        har={"log":{"entries":[{"request":{"url":"http://owned.invalid/"},"response":{"headers":[],"content":{"mimeType":"text/html"}}}]}}
        self.assertEqual({x["rule"] for x in review_text(json.dumps(har))},{"csp-review","nosniff-review"})
        har["log"]["entries"][0]["response"]["headers"]=[False]
        with self.assertRaises(ValueError): review_text(json.dumps(har))
