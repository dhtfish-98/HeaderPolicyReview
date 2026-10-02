import json
import unittest
from review import review_text


def har(url, headers):
    return json.dumps({"log": {"entries": [{"request": {"url": url}, "response": {"headers": [{"name": key, "value": value} for key, value in headers.items()]}}]}})


class HeaderTests(unittest.TestCase):
    def test_missing_https_html_headers(self):
        rules = {item["rule"] for item in review_text(har("https://owned.invalid/", {"Content-Type": "text/html"}))}
        self.assertEqual(rules, {"hsts-review", "csp-review", "nosniff-review"})

    def test_declared_headers_and_http_scope(self):
        good = {"Content-Type": "text/html", "Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": "default-src 'self'", "X-Content-Type-Options": "nosniff"}
        self.assertEqual(review_text(har("https://owned.invalid/", good)), [])
        self.assertEqual({x["rule"] for x in review_text(har("http://owned.invalid/", {"Content-Type": "application/json"}))}, set())
        self.assertEqual(review_text(har("https://owned.invalid/", {"Strict-Transport-Security": "max-age=012"})), [])

    def test_invalid_har(self):
        for value in ("{}", '{"log":null}', '{"log":{"entries":3}}', "invalid"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                review_text(value)
