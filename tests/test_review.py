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

    def test_hsts_directives_are_checked_as_a_complete_field(self):
        valid = (
            "max-age=31536000",
            'Max-Age = "0010"; includeSubDomains',
            'future="a;b"; max-age=1',
            "max-age=1;;future=ok",
            'max-age=1; future="é"',
            'max-age=1; future="a\\\tb"',
            "max-age=1;\r\n includeSubDomains",
            "max-age=1;\r\n\tincludeSubDomains",
        )
        invalid = (
            "max-age=0",
            "max-age=000",
            "max-age=1; max-age=2",
            "max-age=1; includeSubDomains=1",
            "max-age=1; future=ok; FUTURE=again",
            "max-age=1; future=@",
            'max-age=1; future="unterminated',
            "max-age=١٢٣",
            "max-age=1\n",
            "max-age=1;\r\nincludeSubDomains",
            "\u00a0max-age=1",
            "max-age=1;K=ok",
            'max-age=1; future="💥"',
        )
        for value in valid:
            with self.subTest(valid=value):
                self.assertEqual(review_text(har("https://owned.invalid/", {"Strict-Transport-Security": value})), [])
        for value in invalid:
            with self.subTest(invalid=value):
                rules = {item["rule"] for item in review_text(har("https://owned.invalid/", {"Strict-Transport-Security": value}))}
                self.assertIn("hsts-review", rules)
