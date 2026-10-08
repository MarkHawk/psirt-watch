"""Unit tests for psirt_fetch.py.

All HTTP is mocked, no network access or credentials are required to run these.
"""
import datetime
import io
import os
import sys
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psirt_fetch  # noqa: E402


class FakeResponse:
    """Minimal stand-in for the context manager urllib.request.urlopen returns."""

    def __init__(self, body_bytes):
        self._body = body_bytes

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def make_http_error(code, body_bytes):
    return urllib.error.HTTPError(
        url="https://apix.cisco.com/security/advisories/v2/x",
        code=code,
        msg="error",
        hdrs=None,
        fp=io.BytesIO(body_bytes),
    )


class GetTokenTests(unittest.TestCase):
    def setUp(self):
        psirt_fetch._token["value"] = None
        psirt_fetch._token["expires_at"] = 0

    def test_requests_token_and_sends_client_credentials_grant(self):
        body = b'{"access_token": "tok-123", "expires_in": 3599}'
        with mock.patch("urllib.request.urlopen", return_value=FakeResponse(body)) as m:
            token = psirt_fetch.get_token("id", "secret")

        self.assertEqual(token, "tok-123")
        request = m.call_args[0][0]
        self.assertEqual(request.full_url, psirt_fetch.TOKEN_URL)
        self.assertEqual(request.get_method(), "POST")
        sent = request.data.decode()
        self.assertIn("grant_type=client_credentials", sent)
        self.assertIn("client_id=id", sent)

    def test_caches_token_until_near_expiry(self):
        body = b'{"access_token": "tok-123", "expires_in": 3599}'
        with mock.patch("urllib.request.urlopen", return_value=FakeResponse(body)) as m:
            first = psirt_fetch.get_token("id", "secret")
            second = psirt_fetch.get_token("id", "secret")

        self.assertEqual(first, second)
        self.assertEqual(m.call_count, 1)

    def test_refreshes_once_cached_token_is_near_expiry(self):
        body = b'{"access_token": "tok-123", "expires_in": 3599}'
        with mock.patch("urllib.request.urlopen", return_value=FakeResponse(body)) as m:
            psirt_fetch.get_token("id", "secret")
            psirt_fetch._token["expires_at"] = 0  # force expiry
            psirt_fetch.get_token("id", "secret")

        self.assertEqual(m.call_count, 2)


class ApiGet404Tests(unittest.TestCase):
    def test_no_data_found_returns_empty_advisory_list(self):
        error = make_http_error(404, b'{"message": "NO_DATA_FOUND"}')
        with mock.patch("urllib.request.urlopen", side_effect=error):
            result = psirt_fetch.api_get("/all/firstpublished?startDate=2026-01-01&endDate=2026-01-01", "tok")

        self.assertEqual(result, {"advisories": []})

    def test_other_404_bodies_are_reraised(self):
        error = make_http_error(404, b'{"message": "NOT_FOUND"}')
        with mock.patch("urllib.request.urlopen", side_effect=error):
            with self.assertRaises(urllib.error.HTTPError):
                psirt_fetch.api_get("/latest/10", "tok")

    def test_non_404_errors_are_reraised(self):
        error = make_http_error(500, b"server error")
        with mock.patch("urllib.request.urlopen", side_effect=error):
            with self.assertRaises(urllib.error.HTTPError):
                psirt_fetch.api_get("/latest/10", "tok")


class NormaliseTests(unittest.TestCase):
    def test_maps_camel_case_fields(self):
        raw = {
            "advisories": [
                {
                    "advisoryId": "SAMPLE-0001",
                    "advisoryTitle": "Example Title",
                    "sir": "Critical",
                    "cvssBaseScore": "9.8",
                    "cves": ["CVE-0000-00001", "NA"],
                    "productNames": ["Example Product"],
                    "firstPublished": "2026-01-02T00:00:00Z",
                    "lastUpdated": "2026-01-03T00:00:00Z",
                    "version": "1.0",
                    "publicationUrl": "https://example.invalid/SAMPLE-0001",
                }
            ]
        }
        out = psirt_fetch.normalise(raw)
        self.assertEqual(len(out), 1)
        entry = out[0]
        self.assertEqual(entry["id"], "SAMPLE-0001")
        self.assertEqual(entry["cves"], ["CVE-0000-00001"])  # "NA" filtered out
        self.assertEqual(entry["products"], ["Example Product"])
        self.assertEqual(entry["url"], "https://example.invalid/SAMPLE-0001")

    def test_falls_back_to_snake_case_fields(self):
        raw = {
            "advisories": [
                {
                    "advisory_id": "SAMPLE-0002",
                    "advisory_title": "Snake Case Title",
                    "cvss_base_score": "5.0",
                    "cves": "CVE-0000-00002",
                    "product_names": "Example Product",
                    "first_published": "2026-01-01T00:00:00Z",
                }
            ]
        }
        out = psirt_fetch.normalise(raw)
        self.assertEqual(out[0]["id"], "SAMPLE-0002")
        self.assertEqual(out[0]["cves"], ["CVE-0000-00002"])
        self.assertEqual(out[0]["products"], ["Example Product"])

    def test_defaults_sir_to_informational_and_handles_missing_fields(self):
        out = psirt_fetch.normalise({"advisories": [{}]})
        self.assertEqual(out[0]["sir"], "Informational")
        self.assertEqual(out[0]["cves"], [])
        self.assertEqual(out[0]["products"], [])
        self.assertEqual(out[0]["url"], "#")

    def test_sorts_newest_first(self):
        raw = {
            "advisories": [
                {"advisoryId": "OLD", "firstPublished": "2026-01-01T00:00:00Z"},
                {"advisoryId": "NEW", "firstPublished": "2026-06-01T00:00:00Z"},
            ]
        }
        out = psirt_fetch.normalise(raw)
        self.assertEqual([a["id"] for a in out], ["NEW", "OLD"])


class BuildPathRollingWindowTests(unittest.TestCase):
    def _args(self, **overrides):
        defaults = dict(mode="firstpublished", days=14, start=None, end=None,
                        severity="critical", latest=100)
        defaults.update(overrides)
        return mock.Mock(**defaults)

    def test_default_window_is_today_minus_days(self):
        fixed_today = datetime.date(2026, 7, 28)
        with mock.patch("psirt_fetch.date") as mock_date:
            mock_date.today.return_value = fixed_today
            path = psirt_fetch.build_path(self._args(days=14))

        self.assertIn("startDate=2026-07-14", path)
        self.assertIn("endDate=2026-07-28", path)

    def test_explicit_start_end_overrides_days(self):
        path = psirt_fetch.build_path(self._args(start="2026-01-01", end="2026-01-31"))
        self.assertIn("startDate=2026-01-01", path)
        self.assertIn("endDate=2026-01-31", path)

    def test_severity_mode_builds_severity_path(self):
        path = psirt_fetch.build_path(self._args(mode="severity", severity="high"))
        self.assertEqual(path, "/severity/high/firstpublished")

    def test_latest_mode_caps_page_size_at_100(self):
        path = psirt_fetch.build_path(self._args(mode="latest", latest=500))
        self.assertEqual(path, "/latest/100")

    def test_latest_mode_floors_page_size_at_1(self):
        path = psirt_fetch.build_path(self._args(mode="latest", latest=0))
        self.assertEqual(path, "/latest/1")


if __name__ == "__main__":
    unittest.main()
