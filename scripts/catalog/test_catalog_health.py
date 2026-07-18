#!/usr/bin/env python3
"""Unit tests for the catalog evidence health probe."""

from __future__ import annotations

import importlib.util
import pathlib
import unittest
import urllib.error
from unittest import mock

SCRIPT = pathlib.Path(__file__).with_name("catalog_health.py")
SPEC = importlib.util.spec_from_file_location("catalog_health", SCRIPT)
assert SPEC and SPEC.loader
catalog_health = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(catalog_health)


class Response:
    def __init__(self, status: int = 200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, _kind, _value, _traceback):
        return False


class CatalogHealthProbeTests(unittest.TestCase):
    def test_urls_are_interleaved_across_hosts(self):
        urls = {
            "https://a.example/1",
            "https://a.example/2",
            "https://a.example/3",
            "https://b.example/1",
            "https://c.example/1",
        }
        self.assertEqual(
            catalog_health.interleave_by_hostname(urls),
            [
                "https://a.example/1",
                "https://b.example/1",
                "https://c.example/1",
                "https://a.example/2",
                "https://a.example/3",
            ],
        )

    def test_head_success_needs_no_get(self):
        with mock.patch.object(catalog_health.urllib.request, "urlopen", return_value=Response()) as urlopen:
            self.assertEqual(
                catalog_health.check_link("https://example.com/package", 1),
                ("https://example.com/package", None, None),
            )
        self.assertEqual(urlopen.call_count, 1)
        self.assertEqual(urlopen.call_args.args[0].get_method(), "HEAD")

    def test_get_recovers_from_rejected_head(self):
        def open_request(request, timeout):
            self.assertEqual(timeout, 1)
            if request.get_method() == "HEAD":
                raise urllib.error.HTTPError(request.full_url, 405, "rejected", None, None)
            return Response()

        with mock.patch.object(catalog_health.urllib.request, "urlopen", side_effect=open_request):
            self.assertEqual(
                catalog_health.check_link("https://example.com/package", 1),
                ("https://example.com/package", None, None),
            )

    def test_not_found_is_actionable(self):
        def not_found(request, timeout):
            raise urllib.error.HTTPError(request.full_url, 404, "missing", None, None)

        with mock.patch.object(catalog_health.urllib.request, "urlopen", side_effect=not_found):
            url, kind, detail = catalog_health.check_link("https://example.com/missing", 1)
        self.assertEqual(url, "https://example.com/missing")
        self.assertEqual(kind, "evidence_unreachable")
        self.assertEqual(detail, "HTTP 404")

    def test_rate_limit_is_inconclusive_not_broken_evidence(self):
        def rate_limited(request, timeout):
            raise urllib.error.HTTPError(request.full_url, 429, "limited", None, None)

        with mock.patch.object(catalog_health.urllib.request, "urlopen", side_effect=rate_limited):
            url, kind, detail = catalog_health.check_link("https://example.com/package", 1)
        self.assertEqual(url, "https://example.com/package")
        self.assertEqual(kind, "evidence_probe_inconclusive")
        self.assertEqual(detail, "HTTP 429")


if __name__ == "__main__":
    unittest.main()
