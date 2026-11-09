"""Loopback-only checks: no authentication, database or cluster integration."""

import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from demo.response_scenarios.__main__ import assets, handler


class MockServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler(assets()))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_only_mock_assets_and_original_design_css_are_served(self):
        for path in (
            "/console/",
            "/__mock/response/model.mjs",
            "/__mock/response/motion.mjs",
            "/__mock/response/base.css",
        ):
            with urlopen(self.origin + path, timeout=2) as response:
                self.assertEqual(response.status, 200)
                self.assertIn("connect-src 'none'", response.headers["Content-Security-Policy"])
                self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_product_and_execution_routes_do_not_exist(self):
        for path in ("/v1/observed-workload", "/api/security", "/__trial/prepare", "/../.env"):
            with self.assertRaises(HTTPError) as raised:
                urlopen(self.origin + path, timeout=2)
            self.assertEqual(raised.exception.code, 404)
            raised.exception.close()

    def test_mutation_methods_are_rejected_even_on_static_assets(self):
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.assertRaises(HTTPError) as raised:
                urlopen(Request(self.origin + "/console/", data=b"{}", method=method), timeout=2)
            self.assertEqual(raised.exception.code, 405)
            raised.exception.close()


if __name__ == "__main__":
    unittest.main()
