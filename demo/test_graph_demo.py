"""Real registered-DAG process, HTTP, storage, isolation and boundary tests."""

import copy
import http.client
import http.cookiejar
import json
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from graph_demo import Runtime, Server, exchange, handler, load_profiles


class GraphDemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="sova-graph-test-")
        cls.runtime = Runtime(Path(cls.directory.name))

    @classmethod
    def tearDownClass(cls):
        cls.runtime.close()
        assert all(p.poll() is not None for p in cls.runtime.processes.values())
        cls.directory.cleanup()

    def setUp(self):
        runtime = self.runtime
        if runtime.profile["id"] != "service-desk":
            runtime.select_application("service-desk")
        runtime.action("restore", runtime.ids)
        for node in runtime.ids:
            if exchange(runtime.ports[node], runtime.tokens[node])["fault"]:
                runtime.action("clear_fault", [node])

    def test_real_registered_branching_graph_is_not_a_fixed_chain(self):
        state = self.runtime.snapshot()
        self.assertEqual(len(state["nodes"]), 7)
        self.assertEqual(len(state["edges"]), 6)
        self.assertEqual(len([e for e in state["edges"] if e["source"] == "api"]), 3)
        self.assertEqual(len({s["pid"] for s in state["last_request"]["spans"]}), 7)
        self.assertTrue(state["last_request"]["ok"])
        self.assertFalse(state["last_request"]["degraded"])
        self.assertEqual(
            set(state["last_request"]["stores"]), {"database", "archive", "audit"}
        )

    def test_optional_dependency_failure_keeps_core_path_and_other_branch_running(self):
        state = self.runtime.action("fault", ["processor"])
        self.assertTrue(state["last_request"]["ok"])
        self.assertTrue(state["last_request"]["degraded"])
        nodes = {n["id"]: n for n in state["nodes"]}
        self.assertEqual(nodes["processor"]["state"], "failed")
        self.assertEqual(nodes["api"]["state"], "impacted")
        self.assertEqual(nodes["gateway"]["state"], "impacted")
        self.assertEqual(nodes["identity"]["state"], "healthy")
        self.assertEqual(nodes["database"]["state"], "healthy")
        self.assertTrue(nodes["audit"]["called"])
        self.assertFalse(nodes["archive"]["called"])
        self.assertEqual(set(state["last_request"]["stores"]), {"database", "audit"})

    def test_required_storage_failure_fails_request_and_skips_later_branches(self):
        state = self.runtime.action("fault", ["database"])
        self.assertFalse(state["last_request"]["ok"])
        self.assertEqual(state["last_request"]["failures"][0]["node"], "database")
        called = {s["node"] for s in state["last_request"]["spans"]}
        self.assertIn("identity", called)
        self.assertNotIn("processor", called)
        self.assertNotIn("audit", called)
        self.assertFalse(state["last_request"]["stored"])

    def test_selected_isolation_really_stops_only_owned_selected_processes(self):
        runtime = self.runtime
        original = dict(runtime.processes)
        state = runtime.action("isolate", ["processor", "archive"])
        self.assertEqual(state["isolated"], ["archive", "processor"])
        self.assertTrue(state["last_request"]["ok"])
        self.assertTrue(state["last_request"]["degraded"])
        for node in ["processor", "archive"]:
            self.assertIsNotNone(original[node].poll())
            with self.assertRaises((OSError, http.client.HTTPException)):
                exchange(runtime.ports[node], runtime.tokens[node])
        for node in ["gateway", "identity", "api", "database", "audit"]:
            self.assertIsNone(original[node].poll())
        restored = runtime.action("restore", ["archive", "processor"])
        self.assertTrue(restored["last_request"]["ok"])
        self.assertFalse(restored["last_request"]["degraded"])
        for node in ["processor", "archive"]:
            self.assertNotEqual(runtime.processes[node].pid, original[node].pid)
        self.assertIs(runtime.processes["database"], original["database"])

    def test_store_restart_preserves_data_during_demo(self):
        runtime = self.runtime
        before = exchange(runtime.ports["database"], runtime.tokens["database"])["rows"]
        runtime.action("isolate", ["database"])
        self.assertTrue(runtime.action("restore", ["database"])["last_request"]["ok"])
        self.assertGreater(
            exchange(runtime.ports["database"], runtime.tokens["database"])["rows"],
            before,
        )

    def test_application_selection_replaces_owned_graph_with_different_size(self):
        old = dict(self.runtime.processes)
        state = self.runtime.select_application("document-service")
        self.assertEqual(len(state["nodes"]), 4)
        self.assertEqual(len(state["edges"]), 3)
        self.assertTrue(all(p.poll() is not None for p in old.values()))
        self.assertEqual(
            {n["id"] for n in state["nodes"]},
            {"portal", "documents", "document-store", "analyzer"},
        )
        self.assertTrue(state["last_request"]["ok"])
        failed = self.runtime.action("fault", ["analyzer"])
        self.assertFalse(failed["last_request"]["ok"])
        # Storage already happened before the required analysis failure.
        self.assertIn("document-store", failed["last_request"]["stores"])

    def test_invalid_scope_and_unauthenticated_component_access_denied(self):
        runtime = self.runtime
        for action, nodes in [
            ("isolate", ["X"]),
            ("isolate", ["api", "api"]),
            ("isolate", []),
            ("fault", []),
            ("fault", ["api", "processor"]),
            ("probe", ["api"]),
            ("shell", []),
        ]:
            with self.assertRaises(ValueError):
                runtime.action(action, nodes)
        with self.assertRaises(ValueError):
            runtime.select_application("unregistered")
        result = exchange(
            runtime.ports["processor"], "bad-token", "/fault", {"enabled": True}
        )
        self.assertEqual(result, {"error": "not_found"})
        self.assertFalse(
            exchange(runtime.ports["processor"], runtime.tokens["processor"])["fault"]
        )

    def test_old_observations_become_unknown(self):
        for observation in self.runtime.observations.values():
            observation["at"] -= 7
        self.assertTrue(
            all(n["state"] == "unknown" for n in self.runtime.snapshot()["nodes"])
        )
        self.runtime.sample()

    def test_unexpected_process_exit_is_not_marked_as_operator_isolation(self):
        runtime = self.runtime
        runtime.processes["audit"].kill()
        runtime.processes["audit"].wait()
        runtime.sample()
        state = runtime.snapshot()
        node = next(n for n in state["nodes"] if n["id"] == "audit")
        self.assertEqual(node["state"], "failed")
        self.assertNotIn("audit", state["isolated"])
        self.assertTrue(state["last_request"]["ok"])
        self.assertTrue(state["last_request"]["degraded"])

    def test_http_session_origin_host_and_application_registration_guards(self):
        server = Server(("127.0.0.1", 0), type("Placeholder", (), {}))
        origin = f"http://127.0.0.1:{server.server_port}"
        server.RequestHandlerClass = handler(
            self.runtime,
            origin,
            "test-session",
            datetime.now(timezone.utc) + timedelta(minutes=1),
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        client = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )
        try:
            with self.assertRaises(urllib.error.HTTPError) as denied:
                urllib.request.urlopen(origin + "/api/state")
            self.assertEqual(denied.exception.code, 404)
            client.open(origin + "/").read()
            self.assertEqual(
                len(json.load(client.open(origin + "/api/state"))["nodes"]), 7
            )
            for endpoint, body, request_origin, status in [
                (
                    "/api/action",
                    {"action": "fault", "nodes": ["processor"]},
                    "https://foreign.example",
                    403,
                ),
                ("/api/application", {"application_id": "unregistered"}, origin, 400),
                ("/api/action", {"action": "isolate", "nodes": ["X"]}, origin, 400),
            ]:
                request = urllib.request.Request(
                    origin + endpoint,
                    data=json.dumps(body).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "Origin": request_origin,
                    },
                )
                with self.assertRaises(urllib.error.HTTPError) as denied:
                    client.open(request)
                self.assertEqual(denied.exception.code, status)
            request = urllib.request.Request(
                origin + "/api/application",
                data=json.dumps({"application_id": "document-service"}).encode(),
                headers={"Content-Type": "application/json", "Origin": origin},
            )
            self.assertEqual(len(json.load(client.open(request))["nodes"]), 4)
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
            connection.request("GET", "/", headers={"Host": "untrusted.example"})
            self.assertEqual(connection.getresponse().status, 403)
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


class ProfileValidationTests(unittest.TestCase):
    def check_invalid(self, modify):
        app = copy.deepcopy(load_profiles()["service-desk"])
        modify(app)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profiles.json"
            path.write_text(json.dumps({"version": 1, "applications": [app]}))
            with self.assertRaises(ValueError):
                load_profiles(path)

    def test_cycle_rejected(self):
        self.check_invalid(
            lambda app: app["nodes"][1]["dependencies"].append(
                {"target": "gateway", "required": True}
            )
        )

    def test_unknown_and_duplicate_dependencies_rejected(self):
        self.check_invalid(
            lambda app: app["nodes"][0]["dependencies"].append(
                {"target": "missing", "required": True}
            )
        )
        self.check_invalid(
            lambda app: app["nodes"][0]["dependencies"].append(
                {"target": "api", "required": True}
            )
        )

    def test_arbitrary_code_urls_and_invalid_paths_rejected(self):
        self.check_invalid(lambda app: app["nodes"][0].update(command="rm -rf /"))
        self.check_invalid(lambda app: app["nodes"][0].update(id="../outside"))
        self.check_invalid(
            lambda app: app["nodes"][0]["dependencies"][0].update(
                url="http://169.254.169.254/"
            )
        )

    def test_unreachable_node_rejected(self):
        self.check_invalid(
            lambda app: app["nodes"].append(
                {
                    "id": "hidden",
                    "name": "숨김",
                    "kind": "service",
                    "description": "unreachable",
                    "dependencies": [],
                }
            )
        )


if __name__ == "__main__":
    unittest.main()
