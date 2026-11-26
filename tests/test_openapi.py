"""OpenAPI contract tests: the specs are valid, every route is documented, and real responses match."""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from jsonschema import Draft202012Validator
from openapi_spec_validator import validate

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(ROOT / "tests"))

from passkey_vault.approver_api import ApproverHandler  # noqa: E402
from passkey_vault.http_common import BaseHandler  # noqa: E402
from passkey_vault.requester_api import RequesterHandler  # noqa: E402
from test_server import ServerTestBase, raw_request  # noqa: E402

SPECS = {name: yaml.safe_load((ROOT / "docs/openapi" / f"{name}.yaml").read_text()) for name in ("requester", "approver")}


def spec_paths(spec: dict) -> list[tuple[str, str, re.Pattern[str]]]:
    out = []
    for path, ops in spec["paths"].items():
        pattern = re.compile("^" + re.sub(r"\{[^}]+\}", "[^/]+", path) + "$")
        out += [(method.upper(), path, pattern) for method in ops]
    return out


def response_schema(spec: dict, path: str, method: str, status: int) -> dict | None:
    resp = spec["paths"][path][method.lower()]["responses"].get(str(status))
    if resp is None:
        return None
    if "$ref" in resp:
        resp = spec["components"]["responses"][resp["$ref"].rsplit("/", 1)[1]]
    return resp["content"]["application/json"]["schema"]


class SpecTests(unittest.TestCase):
    def test_specs_are_valid_openapi(self) -> None:
        for name, spec in SPECS.items():
            with self.subTest(spec=name):
                validate(spec)

    def test_every_route_is_documented_and_vice_versa(self) -> None:
        for name, handler in (("requester", RequesterHandler), ("approver", ApproverHandler)):
            documented = {(m, p) for m, p, _ in spec_paths(SPECS[name])}
            served = set()
            for method, pattern, _ in handler.routes:
                if pattern.pattern.startswith("/(?!api/)"):
                    continue  # static files
                served.add((method, re.sub(r"\(\[\^/\]\+\)", "{}", pattern.pattern)))
            normalized = {(m, re.sub(r"\{[^}]+\}", "{}", p)) for m, p in documented}
            self.assertEqual(served, normalized, name)


class ResponsesMatchSpec(ServerTestBase):
    """Drive the real server through every operation and validate each JSON response against the spec."""

    def setUp(self) -> None:
        self.records: list[tuple[str, str, str, int, object]] = []
        original = BaseHandler.send_json

        def recording(handler, status, obj):
            door = "requester" if isinstance(handler, RequesterHandler) else "approver"
            self.records.append((door, handler.command, urlsplit(handler.path).path, status, obj))
            return original(handler, status, obj)

        BaseHandler.send_json = recording
        self.addCleanup(setattr, BaseHandler, "send_json", original)
        super().setUp()

    def test_all_responses_match(self) -> None:
        # Exercise every operation, including error paths.
        self.approver.state()
        self.init_vault()
        req = self.new_request()
        req.poll(0)
        self.approver.approve(req.id)
        req.poll(0)
        raw_request(self.requester_port, "GET", f"/requests/{req.id}")  # 410
        denied = self.new_request()
        self.approver.deny(denied.id)
        denied.poll(0)
        raw_request(self.requester_port, "POST", "/requests", b"{}", {"Content-Type": "text/plain"})  # 415
        raw_request(self.requester_port, "POST", "/requests", json.dumps({"secret": "nope", "command": "x", "pubkey": "AA"}).encode(),
                    {"Content-Type": "application/json"})
        self.approver.add_credential("second")
        self.approver.delete_credential(self.approver.creds[1], by=self.approver.creds[0])
        self.approver.delete_item("github")
        self.approver.call("POST", "/api/nonce", {"op": "nope"})
        self.approver.call("GET", "/api/requests/AAAAAAAAAAAAAAAAAAAAAA")

        checked = 0
        for door, method, path, status, body in self.records:
            spec = SPECS[door]
            match = next((p for m, p, rx in spec_paths(spec) if m == method and rx.match(path)), None)
            if match is None:
                continue  # e.g. 404 for unknown paths
            schema = response_schema(spec, match, method, status)
            self.assertIsNotNone(schema, f"{door} {method} {match} returned undocumented status {status}")
            validator = Draft202012Validator({"components": spec["components"], "allOf": [schema]})
            errors = [e.message for e in validator.iter_errors(body)]
            self.assertEqual(errors, [], f"{door} {method} {path} {status}: {body}")
            checked += 1
        self.assertGreater(checked, 20)


if __name__ == "__main__":
    unittest.main()
