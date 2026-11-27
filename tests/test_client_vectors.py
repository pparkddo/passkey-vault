"""The client package against test-vectors/, with nothing from the server package.

Runs on the oldest supported Python as well (see .github/workflows/ci.yml).
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_der_private_key

from passkey_vault_client import Client
from passkey_vault_client.client import ApprovalRequest
from passkey_vault_client.protocol import b64url_decode, b64url_encode, oaep_label

VECTORS = Path(__file__).resolve().parents[1] / "test-vectors"


def load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


class ClientVectorTests(unittest.TestCase):
    def test_label(self) -> None:
        for c in load("label.json")["cases"]:
            self.assertEqual(oaep_label(c["id"], c["command"], b64url_decode(c["pubkey"])).hex(), c["label_hex"])

    def test_decrypt_with_the_sdk(self) -> None:
        for c in load("rsa-oaep.json")["cases"]:
            key = load_der_private_key(b64url_decode(c["private_key_pkcs8"]), None)
            req = ApprovalRequest(Client(), c["id"], "", "", "x", c["command"], b64url_decode(c["pubkey"]), key)
            self.assertEqual(req.decrypt(b64url_decode(c["ciphertext"])).decode(), c["plaintext"])
            with self.assertRaises(Exception):
                req.decrypt(b64url_decode(c["ciphertext"]))  # the one-time key is gone

    def test_wrong_command_cannot_decrypt(self) -> None:
        c = load("rsa-oaep.json")["cases"][0]
        key = load_der_private_key(b64url_decode(c["private_key_pkcs8"]), None)
        req = ApprovalRequest(Client(), c["id"], "", "", "x", c["must_fail_with_command"], b64url_decode(c["pubkey"]), key)
        with self.assertRaises(ValueError):
            req.decrypt(b64url_decode(c["ciphertext"]))

    def test_b64url_round_trip(self) -> None:
        for b in (b"", b"\x00", bytes(range(256))):
            self.assertEqual(b64url_decode(b64url_encode(b)), b)
        with self.assertRaises(ValueError):
            b64url_decode("a+b/")


if __name__ == "__main__":
    unittest.main()
