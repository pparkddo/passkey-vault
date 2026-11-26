"""Check test-vectors/ against the server-side Python rules (passkey_vault.formats) and cryptography."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))

from cryptography.exceptions import InvalidTag  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402
from cryptography.hazmat.primitives.serialization import load_der_private_key  # noqa: E402

from passkey_vault import formats as f  # noqa: E402


def load(name: str) -> dict:
    return json.loads((ROOT / "test-vectors" / name).read_text(encoding="utf-8"))


def oaep(label: bytes) -> padding.OAEP:
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label)


class VectorTests(unittest.TestCase):
    def test_label(self) -> None:
        for c in load("label.json")["cases"]:
            self.assertEqual(f.oaep_label(c["id"], c["command"], f.b64url_decode(c["pubkey"])).hex(), c["label_hex"])

    def test_approve_challenge(self) -> None:
        for c in load("approve-challenge.json")["cases"]:
            got = f.approve_challenge(c["id"], c["secret"], c["command"], f.b64url_decode(c["pubkey"]))
            self.assertEqual(got.hex(), c["challenge_hex"])

    def test_op_challenge(self) -> None:
        for c in load("op-challenge.json")["cases"]:
            fields = c.get("fields") or [bytes.fromhex(x) for x in c["fields_hex"]]
            self.assertEqual(f.op_challenge(c["op"], bytes.fromhex(c["nonce_hex"]), *fields).hex(), c["challenge_hex"])

    def test_rsa_oaep(self) -> None:
        for c in load("rsa-oaep.json")["cases"]:
            priv = load_der_private_key(f.b64url_decode(c["private_key_pkcs8"]), None)
            label = f.oaep_label(c["id"], c["command"], f.b64url_decode(c["pubkey"]))
            self.assertEqual(label.hex(), c["label_hex"])
            ct = f.b64url_decode(c["ciphertext"])
            self.assertEqual(priv.decrypt(ct, oaep(label)).decode(), c["plaintext"])
            with self.assertRaises(ValueError):
                priv.decrypt(ct, oaep(bytes.fromhex(c["must_fail_with_label_hex"])))
            with self.assertRaises(ValueError):
                priv.decrypt(ct, oaep(f.oaep_label(c["id"], c["must_fail_with_command"], f.b64url_decode(c["pubkey"]))))

    def test_keys(self) -> None:
        k = load("keys.json")
        self.assertEqual(f.PRF_SALT.hex(), k["prf_salt_hex"])
        wk = HKDF(algorithm=hashes.SHA256(), length=32, salt=f.HKDF_SALT, info=f.HKDF_INFO).derive(bytes.fromhex(k["prf_output_hex"]))
        self.assertEqual(wk.hex(), k["wrap_key_hex"])
        cred = bytes.fromhex(k["credential_id_hex"])
        master = AESGCM(wk).decrypt(bytes.fromhex(k["wrap_iv_hex"]), bytes.fromhex(k["wrapped_master_key_hex"]), f.wrap_aad(cred))
        self.assertEqual(master.hex(), k["master_key_hex"])
        it = k["item"]
        pt = AESGCM(master).decrypt(bytes.fromhex(k["item_iv_hex"]), bytes.fromhex(k["item_ciphertext_hex"]),
                                    f.item_aad(it["name"], it["site"], it["account"]))
        self.assertEqual(pt.decode(), k["item_plaintext"])
        with self.assertRaises(InvalidTag):
            AESGCM(master).decrypt(bytes.fromhex(k["item_iv_hex"]), bytes.fromhex(k["item_ciphertext_hex"]),
                                   f.item_aad(it["name"], it["site"], k["must_fail_item_with_account"]))

    def test_command_validation(self) -> None:
        self.assertIsNone(f.validate_command("ls -la"))
        self.assertIsNone(f.validate_command("echo bücher ✓"))
        for bad in ["", "a\nb", "a\tb", "echo \u202eabc", "x\u2028y", "a\u061cb", "a\u200bb",
                    "a\ufeffb", "a\u00adb", "\ud800", "a" * 4097, None]:
            self.assertIsNotNone(f.validate_command(bad), repr(bad))

    def test_lp_is_unambiguous(self) -> None:
        # Inputs that would collide with a separator-based encoding must differ with length prefixes.
        self.assertNotEqual(f.oaep_label("a", "b c", b"d"), f.oaep_label("a b", "c", b"d"))


if __name__ == "__main__":
    unittest.main()
