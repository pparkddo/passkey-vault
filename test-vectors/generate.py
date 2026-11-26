"""Test vector generator.

    uv run python test-vectors/generate.py

Deterministic values (label, challenges, HKDF, AES-GCM) are computed from fixed inputs.
RSA-OAEP is randomized, so fixed key pairs and pre-computed ciphertexts are stored instead.
The committed JSON files are the reference. Re-running changes the RSA keys and ciphertexts,
so only regenerate when the rules change.

The RSA private keys in the vectors are public test keys. Never use them for anything else.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tests"))

from support import oaep, spki_der as spki, wrap_key  # noqa: E402  (also puts server/ on sys.path)

from passkey_vault import formats as f  # noqa: E402

NOTE = "passkey-vault test vectors v1. Bytes are hex; keys and DER are base64url without padding. Test-only keys: never use them."


def pkcs8(priv) -> bytes:
    return priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def flip_last_byte(b: bytes) -> bytes:
    return b[:-1] + bytes([b[-1] ^ 0x01])


def write(name: str, data: dict) -> None:
    (HERE / name).write_text(json.dumps({"note": NOTE, **data}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    keys = {bits: rsa.generate_private_key(public_exponent=65537, key_size=bits) for bits in (2048, 3072)}
    pub2048 = spki(keys[2048].public_key())
    ids = ["Q2v9b3nqk1mJt0x4H8sRZw", "AAAAAAAAAAAAAAAAAAAAAA"]
    commands = [
        "gh auth login --with-token",
        "curl -u me:$SECRET https://example.com/api",
        "login --site bücher.example \"with spaces\" ✓",
    ]

    # label
    label_cases = []
    for rid, cmd in [(ids[0], commands[0]), (ids[0], commands[2]), (ids[1], commands[1])]:
        label_cases.append({
            "id": rid, "command": cmd, "pubkey": f.b64url_encode(pub2048),
            "label_hex": f.oaep_label(rid, cmd, pub2048).hex(),
        })
    write("label.json", {"rule": "lp('passkey-vault/oaep-label/v1') || lp(id) || lp(command) || lp(pubkey_der), lp(x)=u32be(len)||x",
                         "cases": label_cases})

    # approve challenge
    write("approve-challenge.json", {
        "rule": "SHA-256(lp('passkey-vault/approve/v1') || lp(id) || lp(secret) || lp(command) || lp(pubkey_der))",
        "cases": [{
            "id": c["id"], "secret": s, "command": c["command"], "pubkey": c["pubkey"],
            "challenge_hex": f.approve_challenge(c["id"], s, c["command"], pub2048).hex(),
        } for c, s in zip(label_cases, ["github", "example.com", "kr.site"])],
    })

    # op challenge
    nonce = bytes(range(16))
    op_cases = [
        {"op": "put-item", "nonce_hex": nonce.hex(), "fields": ["github", "github.com", "me@example.com"]},
        {"op": "delete-item", "nonce_hex": nonce.hex(), "fields": ["github"]},
        {"op": "register", "nonce_hex": nonce.hex(), "fields": ["iPhone"]},
    ]
    for c in op_cases:
        c["challenge_hex"] = f.op_challenge(c["op"], nonce, *c["fields"]).hex()
    # add-credential takes bytes (the credential id) as its field
    cred_new = bytes.fromhex("a1" * 20)
    op_cases.append({"op": "add-credential", "nonce_hex": nonce.hex(), "fields_hex": [cred_new.hex()],
                     "challenge_hex": f.op_challenge("add-credential", nonce, cred_new).hex()})
    write("op-challenge.json", {
        "rule": "SHA-256(lp('passkey-vault/op/v1') || lp(op) || lp(nonce) || lp(field1) || ...). fields are UTF-8 strings, fields_hex are bytes",
        "cases": op_cases,
    })

    # RSA-OAEP
    rsa_cases = []
    for bits, rid, cmd, plaintext in [
        (2048, ids[0], commands[0], "correct horse battery staple"),
        (2048, ids[1], commands[2], "pässwörd ✓ 🔑"),
        (2048, ids[0], commands[1], "x" * 190),  # maximum length for a 2048-bit key
        (3072, ids[0], commands[0], "p@ss/w0rd=+"),
    ]:
        priv = keys[bits]
        pub_der = spki(priv.public_key())
        label = f.oaep_label(rid, cmd, pub_der)
        ct = priv.public_key().encrypt(plaintext.encode("utf-8"), oaep(label))
        rsa_cases.append({
            "bits": bits, "id": rid, "command": cmd,
            "pubkey": f.b64url_encode(pub_der), "private_key_pkcs8": f.b64url_encode(pkcs8(priv)),
            "label_hex": label.hex(), "ciphertext": f.b64url_encode(ct), "plaintext": plaintext,
            "must_fail_with_label_hex": flip_last_byte(label).hex(),
            "must_fail_with_command": cmd + " ",
        })
    write("rsa-oaep.json", {
        "rule": "RSA-OAEP, hash SHA-256, MGF1 SHA-256, label as in label.json. Randomized, so vectors are fixed ciphertext -> expected plaintext. Decrypting with must_fail_* must fail",
        "cases": rsa_cases,
    })

    # HKDF, master key wrapping, item encryption
    prf_out = bytes(range(32))
    wk = wrap_key(prf_out)
    master = bytes(range(100, 132))
    cred_id = bytes.fromhex("c0ffee" * 10)
    wrap_iv = bytes(range(200, 212))
    wrapped = AESGCM(wk).encrypt(wrap_iv, master, f.wrap_aad(cred_id))
    item = {"name": "github", "site": "github.com", "account": "me@example.com"}
    item_iv = bytes(range(50, 62))
    secret = "hunter2 ✓ geheim"
    item_ct = AESGCM(master).encrypt(item_iv, secret.encode("utf-8"), f.item_aad(**item))
    write("keys.json", {
        "rule": "PRF input = SHA-256('passkey-vault/prf-salt/v1'); wrap key = HKDF-SHA256(ikm=PRF output, salt='passkey-vault/hkdf-salt/v1', info='passkey-vault/wrap-key/v1', L=32); "
                "wrap = AES-256-GCM(wrap key, iv, master key, AAD=lp('passkey-vault/wrap/v1')||lp(credential_id)); "
                "item = AES-256-GCM(master key, iv, UTF-8 secret, AAD=lp('passkey-vault/item/v1')||lp(name)||lp(site)||lp(account)). Ciphertext hex includes the 16-byte tag",
        "prf_salt_hex": f.PRF_SALT.hex(),
        "prf_output_hex": prf_out.hex(),
        "wrap_key_hex": wk.hex(),
        "master_key_hex": master.hex(),
        "credential_id_hex": cred_id.hex(),
        "wrap_aad_hex": f.wrap_aad(cred_id).hex(),
        "wrap_iv_hex": wrap_iv.hex(),
        "wrapped_master_key_hex": wrapped.hex(),
        "item": item,
        "item_aad_hex": f.item_aad(**item).hex(),
        "item_iv_hex": item_iv.hex(),
        "item_plaintext": secret,
        "item_ciphertext_hex": item_ct.hex(),
        "must_fail_item_with_account": "me@example.org",
    })
    print("wrote test-vectors/*.json")


if __name__ == "__main__":
    main()
