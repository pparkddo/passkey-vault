"""WebAuthn registration and assertion verification (via py_webauthn).

The server checks: challenge, origin, RP ID hash, UP and UV flags, signature, signature counter.
PRF extension output is an unsigned client value, so the server cannot verify it; the page refuses
authenticators without PRF at registration time.
"""

from __future__ import annotations

from typing import Any

from webauthn import verify_authentication_response, verify_registration_response
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse

from .audit import utc_now_iso
from .errors import ApiError
from .formats import b64url_decode, b64url_encode
from .vault import Signer


def _bad(message: str) -> ApiError:
    return ApiError(400, "invalid_webauthn", message)


def parse_wrapped(w: Any) -> dict[str, str]:
    """Wrapped master key {iv, ct}: 12-byte IV, ct = 32-byte key + 16-byte tag."""
    try:
        iv, ct = b64url_decode(w["iv"]), b64url_decode(w["ct"])
    except (TypeError, KeyError, ValueError):
        raise _bad("malformed wrapped_master_key") from None
    if len(iv) != 12 or len(ct) != 48:
        raise _bad("wrapped_master_key has the wrong length")
    return {"iv": w["iv"], "ct": w["ct"]}


def verify_registration(
    credential: Any, expected_challenge: bytes, rp_id: str, origin: str, name: str, wrapped_master_key: Any
) -> dict[str, Any]:
    if not isinstance(credential, dict):
        raise _bad("registration must be an object")
    wrapped = parse_wrapped(wrapped_master_key)
    try:
        v = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_presence=True,
            require_user_verification=True,
        )
    except (InvalidRegistrationResponse, ValueError, KeyError, TypeError) as e:
        raise _bad(f"registration verification failed: {e}") from None
    return {
        "id": b64url_encode(v.credential_id),
        "name": name,
        "public_key": b64url_encode(v.credential_public_key),
        "sign_count": v.sign_count,
        "aaguid": v.aaguid,
        "created_at": utc_now_iso(),
        "wrapped_master_key": wrapped,
    }


def verify_assertion(
    doc: dict[str, Any],
    assertion: Any,
    expected_challenge: bytes,
    rp_id: str,
    origin: str,
    allowed_ids: set[str] | None = None,
) -> tuple[dict[str, Any], Signer]:
    """Verify a signature by a passkey registered in `doc`.

    Returns (fields for the audit log, signer). Pass the signer to the vault change so the new
    signature counter is stored in the same write.
    """
    if not isinstance(assertion, dict) or not isinstance(assertion.get("id"), str):
        raise _bad("assertion must be an object")
    cred = next((c for c in doc.get("credentials", []) if c["id"] == assertion["id"]), None)
    if cred is None or (allowed_ids is not None and cred["id"] not in allowed_ids):
        raise ApiError(403, "unknown_credential", "this passkey is not registered")
    try:
        v = verify_authentication_response(
            credential=assertion,
            expected_challenge=expected_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=b64url_decode(cred["public_key"]),
            credential_current_sign_count=cred["sign_count"],
            require_user_verification=True,
        )
    except (InvalidAuthenticationResponse, ValueError, KeyError, TypeError) as e:
        raise _bad(f"assertion verification failed: {e}") from None
    resp = assertion["response"]
    audit = {
        "credential_id": cred["id"],
        "credential_name": cred["name"],
        "authenticator_data": resp["authenticatorData"],
        "client_data_json": resp["clientDataJSON"],
        "signature": resp["signature"],
    }
    return audit, (cred["id"], v.new_sign_count)
