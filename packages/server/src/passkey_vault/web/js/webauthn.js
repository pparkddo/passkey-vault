// WebAuthn + PRF. PRF output never leaves this page: the JSON sent to the server always carries an
// empty clientExtensionResults object.

import { b64urlDecode, b64urlEncode, prfSalt, toBytes } from './formats.js';

function prfResult(cred) {
  const ext = cred.getClientExtensionResults?.() ?? {};
  const first = ext.prf?.results?.first;
  return { enabled: ext.prf?.enabled, first: first ? new Uint8Array(first) : null };
}

function baseJson(cred) {
  return {
    id: cred.id,
    rawId: b64urlEncode(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? null,
    clientExtensionResults: {},
  };
}

function registrationJson(cred) {
  const r = cred.response;
  return {
    ...baseJson(cred),
    response: {
      clientDataJSON: b64urlEncode(r.clientDataJSON),
      attestationObject: b64urlEncode(r.attestationObject),
      transports: typeof r.getTransports === 'function' ? r.getTransports() : [],
    },
  };
}

function assertionJson(cred) {
  const r = cred.response;
  return {
    ...baseJson(cred),
    response: {
      clientDataJSON: b64urlEncode(r.clientDataJSON),
      authenticatorData: b64urlEncode(r.authenticatorData),
      signature: b64urlEncode(r.signature),
      userHandle: r.userHandle ? b64urlEncode(r.userHandle) : null,
    },
  };
}

const descriptors = (ids) => ids.map((id) => ({ type: 'public-key', id: b64urlDecode(id) }));

/**
 * Sign a challenge (and evaluate PRF) with one of the allowed passkeys (base64url ids).
 * Returns { json (for the server), credentialId (base64url), prf (Uint8Array | null) }.
 */
export async function getAssertion({ rpId, challenge, allowIds, needPrf = true }) {
  const cred = await navigator.credentials.get({
    publicKey: {
      rpId,
      challenge: toBytes(challenge),
      allowCredentials: descriptors(allowIds),
      userVerification: 'required',
      timeout: 120000,
      extensions: { prf: { eval: { first: await prfSalt() } } },
    },
  });
  if (!cred) throw new Error('The passkey did not respond.');
  const { first } = prfResult(cred);
  if (needPrf && !first) throw new Error('This passkey did not return a PRF result, so it cannot unlock the vault.');
  return { json: assertionJson(cred), credentialId: cred.id, prf: first };
}

/**
 * Create a passkey that supports PRF. If the create response carries no PRF output, sign in once
 * more with the new passkey to obtain it.
 * Returns { json, rawId (Uint8Array), prf (Uint8Array) }.
 */
export async function createPasskey({ rpId, challenge, label, excludeIds = [] }) {
  const cred = await navigator.credentials.create({
    publicKey: {
      rp: { id: rpId, name: 'passkey-vault' },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: `passkey-vault (${label})`, displayName: `passkey-vault (${label})` },
      challenge: toBytes(challenge),
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 }, // ES256
        { type: 'public-key', alg: -8 }, // EdDSA
        { type: 'public-key', alg: -257 }, // RS256
      ],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      attestation: 'none',
      excludeCredentials: descriptors(excludeIds),
      timeout: 120000,
      extensions: { prf: { eval: { first: await prfSalt() } } },
    },
  });
  if (!cred) throw new Error('The passkey did not respond.');
  const created = prfResult(cred);
  if (created.enabled === false) {
    throw new Error('This passkey provider does not support PRF, so it cannot unlock the vault. Use another one.');
  }
  let prf = created.first;
  if (!prf) {
    // Some platforms only return PRF output on sign-in. The server does not verify this assertion.
    ({ prf } = await getAssertion({ rpId, challenge: crypto.getRandomValues(new Uint8Array(32)), allowIds: [cred.id] }));
  }
  return { json: registrationJson(cred), rawId: new Uint8Array(cred.rawId), prf };
}
