// Shared page code: API calls, safe DOM building (never innerHTML), unlocking the master key.

import { b64urlDecode, b64urlEncode } from './formats.js';
import { deriveWrapKey, unwrapMasterKey } from './vaultcrypto.js';
import { getAssertion } from './webauthn.js';

export const $ = (sel) => document.querySelector(sel);

export async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    cache: 'no-store',
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = {};
  try { data = await res.json(); } catch { /* empty body */ }
  if (!res.ok) {
    const err = new Error(data.message || `The server answered ${res.status}.`);
    err.code = data.error;
    err.status = res.status;
    throw err;
  }
  return data;
}

export async function newNonce(op) {
  return b64urlDecode((await api('POST', '/api/nonce', { op })).nonce);
}

/** Build an element with text-only children. */
export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === false || v == null) continue;
    if (k === 'class') node.className = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

/** Show a status line. kind: 'info' | 'ok' | 'error'. */
export function setStatus(target, message, kind = 'info') {
  target.replaceChildren(message ? el('p', { class: `notice notice-${kind}`, role: kind === 'error' ? 'alert' : 'status' }, message) : '');
}

export function describeError(e) {
  if (e?.name === 'NotAllowedError') return 'The passkey prompt was cancelled or timed out. Nothing was changed.';
  if (e?.name === 'InvalidStateError') return 'This passkey is already registered with the vault.';
  if (e?.name === 'OperationError') return 'Decryption failed: the stored item was changed, or this passkey cannot open it.';
  return e?.message || String(e);
}

/** Disable the given (currently enabled) buttons while fn runs. */
export async function busy(buttons, fn) {
  const locked = buttons.filter((b) => !b.disabled);
  locked.forEach((b) => { b.disabled = true; });
  try { return await fn(); } finally { locked.forEach((b) => { b.disabled = false; }); }
}

/**
 * Sign with a passkey (+PRF) and unwrap that passkey's copy of the master key.
 * The PRF bytes are overwritten as soon as the wrap key is derived.
 * Returns { assertion (JSON for the server), credentialId, masterKey (CryptoKey) }.
 */
export async function signAndUnlock(state, challenge, { allowIds, extractable = false } = {}) {
  const ids = allowIds ?? state.credentials.map((c) => c.id);
  const { json, credentialId, prf } = await getAssertion({ rpId: state.rp_id, challenge, allowIds: ids });
  try {
    const entry = state.credentials.find((c) => c.id === credentialId);
    if (!entry) throw new Error('That passkey is not registered with this vault.');
    const wrapKey = await deriveWrapKey(prf);
    const masterKey = await unwrapMasterKey(wrapKey, {
      iv: b64urlDecode(entry.wrapped_master_key.iv), ct: b64urlDecode(entry.wrapped_master_key.ct),
    }, b64urlDecode(credentialId), { extractable });
    return { assertion: json, credentialId, masterKey };
  } finally {
    prf.fill(0);
  }
}

export function wrappedToJson(w) {
  return { iv: b64urlEncode(w.iv), ct: b64urlEncode(w.ct) };
}

/** "4:07" style remaining time. */
export function formatRemaining(seconds) {
  const s = Math.max(0, Math.round(seconds));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}
