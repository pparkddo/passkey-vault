// Byte-level rules: OAEP label, challenges, AAD, base64url, input validation.
// Mirrors server/passkey_vault/formats.py; both are checked against test-vectors/.
// Runs in browsers and in Node 24 (uses globalThis.crypto).

const te = new TextEncoder();

export const TAGS = Object.freeze({
  label: 'passkey-vault/oaep-label/v1',
  approve: 'passkey-vault/approve/v1',
  op: 'passkey-vault/op/v1',
  item: 'passkey-vault/item/v1',
  wrap: 'passkey-vault/wrap/v1',
  prfSalt: 'passkey-vault/prf-salt/v1',
  hkdfSalt: 'passkey-vault/hkdf-salt/v1',
  hkdfInfo: 'passkey-vault/wrap-key/v1',
});

export const SECRET_NAME_RE = /^[A-Za-z0-9._-]{1,64}$/;
export const REQUEST_ID_RE = /^[A-Za-z0-9_-]{22}$/;
export const MAX_COMMAND_BYTES = 4096;
export const MIN_RSA_BITS = 2048;
export const MAX_RSA_BITS = 4096;

// Same categories as the server: controls, format characters (bidi, zero-width), lone surrogates,
// line/paragraph separators.
const FORBIDDEN_CHARS = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u;

export function toBytes(x) {
  if (typeof x === 'string') return te.encode(x);
  if (x instanceof Uint8Array) return x;
  if (x instanceof ArrayBuffer) return new Uint8Array(x);
  if (ArrayBuffer.isView(x)) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
  throw new TypeError('expected a string or bytes');
}

/** Length-prefixed encoding of several fields: u32be(len) || bytes ... */
export function concat(...fields) {
  const parts = fields.map(toBytes);
  const total = parts.reduce((n, p) => n + 4 + p.length, 0);
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let off = 0;
  for (const p of parts) {
    view.setUint32(off, p.length, false);
    out.set(p, off + 4);
    off += 4 + p.length;
  }
  return out;
}

export async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', toBytes(data)));
}

export function oaepLabel(id, command, pubkeyDer) {
  return concat(TAGS.label, id, command, pubkeyDer);
}

export function approveChallenge(id, secret, command, pubkeyDer) {
  return sha256(concat(TAGS.approve, id, secret, command, pubkeyDer));
}

export function opChallenge(op, nonce, ...fields) {
  return sha256(concat(TAGS.op, op, nonce, ...fields));
}

export function itemAad(name, site, account) {
  return concat(TAGS.item, name, site, account);
}

export function wrapAad(credentialId) {
  return concat(TAGS.wrap, credentialId);
}

let prfSaltPromise = null;
/** The fixed PRF input, computed once. */
export function prfSalt() {
  prfSaltPromise ??= sha256(TAGS.prfSalt);
  return prfSaltPromise;
}

export function b64urlEncode(bytes) {
  const b = toBytes(bytes);
  let s = '';
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64urlDecode(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) {
    throw new Error('not base64url');
  }
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function hex(bytes) {
  return [...toBytes(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function hasForbiddenChars(s) {
  return FORBIDDEN_CHARS.test(s);
}

/** Returns a reason string if invalid, otherwise null. */
export function validateCommand(command) {
  if (typeof command !== 'string') return 'command must be a string';
  if (hasForbiddenChars(command)) return 'command must not contain control, format (bidi, zero-width) or separator characters';
  const n = te.encode(command).length;
  if (n < 1 || n > MAX_COMMAND_BYTES) return `command must be 1-${MAX_COMMAND_BYTES} UTF-8 bytes`;
  return null;
}
