// Vault cryptography: PRF -> HKDF -> wrap key, master key wrap/unwrap, item encryption, RSA-OAEP to the requester.
// The master key stays a (non-extractable where possible) CryptoKey; plaintext secrets are Uint8Arrays
// that callers overwrite with zeros after use.

import { TAGS, toBytes, wrapAad, itemAad, MIN_RSA_BITS, MAX_RSA_BITS } from './formats.js';

const te = new TextEncoder();
const subtle = () => globalThis.crypto.subtle;
const AES = { name: 'AES-GCM', length: 256 };

export function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

/** PRF output (32 bytes) -> non-extractable AES-256-GCM wrap key. */
export async function deriveWrapKey(prfOutput) {
  const base = await subtle().importKey('raw', toBytes(prfOutput), 'HKDF', false, ['deriveKey']);
  return subtle().deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: te.encode(TAGS.hkdfSalt), info: te.encode(TAGS.hkdfInfo) },
    base, AES, false, ['wrapKey', 'unwrapKey'],
  );
}

/** A new master key (extractable, which wrapping requires). */
export function generateMasterKey() {
  return subtle().generateKey(AES, true, ['encrypt', 'decrypt']);
}

/** Wrap the master key. ct is AES-GCM(raw master key) ciphertext plus tag. */
export async function wrapMasterKey(wrapKey, masterKey, credentialId) {
  const iv = randomBytes(12);
  const ct = await subtle().wrapKey('raw', masterKey, wrapKey,
    { name: 'AES-GCM', iv, additionalData: wrapAad(credentialId) });
  return { iv, ct: new Uint8Array(ct) };
}

/**
 * Unwrap the master key. extractable=true is only needed to re-wrap it for a new passkey.
 * Throws if the credential id (AAD) or the PRF output differs.
 */
export async function unwrapMasterKey(wrapKey, wrapped, credentialId, { extractable = false } = {}) {
  return subtle().unwrapKey('raw', toBytes(wrapped.ct), wrapKey,
    { name: 'AES-GCM', iv: toBytes(wrapped.iv), additionalData: wrapAad(credentialId) },
    AES, extractable, ['encrypt', 'decrypt']);
}

/** Encrypt a secret (Uint8Array or string) with the master key. */
export async function encryptItem(masterKey, { name, site, account }, secret) {
  const iv = randomBytes(12);
  const ct = await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: itemAad(name, site, account) },
    masterKey, toBytes(secret));
  return { iv, ct: new Uint8Array(ct) };
}

/** Decrypt an item to plaintext bytes (callers zero them after use). Throws if name, site or account changed. */
export async function decryptItem(masterKey, { name, site, account, iv, ct }) {
  const pt = await subtle().decrypt({ name: 'AES-GCM', iv: toBytes(iv), additionalData: itemAad(name, site, account) },
    masterKey, toBytes(ct));
  return new Uint8Array(pt);
}

/** Import the requester's public key (SPKI DER) and check its size and exponent. */
export async function importRequesterKey(pubkeyDer) {
  const key = await subtle().importKey('spki', toBytes(pubkeyDer), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  const { modulusLength, publicExponent } = key.algorithm;
  if (modulusLength < MIN_RSA_BITS) throw new Error(`requester RSA key is too small (${modulusLength} bits)`);
  if (modulusLength > MAX_RSA_BITS) throw new Error(`requester RSA key is too large (${modulusLength} bits)`);
  const e = [...publicExponent].reduce((acc, b) => acc * 256 + b, 0);
  if (e !== 65537) throw new Error('requester RSA public exponent is not 65537');
  return key;
}

/** Largest RSA-OAEP(SHA-256) plaintext: k - 2*hLen - 2 bytes. */
export function maxOaepPlaintext(modulusLength) {
  return modulusLength / 8 - 2 * 32 - 2;
}

export async function rsaEncryptForRequester(pubKey, label, plaintext) {
  const pt = toBytes(plaintext);
  const max = maxOaepPlaintext(pubKey.algorithm.modulusLength);
  if (pt.length > max) throw new Error(`secret is too long for this requester key (${pt.length} bytes, at most ${max})`);
  return new Uint8Array(await subtle().encrypt({ name: 'RSA-OAEP', label: toBytes(label) }, pubKey, pt));
}
