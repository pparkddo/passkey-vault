// node --test tests/js/
// Checks test-vectors/ with the web/js modules (the same code the browser runs). No dependencies (Node 24 WebCrypto).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as F from '../../web/js/formats.js';
import * as V from '../../web/js/vaultcrypto.js';

const load = (name) => JSON.parse(readFileSync(new URL(`../../test-vectors/${name}`, import.meta.url), 'utf8'));
const subtle = globalThis.crypto.subtle;

test('OAEP label', () => {
  for (const c of load('label.json').cases) {
    assert.equal(F.hex(F.oaepLabel(c.id, c.command, F.b64urlDecode(c.pubkey))), c.label_hex);
  }
});

test('approve challenge', async () => {
  for (const c of load('approve-challenge.json').cases) {
    const ch = await F.approveChallenge(c.id, c.secret, c.command, F.b64urlDecode(c.pubkey));
    assert.equal(F.hex(ch), c.challenge_hex);
  }
});

test('operation challenge', async () => {
  for (const c of load('op-challenge.json').cases) {
    const fields = c.fields ?? c.fields_hex.map(F.fromHex);
    assert.equal(F.hex(await F.opChallenge(c.op, F.fromHex(c.nonce_hex), ...fields)), c.challenge_hex);
  }
});

test('RSA-OAEP: fixed key, label and ciphertext decrypt; a changed label or command fails', async () => {
  for (const c of load('rsa-oaep.json').cases) {
    const priv = await subtle.importKey('pkcs8', F.b64urlDecode(c.private_key_pkcs8),
      { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
    const label = F.oaepLabel(c.id, c.command, F.b64urlDecode(c.pubkey));
    assert.equal(F.hex(label), c.label_hex);
    const ct = F.b64urlDecode(c.ciphertext);
    const pt = new TextDecoder().decode(await subtle.decrypt({ name: 'RSA-OAEP', label }, priv, ct));
    assert.equal(pt, c.plaintext);
    await assert.rejects(subtle.decrypt({ name: 'RSA-OAEP', label: F.fromHex(c.must_fail_with_label_hex) }, priv, ct));
    const badLabel = F.oaepLabel(c.id, c.must_fail_with_command, F.b64urlDecode(c.pubkey));
    await assert.rejects(subtle.decrypt({ name: 'RSA-OAEP', label: badLabel }, priv, ct));
  }
});

test('RSA-OAEP: page code path encrypts to the requester key', async () => {
  const c = load('rsa-oaep.json').cases.find((x) => x.bits === 2048);
  const pubDer = F.b64urlDecode(c.pubkey);
  const pub = await V.importRequesterKey(pubDer);
  const label = F.oaepLabel(c.id, c.command, pubDer);
  const ct = await V.rsaEncryptForRequester(pub, label, new TextEncoder().encode('x'.repeat(190)));
  const priv = await subtle.importKey('pkcs8', F.b64urlDecode(c.private_key_pkcs8), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
  assert.equal(new TextDecoder().decode(await subtle.decrypt({ name: 'RSA-OAEP', label }, priv, ct)), 'x'.repeat(190));
  await assert.rejects(V.rsaEncryptForRequester(pub, label, new Uint8Array(191)), /too long/);
});

test('requester key check rejects 1024-bit keys', async () => {
  const kp = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
  const der = new Uint8Array(await subtle.exportKey('spki', kp.publicKey));
  await assert.rejects(V.importRequesterKey(der), /too small/);
});

test('HKDF, master key wrapping and item encryption', async () => {
  const k = load('keys.json');
  assert.equal(F.hex(await F.prfSalt()), k.prf_salt_hex);
  // compare wrap-key bytes (deriveBits is used only in this test)
  const base = await subtle.importKey('raw', F.fromHex(k.prf_output_hex), 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new TextEncoder().encode(F.TAGS.hkdfSalt), info: new TextEncoder().encode(F.TAGS.hkdfInfo) }, base, 256);
  assert.equal(F.hex(bits), k.wrap_key_hex);
  assert.equal(F.hex(F.wrapAad(F.fromHex(k.credential_id_hex))), k.wrap_aad_hex);
  assert.equal(F.hex(F.itemAad(k.item.name, k.item.site, k.item.account)), k.item_aad_hex);

  const wrapKey = await V.deriveWrapKey(F.fromHex(k.prf_output_hex));
  const credId = F.fromHex(k.credential_id_hex);
  const wrapped = { iv: F.fromHex(k.wrap_iv_hex), ct: F.fromHex(k.wrapped_master_key_hex) };
  const master = await V.unwrapMasterKey(wrapKey, wrapped, credId, { extractable: true });
  assert.equal(F.hex(await subtle.exportKey('raw', master)), k.master_key_hex);
  await assert.rejects(V.unwrapMasterKey(wrapKey, wrapped, F.fromHex('00' + k.credential_id_hex.slice(2))));

  const item = { ...k.item, iv: F.fromHex(k.item_iv_hex), ct: F.fromHex(k.item_ciphertext_hex) };
  const pt = await V.decryptItem(master, item);
  assert.equal(new TextDecoder().decode(pt), k.item_plaintext);
  await assert.rejects(V.decryptItem(master, { ...item, account: k.must_fail_item_with_account }));

  // page code path round trips: wrap -> unwrap, encrypt -> decrypt
  const rewrapped = await V.wrapMasterKey(wrapKey, master, credId);
  const master2 = await V.unwrapMasterKey(wrapKey, rewrapped, credId);
  const enc = await V.encryptItem(master2, k.item, 'new secret ✓');
  assert.equal(new TextDecoder().decode(await V.decryptItem(master, { ...k.item, ...enc })), 'new secret ✓');
});

test('command validation', () => {
  assert.equal(F.validateCommand('ls -la'), null);
  assert.equal(F.validateCommand('echo bücher ✓'), null);
  assert.notEqual(F.validateCommand(''), null);
  assert.notEqual(F.validateCommand('a\nb'), null);
  assert.notEqual(F.validateCommand('a\tb'), null);
  assert.notEqual(F.validateCommand('echo \u202Eabc'), null);
  for (const bad of ['a\u061Cb', 'a\u200Bb', 'a\uFEFFb', 'a\u00ADb', '\uD800']) {
    assert.notEqual(F.validateCommand(bad), null, bad);
  }
  assert.notEqual(F.validateCommand('a'.repeat(4097)), null);
});

test('base64url round trip and malformed input', () => {
  const b = V.randomBytes(100);
  assert.deepEqual(F.b64urlDecode(F.b64urlEncode(b)), b);
  assert.throws(() => F.b64urlDecode('a+b/'));
  assert.throws(() => F.b64urlDecode('abcde'));
});
