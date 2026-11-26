// Management screen: first-time setup, secrets, passkeys, pending requests.

import { $, api, busy, describeError, el, formatRemaining, newNonce, setStatus, signAndUnlock, wrappedToJson } from './common.js';
import { SECRET_NAME_RE, b64urlDecode, b64urlEncode, opChallenge } from './formats.js';
import { deriveWrapKey, encryptItem, generateMasterKey, wrapMasterKey } from './vaultcrypto.js';
import { createPasskey, getAssertion } from './webauthn.js';

const statusBox = $('#status');
let state = null;

const say = (message, kind) => setStatus(statusBox, message, kind);
const allButtons = () => [...document.querySelectorAll('button')];
const dateOnly = (iso) => (iso ? iso.slice(0, 10) : '');

function itemRow(it) {
  return el('li', { class: 'row' },
    el('div', { class: 'row-main' },
      el('span', { class: 'row-title' }, it.name),
      el('span', { class: 'row-detail' }, [it.site, it.account].filter(Boolean).join(', ') || 'No site or account')),
    el('div', { class: 'row-actions' },
      el('button', { type: 'button', class: 'link', onclick: () => editItem(it) }, 'Replace'),
      el('button', { type: 'button', class: 'link link-danger', onclick: () => deleteItem(it.name) }, 'Delete')));
}

function passkeyRow(c) {
  const last = state.credentials.length < 2;
  return el('li', { class: 'row' },
    el('div', { class: 'row-main' },
      el('span', { class: 'row-title' }, c.name),
      el('span', { class: 'row-detail' }, `Added ${dateOnly(c.created_at)}`)),
    el('div', { class: 'row-actions' },
      el('button', { type: 'button', class: 'link link-danger', disabled: last,
        title: last ? 'The last passkey cannot be removed' : null, onclick: () => deleteCredential(c) }, 'Remove')));
}

function pendingRow(p) {
  const left = p.expires_in;
  return el('li', { class: 'row' },
    el('a', { class: 'row-main row-link', href: `/approve?id=${encodeURIComponent(p.id)}` },
      el('span', { class: 'row-title' }, p.secret),
      el('code', { class: 'row-command' }, p.command),
      el('span', { class: 'row-detail' }, `${formatRemaining(left)} left`)));
}

async function refresh() {
  state = await api('GET', '/api/state');
  $('#host').textContent = state.rp_id;
  $('#setup').hidden = state.initialized;
  for (const id of ['#items', '#passkeys']) $(id).hidden = !state.initialized;
  $('#pending').hidden = !state.initialized || state.pending.length === 0;
  if (!state.initialized) return;

  $('#pending-list').replaceChildren(...state.pending.map(pendingRow));
  $('#item-list').replaceChildren(...(state.items.length
    ? state.items.map(itemRow)
    : [el('li', { class: 'row row-empty' }, 'No secrets yet. Add the first one below.')]));
  $('#passkey-advice').hidden = state.credentials.length > 1;
  $('#passkey-list').replaceChildren(...state.credentials.map(passkeyRow));
}

// ---------- first-time setup ----------
$('#f-setup').addEventListener('submit', (ev) => {
  ev.preventDefault();
  busy(allButtons(), async () => {
    const name = $('#setup-name').value.trim();
    try {
      say('Creating a passkey on this device…');
      const nonce = await newNonce('setup');
      const created = await createPasskey({ rpId: state.rp_id, challenge: await opChallenge('register', nonce, name), label: name });
      const masterKey = await generateMasterKey();
      const wrapped = await wrapMasterKey(await deriveWrapKey(created.prf), masterKey, created.rawId);
      created.prf.fill(0);
      await api('POST', '/api/setup', {
        setup_code: $('#setup-code').value, nonce: b64urlEncode(nonce), name,
        registration: created.json, wrapped_master_key: wrappedToJson(wrapped),
      });
      $('#setup-code').value = '';
      await refresh();
      say('Vault created. Add a second passkey so you can still open it if this device is lost.', 'ok');
    } catch (e) {
      say(describeError(e), 'error');
    }
  });
});

// ---------- secrets ----------
function resetItemForm() {
  $('#f-item').reset();
  $('#item-summary').textContent = 'Add a secret';
}

$('#item-panel').addEventListener('toggle', (ev) => { if (!ev.target.open) resetItemForm(); });

function editItem(it) {
  $('#item-panel').open = true;
  $('#item-summary').textContent = `Replace ${it.name}`;
  $('#item-name').value = it.name;
  $('#item-site').value = it.site;
  $('#item-account').value = it.account;
  $('#item-secret').value = '';
  $('#item-secret').focus();
}

$('#f-item').addEventListener('submit', (ev) => {
  ev.preventDefault();
  busy(allButtons(), async () => {
    const name = $('#item-name').value.trim();
    const site = $('#item-site').value.trim();
    const account = $('#item-account').value.trim();
    const secretInput = $('#item-secret');
    if (!SECRET_NAME_RE.test(name)) { say('Use 1-64 letters, digits, dots, dashes or underscores for the name.', 'error'); return; }
    const secret = new TextEncoder().encode(secretInput.value);
    let saved = false;
    try {
      say('Waiting for your passkey…');
      const nonce = await newNonce('put-item');
      const { assertion, masterKey } = await signAndUnlock(state, await opChallenge('put-item', nonce, name, site, account));
      const enc = await encryptItem(masterKey, { name, site, account }, secret);
      await api('POST', '/api/items', {
        nonce: b64urlEncode(nonce), name, site, account, iv: b64urlEncode(enc.iv), ct: b64urlEncode(enc.ct), assertion,
      });
      saved = true;
      $('#item-panel').open = false; // the toggle handler resets the form
      await refresh();
      say(`Saved ${name}.`, 'ok');
    } catch (e) {
      say(describeError(e), 'error');
    } finally {
      secret.fill(0);
      if (saved) secretInput.value = ''; // keep what was typed if saving failed, so it can be retried
    }
  });
});

async function signOnly(op, ...fields) {
  const nonce = await newNonce(op);
  const { json } = await getAssertion({
    rpId: state.rp_id, challenge: await opChallenge(op, nonce, ...fields),
    allowIds: state.credentials.map((c) => c.id), needPrf: false,
  });
  return { nonce: b64urlEncode(nonce), assertion: json };
}

async function deleteItem(name) {
  if (!confirm(`Delete ${name}? Requests for it will fail until you add it again.`)) return;
  await busy(allButtons(), async () => {
    try {
      await api('POST', `/api/items/${encodeURIComponent(name)}/delete`, await signOnly('delete-item', name));
      await refresh();
      say(`Deleted ${name}.`, 'ok');
    } catch (e) {
      say(describeError(e), 'error');
    }
  });
}

// ---------- passkeys ----------
$('#f-passkey').addEventListener('submit', (ev) => {
  ev.preventDefault();
  busy(allButtons(), async () => {
    const name = $('#passkey-name').value.trim();
    const existing = state.credentials.map((c) => c.id);
    try {
      const nonce = await newNonce('add-credential');
      say('Step 1 of 2: create the new passkey.');
      const created = await createPasskey({
        rpId: state.rp_id, challenge: await opChallenge('register', nonce, name), label: name, excludeIds: existing,
      });
      say('Step 2 of 2: confirm with a passkey that is already registered.');
      const { assertion, masterKey } = await signAndUnlock(
        state, await opChallenge('add-credential', nonce, created.rawId, name), { allowIds: existing, extractable: true });
      const wrapped = await wrapMasterKey(await deriveWrapKey(created.prf), masterKey, created.rawId);
      created.prf.fill(0);
      await api('POST', '/api/credentials', {
        nonce: b64urlEncode(nonce), name, registration: created.json, wrapped_master_key: wrappedToJson(wrapped), assertion,
      });
      ev.target.reset();
      ev.target.closest('details').open = false;
      await refresh();
      say(`Added passkey ${name}.`, 'ok');
    } catch (e) {
      say(describeError(e), 'error');
    }
  });
});

async function deleteCredential(c) {
  if (!confirm(`Remove the passkey ${c.name}? It will no longer open this vault.`)) return;
  await busy(allButtons(), async () => {
    try {
      await api('POST', `/api/credentials/${encodeURIComponent(c.id)}/delete`, await signOnly('delete-credential', b64urlDecode(c.id)));
      await refresh();
      say(`Removed passkey ${c.name}.`, 'ok');
    } catch (e) {
      say(describeError(e), 'error');
    }
  });
}

refresh().catch((e) => say(describeError(e), 'error'));
