// Management screen: first-time setup, secrets, passkeys, pending requests.

import { $, api, busy, describeError, el, formatRemaining, newNonce, setStatus, signAndUnlock, wrapForNewPasskey } from './common.js';
import { SECRET_NAME_RE, b64urlDecode, b64urlEncode, opChallenge } from './formats.js';
import { encryptItem, generateMasterKey } from './vaultcrypto.js';
import { createPasskey, getAssertion } from './webauthn.js';

const statusBox = $('#status');
let state = null;

const say = (message, kind) => setStatus(statusBox, message, kind);
const dateOnly = (iso) => (iso ? iso.slice(0, 10) : '');

/**
 * Run one user action: lock all buttons, run fn, show fn's success message (or the error), then
 * reload the page state. A failed reload never turns a completed change into an error message.
 */
function action(fn) {
  return busy([...document.querySelectorAll('button')], async () => {
    let message;
    try {
      message = await fn();
    } catch (e) {
      say(describeError(e), 'error');
      return;
    }
    try {
      await refresh();
      say(message, 'ok');
    } catch (e) {
      say(`${message} The page could not be reloaded: ${describeError(e)}`, 'error');
    }
  });
}

function onSubmit(form, fn) {
  form.addEventListener('submit', (ev) => { ev.preventDefault(); action(() => fn(ev.target)); });
}

function row({ title, detail, href, extra, actions = [] }) {
  const main = [el('span', { class: 'row-title' }, title), extra, el('span', { class: 'row-detail' }, detail)];
  return el('li', { class: 'row' },
    href ? el('a', { class: 'row-main row-link', href }, main) : el('div', { class: 'row-main' }, main),
    actions.length ? el('div', { class: 'row-actions' }, actions) : null);
}

const linkButton = (label, onclick, { danger = false, disabled = false, title = null } = {}) =>
  el('button', { type: 'button', class: danger ? 'link link-danger' : 'link', disabled, title, onclick }, label);

async function refresh() {
  state = await api('GET', '/api/state');
  $('#host').textContent = state.rp_id;
  $('#setup').hidden = state.initialized;
  for (const id of ['#items', '#passkeys']) $(id).hidden = !state.initialized;
  $('#pending').hidden = !state.initialized || state.pending.length === 0;
  if (!state.initialized) return;

  $('#pending-list').replaceChildren(...state.pending.map((p) => row({
    title: p.secret, detail: `${formatRemaining(p.expires_in)} left`,
    href: `/approve?id=${encodeURIComponent(p.id)}`, extra: el('code', { class: 'row-command' }, p.command),
  })));
  $('#item-list').replaceChildren(...(state.items.length
    ? state.items.map((it) => row({
      title: it.name,
      detail: [it.site, it.account].filter(Boolean).join(', ') || 'No site or account',
      actions: [linkButton('Replace', () => editItem(it)), linkButton('Delete', () => deleteItem(it.name), { danger: true })],
    }))
    : [el('li', { class: 'row row-empty' }, 'No secrets yet. Add the first one below.')]));
  const last = state.credentials.length < 2;
  $('#passkey-advice').hidden = !last;
  $('#passkey-list').replaceChildren(...state.credentials.map((c) => row({
    title: c.name, detail: `Added ${dateOnly(c.created_at)}`,
    actions: [linkButton('Remove', () => deleteCredential(c),
      { danger: true, disabled: last, title: last ? 'The last passkey cannot be removed' : null })],
  })));
}

/** {nonce, assertion} for an operation that needs a signature but no master key. */
async function signOnly(op, ...fields) {
  const nonce = await newNonce(op);
  const { json } = await getAssertion({
    rpId: state.rp_id, challenge: await opChallenge(op, nonce, ...fields),
    allowIds: state.credentials.map((c) => c.id), needPrf: false,
  });
  return { nonce: b64urlEncode(nonce), assertion: json };
}

// ---------- first-time setup ----------
onSubmit($('#f-setup'), async () => {
  const name = $('#setup-name').value.trim();
  say('Creating a passkey on this device…');
  const nonce = await newNonce('setup');
  const created = await createPasskey({ rpId: state.rp_id, challenge: await opChallenge('register', nonce, name), label: name });
  const wrapped = await wrapForNewPasskey(created, await generateMasterKey());
  await api('POST', '/api/setup', {
    setup_code: $('#setup-code').value, nonce: b64urlEncode(nonce), name,
    registration: created.json, wrapped_master_key: wrapped,
  });
  $('#setup-code').value = '';
  return 'Vault created. Add a second passkey so you can still open it if this device is lost.';
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

onSubmit($('#f-item'), async () => {
  const name = $('#item-name').value.trim();
  const site = $('#item-site').value.trim();
  const account = $('#item-account').value.trim();
  if (!SECRET_NAME_RE.test(name)) throw new Error('Use 1-64 letters, digits, dots, dashes or underscores for the name.');
  const secret = new TextEncoder().encode($('#item-secret').value);
  try {
    say('Waiting for your passkey…');
    const nonce = await newNonce('put-item');
    const { assertion, masterKey } = await signAndUnlock(state, await opChallenge('put-item', nonce, name, site, account));
    const enc = await encryptItem(masterKey, { name, site, account }, secret);
    await api('POST', '/api/items', {
      nonce: b64urlEncode(nonce), name, site, account, iv: b64urlEncode(enc.iv), ct: b64urlEncode(enc.ct), assertion,
    });
  } finally {
    secret.fill(0); // the typed value stays in the field on failure so the user can retry
  }
  $('#item-panel').open = false; // the toggle handler clears the form, including the password
  return `Saved ${name}.`;
});

function deleteItem(name) {
  if (!confirm(`Delete ${name}? Requests for it will fail until you add it again.`)) return;
  action(async () => {
    await api('POST', `/api/items/${encodeURIComponent(name)}/delete`, await signOnly('delete-item', name));
    return `Deleted ${name}.`;
  });
}

// ---------- passkeys ----------
onSubmit($('#f-passkey'), async (form) => {
  const name = $('#passkey-name').value.trim();
  const existing = state.credentials.map((c) => c.id);
  const nonce = await newNonce('add-credential');
  say('Step 1 of 2: create the new passkey.');
  const created = await createPasskey({
    rpId: state.rp_id, challenge: await opChallenge('register', nonce, name), label: name, excludeIds: existing,
  });
  try {
    say('Step 2 of 2: confirm with a passkey that is already registered.');
    const { assertion, masterKey } = await signAndUnlock(
      state, await opChallenge('add-credential', nonce, created.rawId, name), { allowIds: existing, extractable: true });
    await api('POST', '/api/credentials', {
      nonce: b64urlEncode(nonce), name, registration: created.json,
      wrapped_master_key: await wrapForNewPasskey(created, masterKey), assertion,
    });
  } finally {
    created.prf.fill(0); // also on failure before wrapForNewPasskey ran
  }
  form.reset();
  form.closest('details').open = false;
  return `Added passkey ${name}.`;
});

function deleteCredential(c) {
  if (!confirm(`Remove the passkey ${c.name}? It will no longer open this vault.`)) return;
  action(async () => {
    await api('POST', `/api/credentials/${encodeURIComponent(c.id)}/delete`, await signOnly('delete-credential', b64urlDecode(c.id)));
    return `Removed passkey ${c.name}.`;
  });
}

refresh().catch((e) => say(describeError(e), 'error'));
