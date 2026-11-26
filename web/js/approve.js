// Approval screen: show the request, then passkey -> PRF -> master key -> decrypt this one item
// -> RSA-OAEP to the requester's one-time key -> upload. Nothing else is decrypted.

import { $, api, busy, describeError, formatRemaining, setStatus, signAndUnlock } from './common.js';
import { REQUEST_ID_RE, approveChallenge, b64urlDecode, b64urlEncode, oaepLabel, validateCommand } from './formats.js';
import { decryptItem, importRequesterKey, rsaEncryptForRequester } from './vaultcrypto.js';

const statusBox = $('#status');
const FINAL = {
  approved: 'This request was already approved.',
  denied: 'This request was denied.',
  expired: 'This request expired. Ask the requester to send a new one.',
  consumed: 'This request was already used.',
};
const LOW_SECONDS = 60;

let timer = null;

function close(message, kind = 'info') {
  clearInterval(timer);
  $('#decision').hidden = true;
  $('.fuse').classList.add('fuse-out');
  setStatus(statusBox, message, kind);
}

// Counts down from the server's expires_in using the monotonic clock, so a wrong device clock
// cannot make a live request look expired (or the reverse).
function startCountdown(expiresIn, lifetime) {
  const end = performance.now() + expiresIn * 1000;
  const total = Math.max(1, lifetime * 1000);
  const fuse = $('#fuse');
  const tick = () => {
    const left = Math.max(0, end - performance.now());
    $('#r-expires').textContent = formatRemaining(left / 1000);
    fuse.style.transform = `scaleX(${left / total})`;
    document.body.classList.toggle('is-low', left / 1000 <= LOW_SECONDS);
    if (left === 0) close(FINAL.expired, 'error');
  };
  tick();
  timer = setInterval(tick, 1000);
}

async function main() {
  const id = new URLSearchParams(location.search).get('id') ?? '';
  if (!REQUEST_ID_RE.test(id)) {
    setStatus(statusBox, 'This link is incomplete: it has no request id. Open the full link you were sent.', 'error');
    return;
  }
  let req, state;
  try {
    [req, state] = await Promise.all([api('GET', `/api/requests/${id}`), api('GET', '/api/state')]);
  } catch (e) {
    setStatus(statusBox, e.status === 404
      ? 'No such request. It may have expired, or the server restarted. Ask the requester to send a new one.'
      : describeError(e), 'error');
    return;
  }

  $('#r-secret').textContent = req.secret;
  $('#r-site').textContent = req.item?.site || 'Not set';
  $('#r-account').textContent = req.item?.account || 'Not set';
  $('#r-command').textContent = req.command;
  $('#request').hidden = false;

  if (req.status !== 'pending') { close(FINAL[req.status] ?? req.status); return; }
  startCountdown(req.expires_in, (Date.parse(req.expires_at) - Date.parse(req.created_at)) / 1000);

  // Check again on this device before any passkey prompt; the server is not trusted for this.
  const problems = [];
  const commandProblem = validateCommand(req.command);
  if (commandProblem) problems.push(commandProblem);
  if (!req.item || req.item.name !== req.secret) problems.push('the vault has no secret with this name');
  const pubDer = b64urlDecode(req.pubkey);
  let pubKey = null;
  try { pubKey = await importRequesterKey(pubDer); } catch (e) { problems.push(describeError(e)); }
  if (problems.length) {
    const w = $('#r-warning');
    w.textContent = `This request cannot be approved: ${problems.join('; ')}.`;
    w.hidden = false;
    $('#b-approve').hidden = true;
  }

  const buttons = [$('#b-approve'), $('#b-deny')];

  $('#b-approve').addEventListener('click', () => busy(buttons, async () => {
    setStatus(statusBox, 'Waiting for your passkey…');
    let plaintext = null;
    try {
      // The challenge is computed from what is on screen, not taken from the server.
      const challenge = await approveChallenge(req.id, req.secret, req.command, pubDer);
      const { assertion, masterKey } = await signAndUnlock(state, challenge);
      plaintext = await decryptItem(masterKey, {
        name: req.secret, site: req.item.site, account: req.item.account,
        iv: b64urlDecode(req.item.iv), ct: b64urlDecode(req.item.ct),
      });
      const ciphertext = await rsaEncryptForRequester(pubKey, oaepLabel(req.id, req.command, pubDer), plaintext);
      await api('POST', `/api/requests/${req.id}/approve`, { assertion, ciphertext: b64urlEncode(ciphertext) });
      close('Approved. The requester can collect it once, for this command only.', 'ok');
    } catch (e) {
      if (e.code === 'not_pending' || e.status === 404) close(describeError(e), 'error');
      else setStatus(statusBox, describeError(e), 'error');
    } finally {
      plaintext?.fill(0);
    }
  }));

  $('#b-deny').addEventListener('click', () => busy(buttons, async () => {
    try {
      await api('POST', `/api/requests/${req.id}/deny`, {});
      close('Denied. The requester has been told.', 'ok');
    } catch (e) {
      setStatus(statusBox, describeError(e), 'error');
    }
  }));
}

main();
