// Page logic: connect Jade, then encrypt or decrypt dropped files.
import { JadeSerial, JadeError, USER_CANCELLED, isLocked, webSerialSupported, networkFor } from './jade.js';
import * as ops from './gpgops.js';

const $ = id => document.getElementById(id);
const show = (el, on = true) => el.classList.toggle('hidden', !on);
const state = { jade: null, unlocked: false, identity: null, network: 'mainnet' };

function log(msg) {
  const el = $('log');
  el.textContent += `${new Date().toLocaleTimeString()}  ${msg}\n`;
  el.scrollTop = el.scrollHeight;
}
function setStatus(id, text, kind = '') {
  const el = $(id);
  el.textContent = text;
  el.className = 'status' + (kind ? ' ' + kind : '');
}
function errText(e) {
  if (e instanceof JadeError && e.code === USER_CANCELLED) return 'Declined on Jade.';
  if (e && e.name === 'NotFoundError') return 'No device selected.';
  return e && e.message ? e.message : String(e);
}
function download(name, data) {
  const blob = new Blob([data], { type: 'application/octet-stream' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
const readFileBytes = file => new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(new Uint8Array(r.result)); r.onerror = () => rej(r.error); r.readAsArrayBuffer(file); });
const kb = n => (n / 1024).toFixed(1) + ' KB';

// ---------- connect ----------
async function connect() {
  setStatus('connect-status', 'Choose your Jade in the browser prompt', 'busy');
  const jade = new JadeSerial({ onLog: m => log('jade: ' + m.trim()) });
  try {
    const info = await jade.connect({ reuse: false });
    state.jade = jade;
    setStatus('connect-status', 'Connected, reading device info', 'busy');
    const vi = await jade.getVersionInfo();
    log(`connected ${vi.BOARD_TYPE} fw ${vi.JADE_VERSION} state ${vi.JADE_STATE} (${info.usbVendorId?.toString(16)}:${info.usbProductId?.toString(16)})`);
    $('device-info').textContent = `${vi.BOARD_TYPE || 'Jade'} · v${vi.JADE_VERSION}`;
    show($('device-info')); show($('btn-disconnect')); show($('btn-connect'), false);
    if (vi.JADE_STATE === 'UNINIT') throw new Error('This Jade has no wallet yet. Set it up in the Blockstream app first.');
    state.network = networkFor(vi);
    await unlockJade('connect-status');
    setStatus('connect-status', 'Reading your file key from Jade', 'busy');
    state.identity = await withUnlock(() => ops.loadIdentity(jade));
    state.unlocked = true;
    log('file key ' + state.identity.subkeyFingerprintHex);
    setStatus('connect-status', `Jade unlocked · file key ${state.identity.subkeyKeyId}`, 'ok');
    $('card-connect').classList.add('done');
    $('files-hint').textContent = 'Drop a file to encrypt it, or an encrypted file to decrypt it.';
  } catch (e) {
    log('connect error: ' + errText(e));
    setStatus('connect-status', errText(e), 'err');
    if (state.jade && !state.unlocked) await disconnect(true);
  }
}
// Run Jade's PIN flow. Used on connect and again whenever Jade reports that it
// locked itself (idle timeout) part-way through a session.
async function unlockJade(statusId) {
  setStatus(statusId, 'Enter your PIN on Jade', 'busy');
  const ok = await state.jade.unlock({
    network: state.network,
    onStatus: s => setStatus(statusId, s, 'busy'),
    confirmOrigin: async url => confirm(`Jade wants this page to relay its PIN handshake to a non-Blockstream server:\n\n${new URL(url).origin}\n\nOnly continue if you set a custom pinserver yourself.`),
  });
  if (!ok) throw new Error('Wrong PIN. Try again.');
}

// Run a Jade operation; if Jade has locked itself meanwhile, prompt for the
// PIN again and retry once.
async function withUnlock(fn, onRelock) {
  try { return await fn(); }
  catch (e) {
    if (!isLocked(e) || !state.jade) throw e;
    log('jade locked itself, asking for PIN again');
    onRelock?.();
    await unlockJade('connect-status');
    setStatus('connect-status', `Jade unlocked · file key ${state.identity?.subkeyKeyId || ''}`, 'ok');
    return await fn();
  }
}

async function disconnect(silent = false) {
  if (state.jade) { try { await state.jade.disconnect(); } catch {} }
  state.jade = null; state.unlocked = false; state.identity = null;
  show($('btn-disconnect'), false); show($('btn-connect')); show($('device-info'), false);
  $('card-connect').classList.remove('done');
  $('files-hint').textContent = 'Connect your Jade first.';
  if (!silent) setStatus('connect-status', 'Disconnected');
}

// ---------- files ----------
function resultRow(name, size) {
  const row = document.createElement('div');
  row.className = 'row between result-row';
  const left = document.createElement('div');
  left.innerHTML = `<div><strong class="fname"></strong> <span class="hint" style="margin:0">${kb(size)}</span></div><div class="status"></div>`;
  left.querySelector('.fname').textContent = name;
  const right = document.createElement('div'); right.className = 'row';
  row.append(left, right);
  $('results').prepend(row);
  show($('card-history'));
  return { row, status: left.querySelector('.status'), actions: right };
}
function setRowStatus(r, text, kind) { r.status.textContent = text; r.status.className = 'status' + (kind ? ' ' + kind : ''); }

async function handleFiles(files) {
  if (!state.unlocked) { setStatus('connect-status', 'Connect and unlock your Jade first', 'err'); return; }
  for (const file of files) await handleFile(file);
}
async function handleFile(file) {
  const r = resultRow(file.name, file.size);
  try {
    const bytes = await readFileBytes(file);
    if (ops.looksEncrypted(bytes)) {
      setRowStatus(r, 'Decrypting with Jade', 'busy');
      const res = await withUnlock(
        () => { setRowStatus(r, 'Decrypting with Jade', 'busy'); return ops.decryptFile({ jade: state.jade, identity: state.identity, bytes }); },
        () => setRowStatus(r, 'Jade locked itself. Enter your PIN on Jade, then it will retry', 'busy'));
      const outName = res.filename || file.name.replace(/\.(gpg|pgp|asc)$/i, '') || 'decrypted';
      setRowStatus(r, `Decrypted → ${outName} (${kb(res.data.length)})`, 'ok');
      addSave(r, outName, res.data);
      log(`decrypted ${file.name} → ${outName}`);
    } else {
      setRowStatus(r, 'Encrypting', 'busy');
      const out = await ops.encryptFile({ identity: state.identity, bytes, filename: file.name });
      const outName = file.name + '.gpg';
      setRowStatus(r, `Encrypted → ${outName} (${kb(out.length)})`, 'ok');
      addSave(r, outName, out);
      log(`encrypted ${file.name} → ${outName}`);
    }
  } catch (e) {
    log(`${file.name}: ${errText(e)}`);
    setRowStatus(r, errText(e), 'err');
  }
}
function addSave(r, name, data) {
  const b = document.createElement('button');
  b.className = 'small'; b.textContent = 'Save';
  b.onclick = () => download(name, data);
  r.actions.appendChild(b);
  download(name, data); // save immediately as well; the button is for re-saving
}

// ---------- wiring ----------
function init() {
  if (!webSerialSupported()) {
    const b = $('unsupported');
    b.textContent = window.isSecureContext
      ? 'This browser has no Web Serial support, so it cannot talk to Jade. Use Chrome, Edge or Brave on a desktop computer.'
      : 'Web Serial needs a secure page. Open this file directly from disk, or serve it over https or localhost.';
    show(b);
  }
  $('btn-connect').onclick = connect;
  $('btn-disconnect').onclick = () => disconnect();
  const drop = $('drop'), input = $('file-input');
  drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', e => { e.preventDefault(); drop.classList.remove('over'); handleFiles([...e.dataTransfer.files]); });
  input.addEventListener('change', () => { handleFiles([...input.files]); input.value = ''; });
  $('btn-clear-history').onclick = () => { $('results').innerHTML = ''; show($('card-history'), false); };
  if (navigator.serial) navigator.serial.addEventListener('disconnect', () => { if (state.jade) { log('device unplugged'); disconnect(); setStatus('connect-status', 'Jade was unplugged', 'err'); } });
  log(`ready · openpgp.js ${globalThis.openpgp?.config ? 'loaded' : 'MISSING'} · webserial ${webSerialSupported() ? 'yes' : 'no'} · secure ${window.isSecureContext}`);
}
init();
