// Jade over Web Serial: CBOR-RPC framing, request/response matching, and the
// unlock (auth_user) flow that relays the blind pinserver handshake.
import { encode, decodeFirst } from './cbor.js';

export const SERIAL_FILTERS = [
  { usbVendorId: 0x10c4, usbProductId: 0xea60 }, // CP210x (Jade 1.0)
  { usbVendorId: 0x1a86, usbProductId: 0x55d4 }, // CH9102F (Jade 1.1)
  { usbVendorId: 0x303a, usbProductId: 0x4001 }, // ESP32-S3 native USB (Jade Plus / Core)
];

// Pinserver origins the device is allowed to ask us to relay to. Anything else
// gets surfaced to the user before we forward a single byte.
export const PINSERVER_WHITELIST = [
  'https://jadepin.blockstream.com',
  'https://j8d.io',
  'https://jadefw.blockstream.com',
  'http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion',
  'http://vgza7wu4h7osixmrx6e4op5r72okqpagr3w6oupgsvmim4cz3wzdgrad.onion',
];

export class JadeError extends Error {
  constructor(message, code, data) { super(message); this.code = code; this.data = data; }
}
export const USER_CANCELLED = -32000; // CBOR_RPC_USER_CANCELLED
export const HW_LOCKED = -32002;      // CBOR_RPC_HW_LOCKED: device locked itself (idle timeout) or is uninitialised
export const isLocked = e => e instanceof JadeError && e.code === HW_LOCKED;

export function webSerialSupported() {
  return typeof navigator !== 'undefined' && !!navigator.serial;
}

export class JadeSerial {
  constructor({ onLog } = {}) {
    this.port = null;
    this.reader = null;
    this.writer = null;
    this.pending = new Map();
    this.buf = new Uint8Array(0);
    this.nextId = 1;
    this.onLog = onLog || (() => {});
    this.closed = true;
  }

  async connect({ reuse = true } = {}) {
    if (!webSerialSupported()) throw new Error('Web Serial is not available in this browser. Use Chrome, Edge or Brave on desktop.');
    let port = null;
    if (reuse) {
      const ports = await navigator.serial.getPorts();
      if (ports.length === 1) port = ports[0];
    }
    if (!port) port = await navigator.serial.requestPort({ filters: SERIAL_FILTERS });
    await port.open({ baudRate: 115200 });
    this.port = port;
    this.reader = port.readable.getReader();
    this.writer = port.writable.getWriter();
    this.closed = false;
    this.readLoop();
    const info = port.getInfo();
    return { usbVendorId: info.usbVendorId, usbProductId: info.usbProductId };
  }

  async disconnect() {
    this.closed = true;
    try { await this.reader?.cancel(); } catch {}
    try { this.reader?.releaseLock(); } catch {}
    try { this.writer?.releaseLock(); } catch {}
    try { await this.port?.close(); } catch {}
    for (const [, p] of this.pending) p.reject(new Error('Disconnected'));
    this.pending.clear();
    this.port = this.reader = this.writer = null;
  }

  async readLoop() {
    try {
      while (!this.closed) {
        const { value, done } = await this.reader.read();
        if (done) break;
        this.append(value);
        this.drain();
      }
    } catch (e) {
      if (!this.closed) {
        for (const [, p] of this.pending) p.reject(new Error('Serial read failed: ' + e.message));
        this.pending.clear();
      }
    }
  }

  append(chunk) {
    const b = new Uint8Array(this.buf.length + chunk.length);
    b.set(this.buf); b.set(chunk, this.buf.length);
    this.buf = b;
  }

  drain() {
    for (;;) {
      let res;
      try { res = decodeFirst(this.buf); }
      catch (e) { // garbage: skip a byte and resync
        this.buf = this.buf.subarray(1);
        continue;
      }
      if (!res) return;
      this.buf = this.buf.subarray(res.length);
      this.dispatch(res.value);
    }
  }

  dispatch(msg) {
    if (!msg || typeof msg !== 'object') return;
    if ('log' in msg) {
      try { this.onLog(new TextDecoder().decode(msg.log)); } catch {}
      return;
    }
    const p = this.pending.get(msg.id);
    if (!p) return;
    this.pending.delete(msg.id);
    if ('error' in msg) p.reject(new JadeError(msg.error.message || 'Jade error', msg.error.code, msg.error.data));
    else p.resolve(msg.result);
  }

  request(method, params, { timeoutMs = 0 } = {}) {
    const id = String(this.nextId++);
    const msg = { id, method };
    if (params !== undefined) msg.params = params;
    return new Promise((resolve, reject) => {
      let timer = null;
      if (timeoutMs) timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`${method} timed out`)); }, timeoutMs);
      this.pending.set(id, {
        resolve: v => { if (timer) clearTimeout(timer); resolve(v); },
        reject: e => { if (timer) clearTimeout(timer); reject(e); },
      });
      this.writer.write(encode(msg)).catch(e => { this.pending.delete(id); reject(e); });
    });
  }

  // ---- API ----
  getVersionInfo() { return this.request('get_version_info', undefined, { timeoutMs: 5000 }); }

  // Unlock the device. The device may hand back http_request instructions to
  // relay to the pinserver; we forward them (whitelisted origins only unless
  // confirmOrigin(url) returns true) and pass the reply back until we get a
  // boolean result.
  async unlock({ network = 'mainnet', confirmOrigin = null, onStatus = () => {} } = {}) {
    let res = await this.request('auth_user', { network, epoch: Math.floor(Date.now() / 1000) });
    for (;;) {
      if (res === true) return true;
      if (res === false) return false;
      const req = res && res.http_request;
      if (!req) throw new Error('Unexpected auth_user reply');
      const urls = req.params.urls || [];
      const url = urls.find(u => PINSERVER_WHITELIST.includes(new URL(u).origin)) || urls[0];
      if (!url) throw new Error('Device requested a pinserver relay with no URL');
      if (!PINSERVER_WHITELIST.includes(new URL(url).origin)) {
        const ok = confirmOrigin ? await confirmOrigin(url) : false;
        if (!ok) throw new Error('Refused to relay to a non-Blockstream pinserver: ' + new URL(url).origin);
      }
      onStatus(`Contacting ${new URL(url).host}`);
      const method = (req.params.method || 'POST').toUpperCase();
      const resp = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json', 'Accept': req.params.accept || 'application/json' },
        body: method === 'POST' ? JSON.stringify(req.params.data) : undefined,
      });
      if (!resp.ok) throw new Error(`Pinserver returned HTTP ${resp.status}`);
      const reply = await resp.json();
      onStatus('Enter your PIN on Jade');
      res = await this.request(req['on-reply'], reply);
    }
  }

  getIdentityPubkey(identity, type, index = 0) {
    return this.request('get_identity_pubkey', { identity, curve: 'nist256p1', type, index }, { timeoutMs: 15000 });
  }
  signIdentity(identity, challenge, index = 0) {
    return this.request('sign_identity', { identity, curve: 'nist256p1', challenge, index });
  }
  getIdentitySharedKey(identity, theirPubkey, index = 0) {
    return this.request('get_identity_shared_key', { identity, curve: 'nist256p1', their_pubkey: theirPubkey, index });
  }
}

export function networkFor(versionInfo) {
  return versionInfo && versionInfo.JADE_NETWORKS === 'TEST' ? 'testnet' : 'mainnet';
}
