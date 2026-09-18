// Minimal CBOR codec covering what the Jade RPC protocol uses:
// unsigned/negative ints, byte strings, text strings, arrays, maps, bool, null.
// Decoding also tolerates floats and returns how many bytes it consumed, so the
// serial reader can pull one message at a time out of a stream buffer.

const te = new TextEncoder();
const td = new TextDecoder();

function header(major, n) {
  if (n < 24) return [major << 5 | n];
  if (n < 0x100) return [major << 5 | 24, n];
  if (n < 0x10000) return [major << 5 | 25, n >> 8, n & 0xff];
  if (n < 0x100000000) return [major << 5 | 26, n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
  const hi = Math.floor(n / 0x100000000), lo = n >>> 0;
  return [major << 5 | 27, hi >>> 24, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff,
          lo >>> 24, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff];
}

function encodeInto(out, v) {
  if (v === null || v === undefined) return out.push(0xf6);
  if (v === true) return out.push(0xf5);
  if (v === false) return out.push(0xf4);
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new Error('cbor: floats not supported');
    if (v >= 0) return out.push(...header(0, v));
    return out.push(...header(1, -1 - v));
  }
  if (typeof v === 'string') {
    const b = te.encode(v);
    out.push(...header(3, b.length));
    for (const x of b) out.push(x);
    return;
  }
  if (v instanceof Uint8Array || v instanceof ArrayBuffer) {
    const b = v instanceof ArrayBuffer ? new Uint8Array(v) : v;
    out.push(...header(2, b.length));
    for (const x of b) out.push(x);
    return;
  }
  if (Array.isArray(v)) {
    out.push(...header(4, v.length));
    for (const x of v) encodeInto(out, x);
    return;
  }
  if (typeof v === 'object') {
    const keys = Object.keys(v).filter(k => v[k] !== undefined);
    out.push(...header(5, keys.length));
    for (const k of keys) { encodeInto(out, k); encodeInto(out, v[k]); }
    return;
  }
  throw new Error('cbor: unsupported value ' + typeof v);
}

export function encode(v) {
  const out = [];
  encodeInto(out, v);
  return Uint8Array.from(out);
}

class Incomplete extends Error {}

class Reader {
  constructor(buf) { this.buf = buf; this.pos = 0; }
  need(n) { if (this.pos + n > this.buf.length) throw new Incomplete(); }
  u8() { this.need(1); return this.buf[this.pos++]; }
  bytes(n) { this.need(n); const b = this.buf.subarray(this.pos, this.pos + n); this.pos += n; return b; }
  len(info) {
    if (info < 24) return info;
    if (info === 24) return this.u8();
    if (info === 25) { const b = this.bytes(2); return (b[0] << 8) | b[1]; }
    if (info === 26) { const b = this.bytes(4); return ((b[0] << 24) >>> 0) + (b[1] << 16) + (b[2] << 8) + b[3]; }
    if (info === 27) {
      const b = this.bytes(8);
      let n = 0;
      for (const x of b) n = n * 256 + x;
      return n;
    }
    throw new Error('cbor: indefinite lengths not supported');
  }
  item() {
    const ib = this.u8();
    const major = ib >> 5, info = ib & 0x1f;
    switch (major) {
      case 0: return this.len(info);
      case 1: return -1 - this.len(info);
      case 2: return new Uint8Array(this.bytes(this.len(info)));
      case 3: return td.decode(this.bytes(this.len(info)));
      case 4: { const n = this.len(info); const a = []; for (let i = 0; i < n; i++) a.push(this.item()); return a; }
      case 5: { const n = this.len(info); const o = {}; for (let i = 0; i < n; i++) { const k = this.item(); o[k] = this.item(); } return o; }
      case 6: { this.len(info); return this.item(); } // tag: ignore
      case 7: {
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22 || info === 23) return null;
        if (info === 25) { const b = this.bytes(2); return halfToFloat((b[0] << 8) | b[1]); }
        if (info === 26) return new DataView(this.bytes(4).slice().buffer).getFloat32(0);
        if (info === 27) return new DataView(this.bytes(8).slice().buffer).getFloat64(0);
        if (info < 24) return info; // simple value
        if (info === 24) return this.u8();
        throw new Error('cbor: bad simple/float');
      }
    }
    throw new Error('cbor: bad major type');
  }
}

function halfToFloat(h) {
  const s = (h & 0x8000) ? -1 : 1, e = (h >> 10) & 0x1f, f = h & 0x3ff;
  if (e === 0) return s * Math.pow(2, -14) * (f / 1024);
  if (e === 31) return f ? NaN : s * Infinity;
  return s * Math.pow(2, e - 15) * (1 + f / 1024);
}

// Decode exactly one item. Returns {value, length} or null if the buffer does
// not yet hold a complete item.
export function decodeFirst(buf) {
  const r = new Reader(buf);
  try {
    const value = r.item();
    return { value, length: r.pos };
  } catch (e) {
    if (e instanceof Incomplete) return null;
    throw e;
  }
}

export function decode(buf) {
  const res = decodeFirst(buf);
  if (!res) throw new Error('cbor: truncated');
  return res.value;
}
