// OpenPGP building blocks for a Jade-backed P-256 identity.
// Mirrors the packet layout produced by trezor-agent's `jade-agent` so a key
// created here with the same user ID and timestamp is byte-identical to one
// created on the command line. Pure JS + WebCrypto; no openpgp.js dependency.

const te = new TextEncoder();
const td = new TextDecoder();
const subtle = globalThis.crypto.subtle;

export const P256_OID = Uint8Array.from([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]);
export const ALGO_ECDSA = 19;
export const ALGO_ECDH = 18;
export const HASH_SHA256 = 8;
export const KDF_PARAMS = Uint8Array.from([0x03, 0x01, 0x08, 0x07]); // SHA-256, AES-128 key wrap
export const CUSTOM_LABEL = te.encode('TREZOR-GPG'); // marker subpacket used by trezor-agent

// ---------- byte helpers ----------
export function concat(...arrs) {
  let n = 0;
  for (const a of arrs) n += a.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
export function u8(n) { return Uint8Array.from([n & 0xff]); }
export function u16(n) { return Uint8Array.from([(n >> 8) & 0xff, n & 0xff]); }
export function u32(n) { return Uint8Array.from([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]); }
export function hex(b) { return Array.from(b, x => x.toString(16).padStart(2, '0')).join(''); }
export function fromHex(s) {
  s = s.replace(/\s+/g, '');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}
export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
export async function sha256(b) { return new Uint8Array(await subtle.digest('SHA-256', b)); }
export async function sha1(b) { return new Uint8Array(await subtle.digest('SHA-1', b)); }

// ---------- packet framing (RFC 4880) ----------
// Old-format header, as trezor-agent writes it.
export function packet(tag, body) {
  let lt, len;
  if (body.length < 0x100) { lt = 0; len = u8(body.length); }
  else if (body.length < 0x10000) { lt = 1; len = u16(body.length); }
  else { lt = 2; len = u32(body.length); }
  return concat(u8(0x80 | (tag << 2) | lt), len, body);
}

export function subpacket(type, body) { return concat(u8(type), body); }
export function subpacketTime(t) { return subpacket(2, u32(t)); }
export function subpacketByte(type, v) { return subpacket(type, u8(v)); }
export function subpacketBytes(type, vals) { return subpacket(type, Uint8Array.from(vals)); }

function subpacketLenPrefix(n) {
  if (n < 192) return u8(n);
  if (n < 8384) { n -= 192; return Uint8Array.from([(n >> 8) + 192, n & 0xff]); }
  return concat(u8(255), u32(n));
}
export function subpackets(list) {
  const items = list.map(sp => concat(subpacketLenPrefix(sp.length), sp));
  const body = concat(...items);
  return concat(u16(body.length), body);
}

// MPI from a big-endian byte string (leading zero bytes stripped).
export function mpi(bytes) {
  let i = 0;
  while (i < bytes.length && bytes[i] === 0) i++;
  const b = bytes.subarray(i);
  if (b.length === 0) return u16(0);
  const bits = (b.length - 1) * 8 + (32 - Math.clz32(b[0]));
  return concat(u16(bits), b);
}

// ---------- public key packets ----------
// point: 65-byte uncompressed P-256 point (0x04 || x || y), exactly as Jade returns it.
export function publicKeyBody({ created, point, ecdh }) {
  const header = concat(u8(4), u32(created), u8(ecdh ? ALGO_ECDH : ALGO_ECDSA));
  const oid = concat(u8(P256_OID.length), P256_OID);
  return concat(header, oid, mpi(point), ecdh ? KDF_PARAMS : new Uint8Array(0));
}
export function keyDataToHash(body) { return concat(u8(0x99), u16(body.length), body); }
export async function fingerprint(body) { return sha1(keyDataToHash(body)); }
export async function keyId(body) { return (await fingerprint(body)).slice(12); }

// ---------- signatures ----------
// signFn(digest32) -> {r: Uint8Array(32), s: Uint8Array(32)}
export async function makeSignature({ signFn, dataToSign, pubAlgo, hashed, unhashed, sigType }) {
  const header = concat(u8(4), u8(sigType), u8(pubAlgo), u8(HASH_SHA256));
  const hashedBlk = subpackets(hashed);
  const unhashedBlk = subpackets(unhashed);
  const trailer = concat(Uint8Array.from([0x04, 0xff]), u32(header.length + hashedBlk.length));
  const digest = await sha256(concat(dataToSign, header, hashedBlk, trailer));
  const { r, s } = await signFn(digest);
  return concat(header, hashedBlk, unhashedBlk, digest.slice(0, 2), mpi(r), mpi(s));
}

export async function createPrimary({ userId, created, point, signFn }) {
  const body = publicKeyBody({ created, point, ecdh: false });
  const uid = te.encode(userId);
  const dataToSign = concat(keyDataToHash(body), u8(0xb4), u32(uid.length), uid);
  const hashed = [
    subpacketTime(created),
    subpacketByte(0x0B, 9),            // preferred symmetric: AES-256
    subpacketByte(0x1B, 1 | 2),        // key flags: certify + sign
    subpacketBytes(0x15, [8, 9, 10]),  // preferred hash: SHA-256/384/512
    subpacketBytes(0x16, [2, 3, 1]),   // preferred compression
    subpacketByte(0x17, 0x80),         // keyserver prefs: no-modify
    subpacketByte(0x1E, 0x01),         // features: MDC
  ];
  const unhashed = [subpacket(16, await keyId(body)), subpacket(26, CUSTOM_LABEL)];
  const sig = await makeSignature({ signFn, dataToSign, pubAlgo: ALGO_ECDSA, hashed, unhashed, sigType: 0x13 });
  return concat(packet(6, body), packet(13, uid), packet(2, sig));
}

export async function createEncryptionSubkey({ primaryBody, created, point, signFn }) {
  const body = publicKeyBody({ created, point, ecdh: true });
  const dataToSign = concat(keyDataToHash(primaryBody), keyDataToHash(body));
  const hashed = [subpacketTime(created), subpacketByte(0x1B, 4 | 8)]; // encrypt comms + storage
  const unhashed = [subpacket(16, await keyId(primaryBody)), subpacket(26, CUSTOM_LABEL)];
  const sig = await makeSignature({ signFn, dataToSign, pubAlgo: ALGO_ECDSA, hashed, unhashed, sigType: 0x18 });
  return concat(packet(14, body), packet(2, sig));
}

// Build a full public key block: primary (sign/certify) + ECDH subkey (encrypt).
// jade: { pubkey(type), sign(digest) } where type is 'slip-0013' | 'slip-0017'
export async function buildPublicKey({ userId, created, signingPoint, encryptionPoint, signFn }) {
  const primaryBody = publicKeyBody({ created, point: signingPoint, ecdh: false });
  const primary = await createPrimary({ userId, created, point: signingPoint, signFn });
  const sub = await createEncryptionSubkey({ primaryBody, created, point: encryptionPoint, signFn });
  const subBody = publicKeyBody({ created, point: encryptionPoint, ecdh: true });
  return {
    bytes: concat(primary, sub),
    primaryFingerprint: await fingerprint(primaryBody),
    subkeyFingerprint: await fingerprint(subBody),
  };
}

// ---------- ASCII armor ----------
const CRC24_INIT = 0xB704CE, CRC24_POLY = 0x1864CFB;
export function crc24(bytes) {
  let crc = CRC24_INIT;
  for (const b of bytes) {
    crc ^= b << 16;
    for (let i = 0; i < 8; i++) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= CRC24_POLY;
    }
  }
  return crc & 0xFFFFFF;
}
function b64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
function unb64(s) {
  const bin = atob(s.replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export function armor(bytes, type) {
  const body = b64(bytes).replace(/(.{64})/g, '$1\n').replace(/\n$/, '');
  const c = crc24(bytes);
  const crc = b64(Uint8Array.from([(c >> 16) & 0xff, (c >> 8) & 0xff, c & 0xff]));
  return `-----BEGIN PGP ${type}-----\n\n${body}\n=${crc}\n-----END PGP ${type}-----\n`;
}
export function dearmor(text) {
  const m = /-----BEGIN PGP ([A-Z ]+)-----\r?\n([\s\S]*?)-----END PGP \1-----/.exec(text);
  if (!m) throw new Error('No PGP armored block found');
  const type = m[1];
  const lines = m[2].split(/\r?\n/);
  let i = 0;
  while (i < lines.length && lines[i].trim() !== '') i++; // skip armor headers
  const dataLines = [], crcLines = [];
  for (const line of lines.slice(i + 1)) {
    const t = line.trim();
    if (!t) continue;
    if (t.startsWith('=')) crcLines.push(t.slice(1)); else dataLines.push(t);
  }
  const data = unb64(dataLines.join(''));
  if (crcLines.length) {
    const c = unb64(crcLines[0]);
    const want = (c[0] << 16) | (c[1] << 8) | c[2];
    if (crc24(data) !== want) throw new Error('Armor checksum mismatch');
  }
  return { type, data };
}
export function isArmored(text) { return /-----BEGIN PGP [A-Z ]+-----/.test(text); }

// ---------- parsing ----------
export function parsePackets(buf) {
  const out = [];
  let p = 0;
  const be32 = () => { const v = ((buf[p] << 24) >>> 0) + (buf[p + 1] << 16) + (buf[p + 2] << 8) + buf[p + 3]; p += 4; return v; };
  while (p < buf.length) {
    const start = p;
    const b0 = buf[p++];
    if (!(b0 & 0x80)) throw new Error('Bad packet header');
    let tag, body;
    if (b0 & 0x40) { // new format
      tag = b0 & 0x3f;
      const chunks = [];
      for (;;) {
        const l1 = buf[p++];
        let len, partial = false;
        if (l1 < 192) len = l1;
        else if (l1 < 224) len = ((l1 - 192) << 8) + buf[p++] + 192;
        else if (l1 === 255) len = be32();
        else { len = 1 << (l1 & 0x1f); partial = true; }
        chunks.push(buf.subarray(p, p + len));
        p += len;
        if (!partial) break;
      }
      body = chunks.length === 1 ? chunks[0] : concat(...chunks);
    } else {
      tag = (b0 >> 2) & 0x0f;
      const lt = b0 & 3;
      let len;
      if (lt === 0) len = buf[p++];
      else if (lt === 1) { len = (buf[p] << 8) | buf[p + 1]; p += 2; }
      else if (lt === 2) len = be32();
      else throw new Error('Indeterminate packet length not supported');
      body = buf.subarray(p, p + len);
      p += len;
    }
    out.push({ tag, body, start, end: p });
  }
  return out;
}

function readMpi(buf, p) {
  const bits = (buf[p] << 8) | buf[p + 1];
  const n = (bits + 7) >> 3;
  return { bytes: buf.subarray(p + 2, p + 2 + n), next: p + 2 + n };
}

export function parseKeyPacket(body) {
  const version = body[0];
  if (version !== 4) throw new Error(`Unsupported key packet version ${version}`);
  const created = ((body[1] << 24) >>> 0) + (body[2] << 16) + (body[3] << 8) + body[4];
  const algo = body[5];
  const res = { version, created, algo, body };
  if (algo === ALGO_ECDSA || algo === ALGO_ECDH) {
    const oidLen = body[6];
    res.oid = body.subarray(7, 7 + oidLen);
    const m = readMpi(body, 7 + oidLen);
    res.point = m.bytes;
    if (algo === ALGO_ECDH) {
      const kl = body[m.next];
      res.kdf = body.subarray(m.next + 1, m.next + 1 + kl);
    }
  }
  return res;
}

// Parse an (armored or binary) public key block into primary, user IDs and subkeys.
export async function parsePublicKey(input) {
  const bytes = typeof input === 'string' ? dearmor(input).data : input;
  const packets = parsePackets(bytes);
  const res = { userIds: [], subkeys: [] };
  for (const pk of packets) {
    if (pk.tag === 6) {
      if (res.primary) break; // second key in block: ignore
      res.primary = parseKeyPacket(pk.body);
      res.primary.fingerprint = await fingerprint(pk.body);
    } else if (pk.tag === 13) {
      res.userIds.push(td.decode(pk.body));
    } else if (pk.tag === 14) {
      const k = parseKeyPacket(pk.body);
      k.fingerprint = await fingerprint(pk.body);
      res.subkeys.push(k);
    }
  }
  if (!res.primary) throw new Error('No public key packet found');
  return res;
}

// ---------- ECDH decryption (RFC 6637) ----------
// Parse a v3 public-key encrypted session key packet.
export function parsePkesk(body) {
  if (body[0] !== 3) throw new Error(`Unsupported PKESK version ${body[0]}`);
  const keyIdBytes = body.subarray(1, 9);
  const algo = body[9];
  const res = { version: 3, keyId: hex(keyIdBytes).toUpperCase(), algo };
  if (algo === ALGO_ECDH) {
    const m = readMpi(body, 10);
    res.ephemeral = m.bytes;              // 0x04 || x || y
    const cl = body[m.next];
    res.wrapped = body.subarray(m.next + 1, m.next + 1 + cl);
  }
  return res;
}

export function findPkesks(messageBytes) {
  return parsePackets(messageBytes).filter(p => p.tag === 1).map(p => parsePkesk(p.body));
}

// KEK = SHA-256(0x00000001 || Z || params)[0:16], params per RFC 6637 section 8.
export async function deriveKek(sharedX, subkeyFingerprint) {
  const params = concat(u8(P256_OID.length), P256_OID, u8(ALGO_ECDH), KDF_PARAMS,
                        te.encode('Anonymous Sender    '), subkeyFingerprint);
  const h = await sha256(concat(u32(1), sharedX, params));
  return h.slice(0, 16);
}

// AES-128 key unwrap (RFC 3394) via WebCrypto. WebCrypto will only unwrap into a
// CryptoKey, so we unwrap into an extractable HMAC key and export it.
export async function aesUnwrap(kekBytes, wrapped) {
  const kek = await subtle.importKey('raw', kekBytes, 'AES-KW', false, ['unwrapKey']);
  const k = await subtle.unwrapKey('raw', wrapped, kek, 'AES-KW',
    { name: 'HMAC', hash: 'SHA-256', length: (wrapped.length - 8) * 8 }, true, ['sign']);
  return new Uint8Array(await subtle.exportKey('raw', k));
}

// Returns {algo, key} for the symmetric session key.
export async function unwrapSessionKey(sharedX, subkeyFingerprint, wrapped) {
  const kek = await deriveKek(sharedX, subkeyFingerprint);
  const m = await aesUnwrap(kek, wrapped);
  const pad = m[m.length - 1];
  if (pad < 1 || pad > 8 || pad > m.length - 3) throw new Error('Bad session key padding');
  for (let i = m.length - pad; i < m.length; i++) if (m[i] !== pad) throw new Error('Bad session key padding');
  const algo = m[0];
  const key = m.slice(1, m.length - pad - 2);
  const want = (m[m.length - pad - 2] << 8) | m[m.length - pad - 1];
  let sum = 0;
  for (const b of key) sum = (sum + b) & 0xffff;
  if (sum !== want) throw new Error('Session key checksum mismatch');
  return { algo, key };
}

export const SYMMETRIC_NAMES = { 7: 'aes128', 8: 'aes192', 9: 'aes256', 3: 'cast5', 2: 'tripledes', 4: 'blowfish', 10: 'twofish' };

// ---------- ECDH encryption (RFC 6637), mirror of the decrypt path ----------
// AES-128 key wrap via WebCrypto: import the padded payload as an HMAC key and
// wrap it, the counterpart of aesUnwrap above.
export async function aesWrap(kekBytes, payload) {
  const kek = await subtle.importKey('raw', kekBytes, 'AES-KW', false, ['wrapKey']);
  const k = await subtle.importKey('raw', payload, { name: 'HMAC', hash: 'SHA-256' }, true, ['sign']);
  return new Uint8Array(await subtle.wrapKey('raw', k, kek, 'AES-KW'));
}

// Build a v3 public-key encrypted session key packet body for a P-256 ECDH
// recipient given by its public point and key fingerprint.
export async function makePkesk({ recipientPoint, recipientFingerprint, algo, sessionKey }) {
  const eph = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const ephemeral = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));
  const theirs = await subtle.importKey('raw', recipientPoint, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const sharedX = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: theirs }, eph.privateKey, 256));
  const kek = await deriveKek(sharedX, recipientFingerprint);
  let sum = 0;
  for (const b of sessionKey) sum = (sum + b) & 0xffff;
  const m = concat(u8(algo), sessionKey, u16(sum));
  const pad = 8 - (m.length % 8);
  const padded = concat(m, new Uint8Array(pad).fill(pad));
  const wrapped = await aesWrap(kek, padded);
  const body = concat(u8(3), recipientFingerprint.slice(12), u8(ALGO_ECDH), mpi(ephemeral), u8(wrapped.length), wrapped);
  return packet(1, body);
}
