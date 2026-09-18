// Software stand-in for Jade's identity API, derived from the firmware's own
// test seed (TEST_MNEMONIC in Jade's test_jade.py). Implements SLIP-0013/0017
// derivation on nist256p1, RFC 6979 ECDSA over a raw digest, and ECDH.
// Test-only: real users never see private keys; this exists so the OpenPGP
// layer can be checked against the firmware's published test vectors.
import crypto from 'node:crypto';

// BIP39 seed of TEST_MNEMONIC_12_IDENTITY from Jade's test_jade.py (the SLIP-0013 reference mnemonic), no passphrase.
export const TEST_MNEMONIC = 'alcohol woman abuse must during monitor noble actual mixed trade anger aisle';
export const TEST_SEED = crypto.pbkdf2Sync(TEST_MNEMONIC.normalize('NFKD'), 'mnemonic', 2048, 64, 'sha512');

// ---- P-256 arithmetic (bigint) ----
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const A = P - 3n;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const G = [0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
           0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n];
const mod = (a, m = P) => ((a % m) + m) % m;
function inv(a, m = P) { // extended euclid
  let [r0, r1] = [m, mod(a, m)], [s0, s1] = [0n, 1n];
  while (r1 !== 0n) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
  if (r0 !== 1n) throw new Error('not invertible');
  return mod(s0, m);
}
function add(p, q) {
  if (!p) return q; if (!q) return p;
  const [x1, y1] = p, [x2, y2] = q;
  if (x1 === x2) { if (mod(y1 + y2) === 0n) return null; return dbl(p); }
  const l = mod((y2 - y1) * inv(x2 - x1));
  const x3 = mod(l * l - x1 - x2);
  return [x3, mod(l * (x1 - x3) - y1)];
}
function dbl(p) {
  const [x, y] = p;
  const l = mod((3n * x * x + A) * inv(2n * y));
  const x3 = mod(l * l - 2n * x);
  return [x3, mod(l * (x - x3) - y)];
}
function mul(k, p) { let r = null, q = p; while (k > 0n) { if (k & 1n) r = add(r, q); q = dbl(q); k >>= 1n; } return r; }
const toBig = b => BigInt('0x' + Buffer.from(b).toString('hex'));
const to32 = n => Buffer.from(n.toString(16).padStart(64, '0'), 'hex');
const pointBytes = p => Buffer.concat([Buffer.from([4]), to32(p[0]), to32(p[1])]);
function pointFromBytes(b) { if (b[0] !== 4 || b.length !== 65) throw new Error('need uncompressed point'); return [toBig(b.subarray(1, 33)), toBig(b.subarray(33))]; }

// ---- BIP32 on nist256p1, hardened only (as Jade does) ----
const hmac512 = (key, data) => crypto.createHmac('sha512', key).update(data).digest();
function master(seed) { const I = hmac512(Buffer.from('Nist256p1 seed'), seed); return { k: toBig(I.subarray(0, 32)), c: I.subarray(32) }; }
function child(parent, idx) {
  const data = Buffer.concat([Buffer.from([0]), to32(parent.k), Buffer.from([(idx >>> 24) & 0xff, (idx >>> 16) & 0xff, (idx >>> 8) & 0xff, idx & 0xff])]);
  const I = hmac512(parent.c, data);
  return { k: mod(toBig(I.subarray(0, 32)) + parent.k, N), c: I.subarray(32) };
}
function identityPath(prefix, identity, index) {
  const h = crypto.createHash('sha256').update(Buffer.from([index & 0xff, (index >> 8) & 0xff, (index >> 16) & 0xff, (index >>> 24) & 0xff])).update(Buffer.from(identity, 'utf8')).digest();
  const le = o => (h[o] | (h[o + 1] << 8) | (h[o + 2] << 16) | (h[o + 3] << 24)) >>> 0;
  return [prefix, le(0), le(4), le(8), le(12)].map(v => (v | 0x80000000) >>> 0);
}
function privFor(seed, prefix, identity, index) {
  let node = master(seed);
  for (const i of identityPath(prefix, identity, index)) node = child(node, i);
  return node.k;
}

// ---- RFC 6979 deterministic ECDSA (SHA-256, raw 32-byte digest) ----
function rfc6979k(priv, digest) {
  const hm = (k, d) => crypto.createHmac('sha256', k).update(d).digest();
  const x = to32(priv), h1 = Buffer.from(digest);
  let V = Buffer.alloc(32, 1), K = Buffer.alloc(32, 0);
  K = hm(K, Buffer.concat([V, Buffer.from([0]), x, h1])); V = hm(K, V);
  K = hm(K, Buffer.concat([V, Buffer.from([1]), x, h1])); V = hm(K, V);
  for (;;) {
    V = hm(K, V);
    const k = toBig(V);
    if (k >= 1n && k < N) return k;
    K = hm(K, Buffer.concat([V, Buffer.from([0])])); V = hm(K, V);
  }
}
function ecdsaSign(priv, digest) {
  const z = toBig(digest);
  for (;;) {
    const k = rfc6979k(priv, digest);
    const R = mul(k, G);
    const r = mod(R[0], N);
    if (r === 0n) continue;
    let s = mod(inv(k, N) * (z + r * priv), N);
    if (s === 0n) continue;
    if (s > N / 2n) s = N - s; // low-s, as the firmware emits
    return { r: to32(r), s: to32(s) };
  }
}

export class SoftJade {
  constructor(seed = TEST_SEED) { this.seed = seed; this.prompts = []; }
  async get_identity_pubkey(identity, curve, type, index = 0) {
    const prefix = type === 'slip-0017' ? 17 : 13;
    return new Uint8Array(pointBytes(mul(privFor(this.seed, prefix, identity, index), G)));
  }
  async sign_identity(identity, curve, challenge, index = 0) {
    this.prompts.push({ op: 'sign', identity });
    const priv = privFor(this.seed, 13, identity, index);
    const digest = identity.startsWith('ssh://') ? crypto.createHash('sha256').update(challenge).digest() : challenge;
    const { r, s } = ecdsaSign(priv, digest);
    return { signature: new Uint8Array(Buffer.concat([Buffer.from([0]), r, s])), pubkey: new Uint8Array(pointBytes(mul(priv, G))) };
  }
  async get_identity_shared_key(identity, curve, theirPubkey, index = 0) {
    this.prompts.push({ op: 'ecdh', identity });
    const priv = privFor(this.seed, 17, identity, index);
    const S = mul(priv, pointFromBytes(theirPubkey));
    return new Uint8Array(to32(S[0]));
  }
}
