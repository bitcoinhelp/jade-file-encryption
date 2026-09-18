// File encryption and decryption against a Jade-held key. `jade` is anything
// with getIdentityPubkey / getIdentitySharedKey (real device or test double).
import * as pgp from './pgp.js';

const openpgp = () => {
  if (!globalThis.openpgp) throw new Error('openpgp.js is not loaded');
  return globalThis.openpgp;
};

// One fixed identity for this page. Jade derives the key from the wallet seed
// plus this string, so the same wallet always yields the same key, and it is
// what Jade displays when asking you to confirm a decryption.
export const IDENTITY = 'gpg://Jade File Encryption';
export const CREATED = 0; // fixed creation time, as jade-agent defaults to

// Fetch the encryption key for this wallet. No confirmation on Jade.
export async function loadIdentity(jade) {
  const point = await jade.getIdentityPubkey(IDENTITY, 'slip-0017');
  const body = pgp.publicKeyBody({ created: CREATED, point, ecdh: true });
  const subkeyFingerprint = await pgp.fingerprint(body);
  return {
    identity: IDENTITY,
    point,
    subkeyFingerprint,
    subkeyFingerprintHex: pgp.hex(subkeyFingerprint).toUpperCase(),
    subkeyKeyId: pgp.hex(subkeyFingerprint.slice(12)).toUpperCase(),
  };
}

// Does this look like a PGP encrypted file (binary or armored)?
export function looksEncrypted(bytes) {
  try {
    const b = armoredToBinary(bytes);
    if (!b.length || !(b[0] & 0x80)) return false;
    return pgp.parsePackets(b).some(p => p.tag === 1 || p.tag === 3);
  } catch { return false; }
}

function armoredToBinary(bytes) {
  if (bytes.length && !(bytes[0] & 0x80) && bytes.length < 50_000_000) {
    const head = new TextDecoder().decode(bytes.subarray(0, 64));
    if (head.includes('-----BEGIN PGP')) return pgp.dearmor(new TextDecoder().decode(bytes)).data;
  }
  return bytes;
}

// Encrypt a file to our own key. No Jade confirmation needed.
export async function encryptFile({ identity, bytes, filename }) {
  const o = openpgp();
  const sessionKey = crypto.getRandomValues(new Uint8Array(32));
  const message = await o.createMessage({ binary: bytes, filename: filename || 'file' });
  // openpgp.js builds the encrypted data packet with our session key; the
  // password packet it prepends is thrown away and replaced by our PKESK.
  const withSkesk = await o.encrypt({ message, passwords: ['unused'], sessionKey: { data: sessionKey, algorithm: 'aes256' }, format: 'binary', config: { aeadProtect: false } });
  const packets = pgp.parsePackets(withSkesk);
  const skesk = packets.find(p => p.tag === 3);
  if (!skesk) throw new Error('Unexpected openpgp.js output');
  const pkesk = await pgp.makePkesk({ recipientPoint: identity.point, recipientFingerprint: identity.subkeyFingerprint, algo: 9, sessionKey });
  return pgp.concat(pkesk, withSkesk.subarray(skesk.end));
}

// Decrypt a file encrypted to our key. One confirmation on Jade.
export async function decryptFile({ jade, identity, bytes }) {
  const o = openpgp();
  const bin = armoredToBinary(bytes);
  const pkesks = pgp.findPkesks(bin);
  if (!pkesks.length) throw new Error('This is not a PGP encrypted file');
  const ours = pkesks.filter(p => p.algo === pgp.ALGO_ECDH && (p.keyId === identity.subkeyKeyId || p.keyId === '0000000000000000'));
  if (!ours.length) {
    throw new Error(`This file was not encrypted with this Jade (key ${identity.subkeyKeyId}). It is for key ${pkesks.map(p => p.keyId).join(', ')}.`);
  }
  const message = await o.readMessage({ binaryMessage: bin });
  let lastErr = null;
  for (const pk of ours) {
    try {
      const sharedX = await jade.getIdentitySharedKey(identity.identity, pk.ephemeral);
      const { algo, key } = await pgp.unwrapSessionKey(sharedX, identity.subkeyFingerprint, pk.wrapped);
      const algorithm = pgp.SYMMETRIC_NAMES[algo];
      if (!algorithm) throw new Error('Unsupported symmetric algorithm ' + algo);
      const res = await o.decrypt({ message, sessionKeys: [{ data: key, algorithm }], format: 'binary' });
      const data = res.data instanceof Uint8Array ? res.data : new Uint8Array(await new Response(res.data).arrayBuffer());
      return { data, filename: res.filename || '' };
    } catch (e) {
      lastErr = e;
      if (e.code === -32000) throw e; // declined on Jade
    }
  }
  throw lastErr;
}
