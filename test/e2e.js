// End-to-end for the file page: encrypt with the page's code, decrypt through
// Jade's ECDH; cross-check with GnuPG and with openpgp.js software keys.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { SoftJade } from './softjade.js';
import * as ops from '../src/gpgops.js';
import * as pgp from '../src/pgp.js';

vm.runInThisContext(fs.readFileSync(new URL('../vendor/openpgp.min.js', import.meta.url), 'utf8'));

let fail = 0;
const ok = (name, cond, extra = '') => { if (!cond) fail++; console.log(`${cond ? 'ok  ' : 'FAIL'} ${name}${extra ? ' ' + extra : ''}`); };

class Jade extends SoftJade {
  getIdentityPubkey(identity, type, index = 0) { return this.get_identity_pubkey(identity, 'nist256p1', type, index); }
  signIdentity(identity, challenge, index = 0) { return this.sign_identity(identity, 'nist256p1', challenge, index); }
  getIdentitySharedKey(identity, theirPubkey, index = 0) { return this.get_identity_shared_key(identity, 'nist256p1', theirPubkey, index); }
}
const jade = new Jade();

const id = await ops.loadIdentity(jade);
ok('identity loads with no Jade confirmation', jade.prompts.length === 0);
const id2 = await ops.loadIdentity(jade);
ok('identity is deterministic', id.subkeyFingerprintHex === id2.subkeyFingerprintHex);
console.log('   key ' + id.subkeyFingerprintHex);

// page encrypt -> page decrypt
const fileBytes = crypto.randomBytes(300_000);
const enc = await ops.encryptFile({ identity: id, bytes: fileBytes, filename: 'photo.jpg' });
ok('encrypted output looks encrypted', ops.looksEncrypted(enc));
ok('plain input does not look encrypted', !ops.looksEncrypted(fileBytes) && !ops.looksEncrypted(new TextEncoder().encode('hello')));
jade.prompts.length = 0;
const dec = await ops.decryptFile({ jade, identity: id, bytes: enc });
ok('round trip restores the file', Buffer.from(dec.data).equals(fileBytes));
ok('filename restored', dec.filename === 'photo.jpg', dec.filename);
ok('decrypt took exactly 1 Jade ECDH call', jade.prompts.length === 1 && jade.prompts[0].op === 'ecdh');
const enc2 = await ops.encryptFile({ identity: id, bytes: fileBytes, filename: 'photo.jpg' });
ok('each encryption uses fresh randomness', !pgp.equalBytes(enc, enc2));

// GnuPG parses our file and sees the right recipient
const home = fs.mkdtempSync(path.join(os.tmpdir(), 'jadegpg-'));
fs.chmodSync(home, 0o700);
const gpg = (args, input) => execFileSync('gpg', ['--homedir', home, '--batch', '--yes', '--trust-model', 'always', ...args], { input, stdio: ['pipe', 'pipe', 'pipe'] }).toString();
fs.writeFileSync(path.join(home, 'x.gpg'), enc);
let pkts = '';
try { pkts = gpg(['--list-packets', path.join(home, 'x.gpg')]); } catch (e) { pkts = e.stdout.toString(); } // gpg exits 2: it also tries to decrypt
ok('gpg parses the file as pubkey-encrypted to our key', pkts.includes('pubkey enc packet') && pkts.toUpperCase().includes(id.subkeyKeyId) && pkts.includes('encrypted data packet'));

// GnuPG-encrypted file (to a signed public key built the jade-agent way) decrypts
const signingPoint = await jade.getIdentityPubkey(ops.IDENTITY, 'slip-0013');
const signFn = async digest => { const r = await jade.signIdentity(ops.IDENTITY, digest); return { r: r.signature.subarray(1, 33), s: r.signature.subarray(33) }; };
const built = await pgp.buildPublicKey({ userId: 'Jade File Encryption', created: ops.CREATED, signingPoint, encryptionPoint: id.point, signFn });
ok('signed key has the same encryption fingerprint', pgp.hex(built.subkeyFingerprint).toUpperCase() === id.subkeyFingerprintHex);
fs.writeFileSync(path.join(home, 'pub.asc'), pgp.armor(built.bytes, 'PUBLIC KEY BLOCK'));
gpg(['--import', path.join(home, 'pub.asc')]);
const plain = path.join(home, 'secret.bin');
fs.writeFileSync(plain, fileBytes);
gpg(['--encrypt', '-r', pgp.hex(built.primaryFingerprint), '--output', plain + '.gpg', plain]);
const d3 = await ops.decryptFile({ jade, identity: id, bytes: new Uint8Array(fs.readFileSync(plain + '.gpg')) });
ok('gpg-encrypted file decrypts', Buffer.from(d3.data).equals(fileBytes) && d3.filename === 'secret.bin');
const armored = gpg(['--armor', '--encrypt', '-r', pgp.hex(built.primaryFingerprint)], Buffer.from('armored text file'));
const d4 = await ops.decryptFile({ jade, identity: id, bytes: new TextEncoder().encode(armored) });
ok('armored .asc file decrypts', new TextDecoder().decode(d4.data) === 'armored text file');

// our PKESK is standard: encrypt to an openpgp.js software key, decrypt with openpgp.js
const soft = await openpgp.generateKey({ userIDs: [{ name: 'Soft', email: 'soft@example.com' }], curve: 'nistP256', format: 'object' });
const softSub = soft.privateKey.subkeys[0];
const softId = { identity: 'n/a', point: softSub.keyPacket.publicParams.Q, subkeyFingerprint: softSub.keyPacket.getFingerprintBytes(), subkeyKeyId: softSub.getKeyID().toHex().toUpperCase() };
const encSoft = await ops.encryptFile({ identity: softId, bytes: fileBytes, filename: 'a.bin' });
const dSoft = await openpgp.decrypt({ message: await openpgp.readMessage({ binaryMessage: encSoft }), decryptionKeys: soft.privateKey, format: 'binary' });
ok('our PKESK decrypts with a standard openpgp.js key', Buffer.from(dSoft.data).equals(fileBytes));

// negative cases
let threw = '';
try { await ops.decryptFile({ jade, identity: id, bytes: encSoft }); } catch (e) { threw = e.message; }
ok('file for another key is rejected before touching Jade', /not encrypted with this Jade/.test(threw));
threw = '';
try { await ops.decryptFile({ jade, identity: id, bytes: fileBytes }); } catch (e) { threw = e.message; }
ok('random bytes are rejected', threw.length > 0);

fs.rmSync(home, { recursive: true, force: true });
if (fail) { console.log(`${fail} failure(s)`); process.exit(1); }
console.log('e2e passed');
