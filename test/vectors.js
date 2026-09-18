// Check the software Jade against the firmware's identity test vectors
// (Jade repo: test_data/identity_*.json, wallet = TEST_MNEMONIC_12_IDENTITY).
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { SoftJade } from './softjade.js';
import { hex } from '../src/pgp.js';

const dir = process.env.JADE_TEST_DATA || path.join(os.homedir(), 'Jade', 'test_data');
const files = fs.readdirSync(dir).filter(f => /^identity_.*\.json$/.test(f)).sort();
if (!files.length) { console.error('no identity_*.json vectors found in ' + dir); process.exit(1); }

const jade = new SoftJade();
let fail = 0;
const check = (name, got, want) => { const ok = got === want; if (!ok) fail++; console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}`); if (!ok) console.log('   got ', got, '\n   want', want); };
const cases = files.map(f => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')));
for (const c of cases) {
  const { identity, curve, index, challenge } = c.input, e = c.expected_output;
  check(`${identity} #${index} slip-0013`, hex(await jade.get_identity_pubkey(identity, curve, 'slip-0013', index)), e['slip-0013']);
  check(`${identity} #${index} slip-0017`, hex(await jade.get_identity_pubkey(identity, curve, 'slip-0017', index)), e['slip-0017']);
  const sig = await jade.sign_identity(identity, curve, Buffer.from(challenge, 'hex'), index);
  check(`${identity} #${index} signature`, hex(sig.signature), e.signature);
}
// ECDH symmetry between two identities, as the firmware test does
const [a, b] = cases;
const sa = await jade.get_identity_shared_key(a.input.identity, 'nist256p1', Buffer.from(b.expected_output['slip-0017'], 'hex'), a.input.index);
const sb = await jade.get_identity_shared_key(b.input.identity, 'nist256p1', Buffer.from(a.expected_output['slip-0017'], 'hex'), b.input.index);
check('ecdh symmetry', hex(sa), hex(sb));
if (fail) { console.log(`${fail} failure(s)`); process.exit(1); }
console.log(`all ${cases.length} vector files pass`);
