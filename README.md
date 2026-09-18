# Jade File Encryption

**Experimental. Do not use for real files.** Not audited or reviewed by anyone but the author. Use it only with files you can afford to lose or expose. Before trying it seriously, restore your wallet on a second Jade and check that a test file decrypts.

A single HTML file that encrypts and decrypts your own files with a Blockstream Jade. The page asks Jade for a public key and, per decryption, one ECDH shared secret; the private key is not part of the protocol.

## Use

1. Open `docs/jade-gpg.html` in Chrome, Edge or Brave on a desktop computer. Either open the file straight from disk or serve it locally (`npm run serve`, then http://localhost:4180).
2. Connect Jade over USB and enter your PIN on the device.
3. Drop files. A plain file is encrypted and saved as `name.gpg`. An encrypted file (`.gpg` or `.asc`) is decrypted and saved under its original name.
4. Disconnect when you are done.

There is no setup and nothing to remember. The same wallet on any Jade opens the same files.

## Before you trust it with anything

- **Verify the file you were given.** Compare its SHA-256 with `docs/SHA256SUMS` from the source repository. Do not trust a copy from a URL you cannot tie back to the source.
- **Test recovery first.** Encrypt a throwaway file, wipe or use a second Jade, restore the wallet, decrypt. Then and only then encrypt something real.
- **BIP39 passphrase.** The key depends on the seed and the passphrase, if your wallet uses one. Restoring without the passphrase gives a different key and your files will not open.
- **The PIN is the approval.** In the current Jade firmware the decrypt step (`get_identity_shared_key`) does not show a confirmation screen; only `sign_identity` does. While Jade is unlocked and plugged in, any software with access to that USB port could decrypt files made with this key. Disconnect when you finish.
- **Browser extensions can read page contents**, including decrypted files, as with any in-browser tool.

## What it cannot do

- It cannot spend or expose your bitcoin. The page sends Jade four commands: version info, unlock, fetch the file public key, and the ECDH decrypt step. Nothing that signs a transaction or reads wallet addresses. Even a tampered copy of the page could not spend, because Jade shows every transaction on its own screen and waits for a tap.
- It cannot learn your seed or PIN. The PIN handshake between Jade and Blockstream's blind pinserver is end-to-end encrypted; the page only relays it.
- The only network request in the page's code is the PIN handshake relay. No fonts, no CDN, no analytics. Check your browser's network tab to confirm.

## How the key works

Jade derives identity keys deterministically from the wallet seed plus a text string (SLIP-0013/0017). This page uses the fixed string `gpg://Jade File Encryption` and an OpenPGP key creation time of 0, the same defaults `jade-agent` uses. Two consequences:

- Recovery needs only the wallet (seed plus passphrase). No timestamps, no exported keys.
- The key is exactly the one `jade-agent init "Jade File Encryption"` produces, so GnuPG can open the files without this page.

Files are standard OpenPGP: a random AES-256 session key wrapped to the Jade key with RFC 6637 ECDH (P-256, SHA-256, AES-128 key wrap), then an integrity-protected encrypted data packet.

## Recovery without this page

Not yet demonstrated on hardware; the key math is verified in the tests. With Python, GnuPG and a Jade:

```bash
pip install jade-agent
jade-gpg init "Jade File Encryption"        # creates ~/.gnupg/jade with the public key, time defaults to 0
export GNUPGHOME=~/.gnupg/jade
gpg --decrypt secret.numbers.gpg > secret.numbers
```

The fingerprint GnuPG shows must match the key ID the page displays after connecting.

## Building and testing

```
src/cbor.js     minimal CBOR codec
src/pgp.js      OpenPGP packets, armor, fingerprints, RFC 6637 ECDH wrap/unwrap, key building (unused by the page, kept for a future messaging page)
src/jade.js     Web Serial transport, RPC, unlock flow
src/gpgops.js   loadIdentity, encryptFile, decryptFile
src/app.js      page logic
vendor/openpgp.min.js   OpenPGP.js 6.3.1 (LGPL), verified against the npm release; see vendor/README.md
test/softjade.js        software Jade from the firmware's SLIP-0013 test mnemonic
test/vectors.js         checks softjade against Jade's test_data/identity_*.json
test/e2e.js             encrypt/decrypt round trips, GnuPG cross-checks, openpgp.js cross-check, negative cases
build.js                inlines everything into docs/jade-gpg.html, refuses a tampered openpgp.js, writes docs/SHA256SUMS
```

`npm run build` is deterministic: the same sources produce the same file and hash. `npm test` needs `gpg` on PATH and the Jade firmware repo at `~/Jade` (override with `JADE_TEST_DATA`).

## Verified

- Software Jade matches all five firmware identity vectors, including deterministic signatures.
- Files encrypted by the page decrypt through the page's code, restoring the filename, with one ECDH call to Jade.
- Files encrypted by GnuPG 2.5 to the same key (binary and armored) decrypt through the page's code.
- The page's output is parsed by GnuPG as pubkey-encrypted to the right key, and the same encryption code decrypts under a standard openpgp.js P-256 key, so the format is not Jade-specific.
- Connect, unlock, encrypt and decrypt on a physical Jade Plus over USB (Chrome, macOS).

## Not yet verified

- Recovery through `jade-agent` on hardware.
- Web Serial when the file is opened from disk (`file://`). The page shows a banner if the browser refuses.
- Bluetooth. USB only.
- Any review by someone other than the author.

## Browser support

Chrome, Edge and Brave on desktop, which expose USB serial to web pages. Safari and Firefox do not.

## Licence

MIT for this project (see LICENSE). OpenPGP.js is LGPL-3.0+ and is bundled unmodified with its notice intact.
