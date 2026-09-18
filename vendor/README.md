# Vendored dependencies

## openpgp.min.js

- Package: `openpgp` 6.3.1 (https://openpgpjs.org, LGPL-3.0+)
- Source: `dist/openpgp.min.js` from the npm tarball https://registry.npmjs.org/openpgp/-/openpgp-6.3.1.tgz
- Tarball integrity (npm registry): `sha512-7oSPvmlKPojxFoyelT5DWPIAVmqWZh4qU/5pO6bdoShEtRpCw9Sye9IXUQj6EFM3XpgGssqccAr705YtTcLNQw==`
- File sha256: `9736f49e81790af972029cd8416a8f9e5be7c4bddfb041676ab93fcad8332f5e`

`build.js` refuses to build if the file's hash differs from the value above.

To re-verify yourself:

```bash
curl -sL https://registry.npmjs.org/openpgp/-/openpgp-6.3.1.tgz -o openpgp-6.3.1.tgz
openssl dgst -sha512 -binary openpgp-6.3.1.tgz | base64     # compare with the integrity value
tar xzf openpgp-6.3.1.tgz && shasum -a 256 package/dist/openpgp.min.js vendor/openpgp.min.js
```

OpenPGP.js is used unmodified. Its licence notice is retained in the file header and travels inside the built page.
