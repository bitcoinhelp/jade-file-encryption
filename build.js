// Bundle src/ + vendor/openpgp.min.js into one self-contained docs/jade-gpg.html.
// Each ES module is wrapped in its own function scope; imports become
// destructuring from the already-built module object.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

// sha256 of dist/openpgp.min.js from the openpgp@6.3.1 npm tarball (registry
// integrity sha512-7oSPvmlKPojxFoyelT5DWPIAVmqWZh4qU/5pO6bdoShEtRpCw9Sye9IXUQj6EFM3XpgGssqccAr705YtTcLNQw==).
const OPENPGP_VERSION = '6.3.1';
const OPENPGP_SHA256 = '9736f49e81790af972029cd8416a8f9e5be7c4bddfb041676ab93fcad8332f5e';

const root = path.dirname(new URL(import.meta.url).pathname);
const read = p => fs.readFileSync(path.join(root, p), 'utf8');
const ORDER = ['cbor', 'pgp', 'jade', 'gpgops', 'app'];

function transform(name, code) {
  const exportsFound = [];
  code = code.replace(/^import \* as (\w+) from '\.\/(\w+)\.js';\s*$/gm, (_, alias, mod) => `const ${alias} = __m_${mod};`);
  code = code.replace(/^import \{([^}]+)\} from '\.\/(\w+)\.js';\s*$/gm, (_, names, mod) => `const {${names}} = __m_${mod};`);
  if (/^import /m.test(code)) throw new Error(`${name}: unhandled import`);
  code = code.replace(/^export (async function|function|class|const|let) (\w+)/gm, (_, kind, id) => { exportsFound.push(id); return `${kind} ${id}`; });
  if (/^export /m.test(code)) throw new Error(`${name}: unhandled export`);
  return `const __m_${name} = (() => {\n${code}\nreturn { ${exportsFound.join(', ')} };\n})();`;
}

const app = ORDER.map(n => transform(n, read(`src/${n}.js`))).join('\n\n');
const openpgp = read('vendor/openpgp.min.js');
const openpgpHash = crypto.createHash('sha256').update(openpgp).digest('hex');
if (openpgpHash !== OPENPGP_SHA256) throw new Error(`vendor/openpgp.min.js sha256 ${openpgpHash} does not match the pinned npm release hash`);
if (!openpgp.startsWith(`/*! OpenPGP.js v${OPENPGP_VERSION}`)) throw new Error('vendor/openpgp.min.js is not the pinned version');
const VERSION = JSON.parse(read('package.json')).version;
const css = read('src/styles.css');
for (const [label, text] of [['app', app], ['openpgp', openpgp]]) if (text.includes('</script')) throw new Error(label + ' contains </script');

let html = read('src/index.html');
const put = (tag, val) => { if (!html.includes(tag)) throw new Error('missing ' + tag); html = html.split(tag).join(val); };
put('/*{{CSS}}*/', css);
put('/*{{OPENPGP}}*/', openpgp);
put('/*{{APP}}*/', app);
put('{{VERSION}}', VERSION);
put('{{OPENPGP_VERSION}}', OPENPGP_VERSION);
fs.mkdirSync(path.join(root, 'docs'), { recursive: true });
fs.writeFileSync(path.join(root, 'docs/jade-gpg.html'), html);
fs.writeFileSync(path.join(root, 'docs/index.html'), html);
const pageHash = crypto.createHash('sha256').update(html).digest('hex');
fs.writeFileSync(path.join(root, 'docs/SHA256SUMS'), `${pageHash}  jade-gpg.html\n${pageHash}  index.html\n`);
console.log(`docs/jade-gpg.html v${VERSION} ${(html.length / 1024).toFixed(0)} KB\nsha256 ${pageHash}\nopenpgp.js ${OPENPGP_VERSION} verified`);
