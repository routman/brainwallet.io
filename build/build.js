const fs = require('fs');

console.log('Building brainwallet.html...');

// Read all source files
const html = fs.readFileSync('src/index.html', 'utf8');
const css = fs.readFileSync('src/styles.css', 'utf8');

// Read all lib files in order
const libs = [
  'src/lib/bitcoinjs-lib.js',
  'src/lib/cryptojs.js',
  'src/lib/qrcode.js',
  'src/lib/bip39-wordlist.js',
  'src/lib/bip39.js',
  'src/lib/scrypt.js',
  'src/lib/bech32.js',
  'src/lib/keccak256.js',
  'src/lib/argon2.js'
].map(file => {
  console.log(`  Reading ${file}...`);
  return fs.readFileSync(file, 'utf8');
}).join('\n\n');

const mainJs = fs.readFileSync('src/brainwallet.js', 'utf8');

// Combine all JavaScript
const allJs = libs + '\n\n' + mainJs;

// Inject into HTML
let output = html;
output = output.replace('<!-- CSS_PLACEHOLDER -->', 
  `<style>\n${css}\n</style>`);
output = output.replace('<!-- JS_PLACEHOLDER -->', 
  `<script>\n${allJs}\n</script>`);

// Write output
fs.mkdirSync('dist', {recursive: true});
fs.writeFileSync('dist/brainwallet.html', output, 'utf8');

console.log('✓ Built dist/brainwallet.html');
console.log(`  Size: ${(output.length / 1024).toFixed(2)} KB`);