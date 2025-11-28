const fs = require('fs');
const path = require('path');

console.log('Copying argon2-browser bundle...');

// argon2-browser comes with a pre-built browser bundle
const argon2Path = path.join(__dirname, '../node_modules/argon2-browser/dist/argon2-bundled.min.js');

if (!fs.existsSync(argon2Path)) {
  console.error('Error: argon2-browser bundle not found at:', argon2Path);
  console.log('Available files in dist:');
  const distPath = path.join(__dirname, '../node_modules/argon2-browser/dist');
  fs.readdirSync(distPath).forEach(file => console.log('  -', file));
  process.exit(1);
}

// Copy the bundle
const bundle = fs.readFileSync(argon2Path);
fs.writeFileSync('src/lib/argon2.js', bundle);

console.log('✓ Created src/lib/argon2.js');
console.log(`  Size: ${(bundle.length / 1024).toFixed(2)} KB`);