const fs = require('fs');
const path = require('path');

console.log('Bundling Keccak-256...');

// Copy the pre-built js-sha3 library
const sourcePath = path.join(__dirname, '../node_modules/js-sha3/src/sha3.js');
const destPath = path.join(__dirname, '../src/lib/keccak256.js');

// Read the source file
const content = fs.readFileSync(sourcePath, 'utf8');

// Wrap it to expose keccak256 globally
const wrapped = `
// Keccak-256 from js-sha3
(function() {
${content}

// Export keccak256 to global scope
if (typeof window !== 'undefined') {
    window.keccak256 = keccak_256;
}
})();
`;

// Write to destination
fs.writeFileSync(destPath, wrapped, 'utf8');

console.log('✓ Created src/lib/keccak256.js');
