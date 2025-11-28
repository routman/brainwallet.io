/*
 * BIP39 Mnemonic Implementation
 * Generates and encodes cryptocurrency mnemonics using the BIP39 standard
 * https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 */

var BIP39 = (function() {
  'use strict';

  // Generate a mnemonic from entropy bytes
  function generate(entropyBytes) {
    if (!entropyBytes || entropyBytes.length < 16) {
      throw new Error('Entropy must be at least 16 bytes');
    }
    
    // Convert to Uint8Array if needed
    var entropy = entropyBytes instanceof Uint8Array ? entropyBytes : new Uint8Array(entropyBytes);
    
    // Calculate checksum
    var entropyBits = bytesToBinary(entropy);
    var checksumBits = deriveChecksumBits(entropy);
    var bits = entropyBits + checksumBits;
    
    // Split into 11-bit chunks and convert to words
    var chunks = bits.match(/(.{1,11})/g);
    var words = chunks.map(function(binary) {
      var index = parseInt(binary, 2);
      return bip39_words[index];
    });
    
    return words.join(' ');
  }

  // Generate random mnemonic using native crypto
  function generateRandom(wordCount) {
    wordCount = wordCount || 12;
    var strength = (wordCount === 12) ? 16 : 32; // 12 words = 128 bits, 24 words = 256 bits
    
    // Use native crypto.getRandomValues for secure random generation
    var entropy = new Uint8Array(strength);
    if (typeof window !== 'undefined' && window.crypto) {
      window.crypto.getRandomValues(entropy);
    } else if (typeof self !== 'undefined' && self.crypto) {
      self.crypto.getRandomValues(entropy);
    } else {
      throw new Error('crypto.getRandomValues is not supported');
    }
    
    return generate(entropy);
  }

  // Decode mnemonic back to entropy (for verification)
  function decode(mnemonic) {
    var words = mnemonic.trim().split(/\s+/);
    
    if (words.length % 3 !== 0) {
      throw new Error('Invalid mnemonic length');
    }
    
    // Convert words to binary string
    var bits = words.map(function(word) {
      var index = bip39_words.indexOf(word);
      if (index === -1) {
        throw new Error('Invalid word: ' + word);
      }
      return ('00000000000' + index.toString(2)).slice(-11);
    }).join('');
    
    // Split entropy and checksum
    var dividerIndex = Math.floor(bits.length / 33) * 32;
    var entropyBits = bits.slice(0, dividerIndex);
    var checksumBits = bits.slice(dividerIndex);
    
    // Verify checksum
    var entropy = binaryToBytes(entropyBits);
    var newChecksum = deriveChecksumBits(entropy);
    
    if (newChecksum !== checksumBits) {
      throw new Error('Invalid mnemonic checksum');
    }
    
    return entropy;
  }

  // Validate a mnemonic
  function validate(mnemonic) {
    try {
      decode(mnemonic);
      return true;
    } catch (e) {
      return false;
    }
  }

  // Helper: Convert bytes to binary string
  function bytesToBinary(bytes) {
    return Array.from(bytes).map(function(byte) {
      return ('00000000' + byte.toString(2)).slice(-8);
    }).join('');
  }

  // Helper: Convert binary string to bytes
  function binaryToBytes(binary) {
    var bytes = new Uint8Array(binary.length / 8);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(binary.slice(i * 8, i * 8 + 8), 2);
    }
    return bytes;
  }

  // Helper: Derive checksum bits from entropy
  function deriveChecksumBits(entropy) {
    var ENT = entropy.length * 8;
    var CS = ENT / 32;
    
    // Use existing Crypto.SHA256 from CryptoJS
    if (typeof Crypto === 'undefined' || !Crypto.SHA256) {
      throw new Error('CryptoJS SHA256 not available');
    }
    
    // Convert Uint8Array to array for Crypto.SHA256
    var entropyArray = Array.from(entropy);
    var hashBytes = Crypto.SHA256(entropyArray, { asBytes: true });
    
    var hashBits = bytesToBinary(hashBytes);
    return hashBits.slice(0, CS);
  }

  return {
    generate: generate,
    generateRandom: generateRandom,
    decode: decode,
    validate: validate
  };
})();
