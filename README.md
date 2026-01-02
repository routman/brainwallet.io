# brainwallet.io v3.0.1
Deterministic Cryptocurrency Address Generator

**Brainwallet.io** is an open-source, deterministic cryptocurrency address generator for **Bitcoin**, **Litecoin**, **Ethereum**, and **Dogecoin**. It runs entirely in your web browser, serving as a secure tool for creating **cold storage**, **paper wallets**, and **brainwallets**. By converting any text or file into a public address and private key pair, it enables complete **self-custody** of your digital assets. All cryptographic operations run locally; no information is ever transmitted to any server.

## Security Warning

**Disclaimer: Use at your own risk.** Brainwallets are inherently risky if proper security precautions are not taken.

*   **Weak Passphrases:** Passphrases must be strong and unique. Never use text found in books, lyrics, quotes, or religious texts. **Never use Artificial Intelligence (AI) tools to generate passphrases or salts**, as these inputs may be stored or learned by the model.
*   **Brute Force:** Weak inputs are vulnerable to brute-force attacks. If you use a weak passphrase, you are at risk of theft.
*   **No Recovery:** There is no "forgot password" feature. If you lose your passphrase or salts, your funds are permanently lost.
*   **Offline Usage:** For maximum security, download the source code from GitHub, verify the PGP signature, and run this tool on an air-gapped (offline) computer.

## Key Derivation Modes

### Argon2id (Recommended)
*   **Algorithm:** Argon2id (v1.3)
*   **Parameters:** 384MB Memory, 25 Iterations, 1 Parallelism.
*   **Security:** This process is intentionally slow (taking 10+ seconds on modern hardware) to make brute-force attacks computationally infeasible.
*   **Address Types:**
    *   **Bitcoin/Litecoin:** SegWit (Bech32) addresses (`bc1q...`, `ltc1q...`).
    *   **Ethereum:** Standard EIP-55 checksum addresses (`0x...`).
    *   **Dogecoin:** Legacy P2PKH addresses (`D...`).

### Scrypt (Legacy)
*   **Algorithm:** Scrypt
*   **Parameters:** N=2^18, r=8, p=1.
*   **Purpose:** Provided for backward compatibility with wallets created on older versions of this site.
*   **Address Types:** Generates legacy P2PKH addresses (`1...`, `L...`) for Bitcoin and Litecoin only.

## Technical Details

**Argon2id Mode:**
```
key = argon2id(passphrase, salt, mem=384MB, iterations=25, parallelism=1, hashLen=32)
keypair = generate_keypair(key) // uses raw Argon2 output directly
```

**Scrypt Mode:**
```
key = scrypt(passphrase, salt, N=2^18, r=8, p=1, dkLen=32)
keypair = generate_keypair(sha256(key)) // SHA-256 applied for backward compatibility
```

Both functions are memory-intensive. Private keys are validated against the secp256k1 curve order to ensure cryptographic correctness.

## Development

To build from source:

1.  Install dependencies: `npm install`
2.  Build the project: `npm run build`
3.  Open `src/index.html` in your browser.

## Terms of Service

These Terms of Service (“Terms”) govern your access to and use of brainwallet.io (“Service”). By using the Service you agree to be bound by these Terms.

You are responsible for your use of this Service and for any Content you provide. Your access to and use of the Service are at your own risk. The Service is provided on an “AS IS” and “AS AVAILABLE” basis.

In no event shall brainwallet.io be held liable for anything arising out of or in any way connected with your use of this Service. Brainwallet.io is not responsible for any losses in cryptocurrency that you may incur for any reason.

## License

Copyright (c) 2015-2026 Daniel Routman

Licensed under The MIT License (MIT).

**Donations:** `bc1qyw93y3zlk5ga2ku8x6rm2weyyyn3cden7nknmz`
