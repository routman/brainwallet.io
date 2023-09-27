# brainwallet.io
Deterministic Bitcoin and Litecoin Address Generator

Brainwallet.io is a deterministic cryptocurrency address generator for Bitcoin and Litecoin that runs in your web browser. It converts any text or file into a private key and public address, allowing you to store cryptocurrency on paper, in a password manager, within a photograph or document, or in your brain by memorizing the passphrase and salts. Key generation takes place in your browser, and no information is ever sent to our server.

Disclaimer: Use at your own risk. Brainwallets can be risky if you don't know what you are doing. You must use a strong passphrase and take security precautions to prevent loss or theft. By using brainwallet.io, you are agreeing to our Terms of Service (below).

Use a long, unique passphrase that is never used in any song, literature, or media. If you use a weak passphrase, you are at risk of having your money stolen. We recommend a minimum of 8 random words. Click the "random" button to have a secure 12-word passphrase generated for you. If you forget your passphrase, your cryptocurrency will be lost forever, so please write down your passphrase and salts. 

Your salts are used as additional inputs to the cryptographic function that generates your brainwallet. This information never gets sent or stored anywhere, and is only used to strengthen your passphrase. You are required to enter at least one salt, and you have the ability to choose between different types of salts. There is no recovery process, so don't forget what you enter.

Instead of typing a passphrase, you can use any file as your passphrase by selecting a file, or by dragging the file to the passphrase field. Your browser performs an SHA256 hash operation on the file to derive a checksum, which is used as your passphrase. The file hashing takes place in your browser, and the file is never uploaded. It's important to never use a file that exists on the internet, and to keep it stored securely. We recommend using a photograph that you have taken.

Brainwallet.io is a self-contained website that can be run offline. We recommend that you download the latest HTML file from GitHub, verify file integrity (checksum) with the PGP-signed changelog, and run it on an offline computer. Keep a copy of the HTML file that you used to generate your brainwallet with for safekeeping.
#
Brainwallet.io uses the scrypt key derivation function to generate cryptocurrency keys. Your salt inputs are concatenated and used as the salt for the scrypt function.

The process is as follows (pseudocode):

key = scrypt(passphrase, salt, N=2^18, r=8, p=1, dkLen=32)
keypair = generate_keypair(sha256(key))

Scrypt is a memory-intensive function that is deliberately slow to frustrate brute-force attacks. Performance may vary depending on your hardware, and in some cases may not work at all. If you run into problems, try a different web browser or a newer computer. We can't sacrifice security for legacy support.
#
TERMS OF SERVICE

These Terms of Service (“Terms”) govern your access to and use of brainwallet.io (“Service”), and any information, text, links, graphics, photos, videos, or other materials uploaded, downloaded or appearing on the Service (collectively referred to as “Content”). By using the Service you agree to be bound by these Terms.

You are responsible for your use of this Service and for any Content you provide, including compliance with applicable laws, rules, and regulations. Your access to and use of the Service or any Content are at your own risk. You understand and agree that the Service is provided to you on an “AS IS” and “AS AVAILABLE” basis.

In no event shall brainwallet.io be held liable for anything arising out of or in any way connected with your use of this Service whether such liability is under contract. Brainwallet.io shall not be held liable for any indirect, consequential or special liability arising out of or in any way related to your use of this Service.

Brainwallet.io is not responsible for any losses in cryptocurrency that you may incur for any reason.

We reserve the right to modify or terminate the Service for any reason, without notice at any time. We reserve the right to alter these Terms at any time.
#
Donations are greatly appreciated!

BTC: bc1q7fqwmtq2vaka8wwpjpnmlehe36qrgfmlw33vh9

LTC: LYMSJ313xJaUsAmucuYRkVJmGB8Ut9VDz8

Brainwallet.io is licensed under The MIT License (MIT)
