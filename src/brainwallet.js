(function(){
	var gen_compressed = false;

	var currency = 'btc';
	var mode = 2; //generic
	var busy = 0;
	var passphrase;
	var salts = [];
	var salt;

	// KDF mode: 'argon2' or 'legacy'
	var kdfMode = 'argon2';

		// Argon2 parameters
    var argon2Params = {
        time: 25,        // iterations 
        mem: 393216,     // 384 MB memory 
        parallelism: 1,
        hashLen: 32,
        type: 2         // 0=Argon2d, 1=Argon2i, 2=Argon2id
    };

	//scrypt parameters
	var logN = 18;
	var r = 8;
	var L = 32;
	var step = 2048;  //iterations per step

	function pad(str, len, ch) {
        var padding = '';
        for (var i = 0; i < len - str.length; i++) {
            padding += ch;
        }
        return padding + str;
    }
    
    // Convert between bit arrays (for Bech32)
    function convertBits(data, fromBits, toBits, pad) {
        var acc = 0;
        var bits = 0;
        var ret = [];
        var maxv = (1 << toBits) - 1;
        for (var i = 0; i < data.length; i++) {
            var value = data[i];
            if (value < 0 || (value >> fromBits) !== 0) {
                return null;
            }
            acc = (acc << fromBits) | value;
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                ret.push((acc >> bits) & maxv);
            }
        }
        if (pad) {
            if (bits > 0) {
                ret.push((acc << (toBits - bits)) & maxv);
            }
        } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) {
            return null;
        }
        return ret;
    }

    function getEncoded(pt, compressed) {
		var x = pt.getX().toBigInteger();
		var y = pt.getY().toBigInteger();
		var enc = integerToBytes(x, 32);
		if (compressed) {
		 	if (y.isEven()) {
		   		enc.unshift(0x02);
		 	} else {
		   		enc.unshift(0x03);
		 	}
		} else {
		 	enc.unshift(0x04);
		 	enc = enc.concat(integerToBytes(y, 32));
		}
		return enc;
    }
    
    // EIP-55 checksum for Ethereum addresses
    function toChecksumAddress(address) {
        address = address.toLowerCase().replace('0x', '');
        var hash = keccak256(address);
        var checksum = '0x';
        
        for (var i = 0; i < address.length; i++) {
            if (parseInt(hash[i], 16) >= 8) {
                checksum += address[i].toUpperCase();
            } else {
                checksum += address[i];
            }
        }
        return checksum;
    }

    function makeAddr(phr, skipHash) {
        var hash;
        if (skipHash) {
            // Argon2: use raw bytes directly (phr is already Uint8Array)
            hash = Array.from(phr);
        } else {
            // Legacy: hash the hex string for backward compatibility
            hash = Crypto.SHA256(phr, { asBytes: true });
        }
        
        hash = Crypto.util.bytesToHex(hash);
        var hash_str = pad(hash, 64, '0');
        
        // Validate private key is within secp256k1 curve order (loop until valid)
        var n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
        var attempts = 0;
        var maxAttempts = 100;
        var d = new BigInteger(hash_str, 16);
        
        while (d.compareTo(BigInteger.ZERO) <= 0 || d.compareTo(n) >= 0) {
            if (attempts >= maxAttempts) {
                throw new Error('Could not generate valid private key within range after ' + maxAttempts + ' attempts');
            }
            // Rehash with domain separator and counter
            hash = Crypto.SHA256("BW" + attempts + hash_str, { asBytes: true });
            hash = Crypto.util.bytesToHex(hash);
            hash_str = pad(hash, 64, '0');
            d = new BigInteger(hash_str, 16);
            attempts++;
        }
        
        var hash = Crypto.util.hexToBytes(hash_str);
        
        // Force compressed keys for SegWit (Argon2 mode with BTC/LTC)
        var compressed = (kdfMode === 'argon2' && (currency === 'btc' || currency === 'ltc')) ? true : gen_compressed;
        
        var eckey = new Bitcoin.ECKey(hash);
        var gen_eckey = eckey;
        var curve = getSECCurveByName("secp256k1");
        var gen_pt = curve.getG().multiply(eckey.priv);
        gen_eckey.pub = getEncoded(gen_pt, compressed);
        gen_eckey.pubKeyHash = Bitcoin.Util.sha256ripe160(gen_eckey.pub);
        var hash160 = eckey.getPubKeyHash();
        
        // Generate address based on currency and KDF mode
        var addrText;
        
        if (currency === 'eth') {
            // Ethereum: Keccak-256 of uncompressed public key
            // Get uncompressed public key (remove 0x04 prefix)
            var uncompressedPub = getEncoded(gen_pt, false);
            var pubKey = uncompressedPub.slice(1); // Remove 0x04 prefix, 64 bytes remain
            
            // Keccak-256 hash of raw bytes (not hex string)
            var ethHash = keccak256(new Uint8Array(pubKey));
            
            // Last 20 bytes (40 hex chars) as address
            var ethAddress = '0x' + ethHash.slice(-40);
            addrText = toChecksumAddress(ethAddress);
        } else if (kdfMode === 'argon2' && (currency === 'btc' || currency === 'ltc')) {
            // Native SegWit (Bech32): bc1q... for BTC, ltc1q... for LTC
            var hrp = (currency === 'btc') ? 'bc' : 'ltc';
            var witnessVersion = 0;
            
            // Validate witness program length (must be 20 bytes for P2WPKH)
            if (hash160.length !== 20) {
                throw new Error('Invalid witness program length: expected 20 bytes for P2WPKH');
            }
            
            // Convert hash160 (8-bit) to 5-bit array for bech32
            var words = convertBits(hash160, 8, 5, true);
            if (!words) {
                throw new Error('Could not convert to 5-bit array');
            }
            
            // Prepend witness version
            words.unshift(witnessVersion);
            
            addrText = Bech32.encode(hrp, words);
        } else {
            // Legacy P2PKH: 1... for BTC, L... for LTC, D... for DOGE
            var addr = new Bitcoin.Address(hash160);
            if (currency === 'btc') {
                addr.version = 0x00;
            }
            else if (currency === 'ltc') {
                addr.version = 0x30;
            }
            else if (currency === 'doge') {
                addr.version = 0x1e;
            }
            addrText = addr.toString();
        }
        
        document.getElementById('addr').textContent = addrText;
        
        // Private key format
        var privateKeyText;
        if (currency === 'eth') {
            // Ethereum: raw hex with 0x prefix
            privateKeyText = '0x' + Crypto.util.bytesToHex(hash);
        } else {
            // Bitcoin/Litecoin/Dogecoin: WIF format
            var payload = hash;
            if (compressed)
                payload.push(0x01);
            var sec = new Bitcoin.Address(payload);
            if (currency === 'btc') {
                sec.version = 0x80;
            }
            else if (currency === 'ltc') {
                sec.version = 0xb0;
            }
            else if (currency === 'doge') {
                sec.version = 0x9e;
            }
            privateKeyText = sec.toString();
        }
        document.getElementById('private').textContent = privateKeyText;

        document.getElementById('privateQR').innerHTML = '';
        var privateQR = new QRCode("privateQR", {
            text: privateKeyText,
            width: 164,
            height: 164,
            colorDark : "#000000",
            colorLight : "#ffffff",
            correctLevel : QRCode.CorrectLevel.H
        }).makeCode(privateKeyText);
        document.getElementById('addrQR').innerHTML = '';
        var addrQR = new QRCode("addrQR", {
            text: addrText,
            width: 164,
            height: 164,
            colorDark : "#000000",
            colorLight : "#ffffff",
            correctLevel : QRCode.CorrectLevel.H
        }).makeCode(addrText);
        document.getElementById('submit').value = 'generate';
    }

    function processFile(file) {
        if (!file) {
            alert("Failed to load file.");
            return;
        }
        var r = new FileReader();
        r.readAsArrayBuffer(file);
        r.onloadend = function () {
            var wordArray = CryptoJS.lib.WordArray.create(r.result);
            var filehash = CryptoJS.SHA256(wordArray).toString().toUpperCase();
            document.getElementById('passphrase').value = filehash;
        }
    }

    function hashFile(evt) {
		if (window.FileReader) {
            var f = evt.target.files[0];
            processFile(f);
        }
        else {
          alert('This feature is not supported by your browser.');
        }
    }

    function random() {
        // Generate secure random mnemonic using BIP39 standard
        // 12 words = 128 bits, 24 words = 256 bits of entropy
        document.getElementById('passphrase').value = BIP39.generateRandom(12);
    }

	document.addEventListener('DOMContentLoaded', function() {
        document.getElementById('passform').addEventListener('submit', function(event) {
        	event.preventDefault();

        	if (busy === 0) {
        		busy = 1;
	            document.getElementById('result').style.display = 'none';

	            passphrase = document.getElementById('passphrase').value;
			document.getElementById('p-passphrase').innerHTML = passphrase.replace(/\n/g, '<br />');

	        if (kdfMode === 'argon2') {
	        	// Argon2 mode: use single salt field
	        	salts[0] = document.getElementById('argon2salt1').value;
	        	salts[1] = "";
	        	salts[2] = "";
	        	salts[3] = "";
	        	
	        	document.getElementById('p-label1').innerHTML = 'Salt:';
	        	document.getElementById('p-label2').innerHTML = '';
	        	document.getElementById('p-label3').innerHTML = '';
	        	document.getElementById('p-label4').innerHTML = '';
	        } else {
	        	// Legacy mode: use salt type selections
	        	if (mode === 0) { //login salts
            salts[0] = document.getElementById('loginsalt1').value;
            salts[1] = document.getElementById('loginsalt2').value;
            salts[2] = document.getElementById('loginsalt3').value;
            salts[3] = "";

            document.getElementById('p-label1').innerHTML = 'Username:';
            document.getElementById('p-label2').innerHTML = 'Password:';
            document.getElementById('p-label3').innerHTML = '4-6 Digit PIN:';
            document.getElementById('p-label4').innerHTML = '';
	        }

          if (mode === 1) { //personal salts
              salts[0] = document.getElementById('personalsalt1').value;
              salts[1] = document.getElementById('personalsalt2').value;
              salts[2] = document.getElementById('personalsalt3').value;
              salts[3] = document.getElementById('personalsalt4').value;

              document.getElementById('p-label1').innerHTML = 'Name:';
              document.getElementById('p-label2').innerHTML = 'Email:';
              document.getElementById('p-label3').innerHTML = 'Phone:';
              document.getElementById('p-label4').innerHTML = 'Date of Birth:';
	          }

	          if (mode === 2) { //generic salt
              salts[0] = document.getElementById('genericsalt1').value;
              salts[1] = "";
              salts[2] = "";
              salts[3] = "";

              document.getElementById('p-label1').innerHTML = 'Salt:';
              document.getElementById('p-label2').innerHTML = '';
              document.getElementById('p-label3').innerHTML = '';
              document.getElementById('p-label4').innerHTML = '';
	          }
	        }

	            salt = salts[0]+salts[1]+salts[2]+salts[3];

              document.getElementById('p-salt1').innerHTML = salts[0];
              document.getElementById('p-salt2').innerHTML = salts[1];
              document.getElementById('p-salt3').innerHTML = salts[2];
              document.getElementById('p-salt4').innerHTML = salts[3];

	            if (!passphrase) {
	              	alert("You must enter a passphrase");
	              	busy = 0;
	            }
	            else if (!salt) {
	              	alert("You must enter at least one salt")
	              	busy = 0;
	            }
	            else {
	            	document.getElementById('submit').style.visibility = 'hidden';
	            	document.getElementById('spinner').style.display = 'flex';

	            	// Use Argon2 or Legacy (Scrypt) based on mode selection
	            	if (kdfMode === 'argon2') {
	            		// Force browser to render spinner before blocking computation
	            		setTimeout(function() {
	            			// Argon2id key derivation
	            		argon2.hash({
	            		pass: passphrase,
	            		salt: salt,
	            		time: argon2Params.time,
	            		mem: argon2Params.mem,
	            		hashLen: argon2Params.hashLen,
	            		parallelism: argon2Params.parallelism,
	            		type: argon2Params.type
	            	}).then(function(result) {
	            		try {
	            			makeAddr(result.hash, true); // Use raw bytes, skip SHA256
	            			document.getElementById('result').style.display = 'block';
	            			var resultElement = document.getElementById('result');
	            			window.scrollTo({
	            				top: resultElement.offsetTop,
	            				behavior: 'smooth'
	            			});
	            		} catch (err) {
	            			alert('Address generation failed: ' + err.message);
	            		} finally {
	            			document.getElementById('spinner').style.display = 'none';
	            			document.getElementById('submit').style.visibility = 'visible';
	            			busy = 0;
	            		}
	            		}).catch(function(err) {
	            			document.getElementById('spinner').style.display = 'none';
	            			document.getElementById('submit').style.visibility = 'visible';
	            			alert('Argon2 error: ' + err.message);
	            			busy = 0;
	            		});
	            		}, 0); // End setTimeout
	            	} else {
	            		// Legacy Scrypt key derivation
	            		scrypt(passphrase, salt, logN, r, L, step,
	              		function(progress) {
		                // Scrypt progress callback (not used with spinner)
		            },
		            function(result) {
		            	try {
		            		makeAddr(result, false); // Legacy: use hex string with SHA256
		            		document.getElementById('result').style.display = 'block';
		            		var resultElement = document.getElementById('result');
		            		window.scrollTo({
		            			top: resultElement.offsetTop,
		            			behavior: 'smooth'
		            		});
		            	} catch (err) {
		            		alert('Address generation failed: ' + err.message);
		            	} finally {
		            		document.getElementById('spinner').style.display = 'none';
		            		document.getElementById('submit').style.visibility = 'visible';
		            		busy = 0;
		            	}
		            },
			        "hex");
	            	}
	            }
	        }
        });
        
        // Handle Enter key for salt inputs
        var legacySaltInputs = document.querySelectorAll('#loginsalt .saltinput, #personalsalt .saltinput, #genericsalt .saltinput');
        legacySaltInputs.forEach(function(input) {
            input.addEventListener('keydown', function(event){
                if(event.keyCode == 13) {
                    event.preventDefault();
                    return false;
                }
            });
        });
        
        // Allow Enter key to submit form for argon2salt1
        document.getElementById('argon2salt1').addEventListener('keypress', function(event){
            if(event.key === 'Enter' || event.keyCode == 13) {
                event.preventDefault();
                event.stopPropagation();
                var form = document.getElementById('passform');
                var submitEvent = new Event('submit', {
                    bubbles: true,
                    cancelable: true
                });
                form.dispatchEvent(submitEvent);
            }
        });

        //RANDOM PASSPHRASE
        document.getElementById('random').addEventListener('click', function() {
			random();
        });
        
        // Show/hide salt options based on KDF mode
        function updateSaltFieldsVisibility() {
        	if (kdfMode === 'argon2') {
        		// Show Argon2 salt field, hide Scrypt salt options
        		document.getElementById('argon2salt').style.display = 'block';
        		document.getElementById('salt-type-label').style.display = 'none';
        		document.getElementById('mode').style.display = 'none';
        		document.getElementById('loginsalt').style.display = 'none';
        		document.getElementById('personalsalt').style.display = 'none';
        		document.getElementById('genericsalt').style.display = 'none';
        	} else {
        		// Show Scrypt salt options, hide Argon2 salt field
        		document.getElementById('argon2salt').style.display = 'none';
        		document.getElementById('salt-type-label').style.display = 'block';
        		document.getElementById('mode').style.display = 'flex';
        		// Show the currently selected salt type
        		if (mode === 0) {
        			document.getElementById('loginsalt').style.display = 'block';
        		} else if (mode === 1) {
        			document.getElementById('personalsalt').style.display = 'block';
        		} else {
        			document.getElementById('genericsalt').style.display = 'block';
        		}
        	}
        }
        
        // Initialize salt fields visibility
        updateSaltFieldsVisibility();

		//CURRENCY SELECTION
		document.getElementById('btc').addEventListener('click', function() {
			currency = 'btc';
			document.getElementById('btc').classList.add('active');
			document.getElementById('ltc').classList.remove('active');
			document.getElementById('eth').classList.remove('active');
			document.getElementById('doge').classList.remove('active');
			document.getElementById('p-currency').innerHTML = 'BTC';
			updateKdfModeAvailability();
			updateSaltFieldsVisibility();
		});
		document.getElementById('ltc').addEventListener('click', function() {
			currency = 'ltc';
			document.getElementById('btc').classList.remove('active');
			document.getElementById('ltc').classList.add('active');
			document.getElementById('eth').classList.remove('active');
			document.getElementById('doge').classList.remove('active');
			document.getElementById('p-currency').innerHTML = 'LTC';
			updateKdfModeAvailability();
			updateSaltFieldsVisibility();
		});
		document.getElementById('eth').addEventListener('click', function() {
			currency = 'eth';
			document.getElementById('btc').classList.remove('active');
			document.getElementById('ltc').classList.remove('active');
			document.getElementById('eth').classList.add('active');
			document.getElementById('doge').classList.remove('active');
			document.getElementById('p-currency').innerHTML = 'ETH';
			// Force Argon2id for Ethereum
			kdfMode = 'argon2';
			updateModeButtons();
			updateKdfModeAvailability();
			updateSaltFieldsVisibility();
		});
		document.getElementById('doge').addEventListener('click', function() {
			currency = 'doge';
			document.getElementById('btc').classList.remove('active');
			document.getElementById('ltc').classList.remove('active');
			document.getElementById('eth').classList.remove('active');
			document.getElementById('doge').classList.add('active');
			document.getElementById('p-currency').innerHTML = 'DOGE';
			updateKdfModeAvailability();
			updateSaltFieldsVisibility();
		});

		//KDF MODE SELECTION
		document.getElementById('mode-argon2').addEventListener('click', function() {
			kdfMode = 'argon2';
			updateModeButtons();
			updateSaltFieldsVisibility();
		});

		document.getElementById('mode-legacy').addEventListener('click', function() {
			kdfMode = 'legacy';
			updateModeButtons();
			updateSaltFieldsVisibility();
		});

		function updateModeButtons() {
			document.getElementById('mode-argon2').classList.toggle('active', kdfMode === 'argon2');
			document.getElementById('mode-legacy').classList.toggle('active', kdfMode === 'legacy');
		}
		
		function updateKdfModeAvailability() {
			var legacyBtn = document.getElementById('mode-legacy');
			if (currency === 'eth' || currency === 'doge') {
				// Disable Legacy mode for Ethereum and Dogecoin
				legacyBtn.style.opacity = '0.5';
				legacyBtn.style.cursor = 'not-allowed';
				legacyBtn.disabled = true;
				
				// Force Argon2id mode if Legacy is currently selected
				if (kdfMode === 'legacy') {
					kdfMode = 'argon2';
					document.getElementById('mode-argon2').classList.add('active');
					document.getElementById('mode-legacy').classList.remove('active');
					updateSaltFieldsVisibility();
				}
			} else {
				// Enable Legacy mode for BTC/LTC
				legacyBtn.style.opacity = '1';
				legacyBtn.style.cursor = 'pointer';
				legacyBtn.disabled = false;
			}
		}

        //MODE SELECTION
        document.getElementById('login').addEventListener('click', function() {
			mode = 0;
			document.getElementById('login').classList.add("active");
			document.getElementById('personal').classList.remove("active");
			document.getElementById('generic').classList.remove("active");
			document.getElementById('loginsalt').style.display = 'block';
			document.getElementById('personalsalt').style.display = 'none';
			document.getElementById('genericsalt').style.display = 'none';
        });

        document.getElementById('personal').addEventListener('click', function() {
			mode = 1;
			document.getElementById('login').classList.remove("active");
			document.getElementById('personal').classList.add("active");
			document.getElementById('generic').classList.remove("active");
			document.getElementById('loginsalt').style.display = 'none';
			document.getElementById('personalsalt').style.display = 'block';
			document.getElementById('genericsalt').style.display = 'none';
        });

        document.getElementById('generic').addEventListener('click', function() {
			mode = 2;
			document.getElementById('login').classList.remove("active");
			document.getElementById('personal').classList.remove("active");
			document.getElementById('generic').classList.add("active");
			document.getElementById('loginsalt').style.display = 'none';
			document.getElementById('personalsalt').style.display = 'none';
			document.getElementById('genericsalt').style.display = 'block';
        });

		//clear results when input is changed
		var clearButtons = document.querySelectorAll('.modebutton, .currencybutton, .mode-button, #random');
		clearButtons.forEach(function(button) {
			button.addEventListener('click', function() {
				if (busy === 0) {
					document.getElementById('result').style.display = 'none';
				}
			});
		});
		var inputElements = [document.getElementById('passphrase'), document.getElementById('argon2salt1')].concat(Array.from(document.querySelectorAll('.saltinput')));
		inputElements.forEach(function(element) {
			['change', 'paste', 'keyup'].forEach(function(eventType) {
				element.addEventListener(eventType, function(e) {
					// Don't hide results if Enter key was pressed (it's triggering form submission)
					if (eventType === 'keyup' && (e.key === 'Enter' || e.keyCode === 13)) {
						return;
					}
					if (busy === 0) {
						document.getElementById('result').style.display = 'none';
					}
				});
			});
		});

        //filedrop
        var passphraseElement = document.getElementById('passphrase');
        passphraseElement.addEventListener('dragover', function(e) {
            e.preventDefault();
            e.stopPropagation();
            this.classList.add('active');
        });
        passphraseElement.addEventListener('dragenter', function(e) {
            e.preventDefault();
            e.stopPropagation();
            this.classList.add('active');
        });
        passphraseElement.addEventListener('dragleave', function(e) {
            e.preventDefault();
            e.stopPropagation();
            this.classList.remove('active');
        });
        passphraseElement.addEventListener('drop', function(e){
            this.classList.remove('active');
            if(e.dataTransfer){
                if(e.dataTransfer.files.length) {
                    e.preventDefault();
                    e.stopPropagation();
                    var f = e.dataTransfer.files[0];
                    processFile(f);
                }
            }
        });

		document.getElementById('hidepass').addEventListener('click', function() {
			var passhideElements = document.querySelectorAll('.passhide');
			if (this.checked) {
				passhideElements.forEach(function(el) { el.style.display = 'none'; });
			}
			else {
				passhideElements.forEach(function(el) { el.style.display = ''; });
			}
		});
		document.getElementById('hidesalt').addEventListener('click', function() {
			var salthideElements = document.querySelectorAll('.salthide');
			if (this.checked) {
				salthideElements.forEach(function(el) { el.style.display = 'none'; });
			}
			else {
				salthideElements.forEach(function(el) { el.style.display = ''; });
			}
		});

		document.getElementById('hidepriv').addEventListener('click', function() {
			var privateElements = [document.getElementById('private'), document.getElementById('privateQR'), document.getElementById('privatelabel')];
			if (this.checked) {
				privateElements.forEach(function(el) { el.style.display = 'none'; });
			}
			else {
				privateElements.forEach(function(el) { el.style.display = ''; });
			}
		});

        //file selection handler
        document.getElementById('file').addEventListener('change', hashFile, false);
    });
})();