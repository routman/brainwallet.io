// Copyright (c) 2015 Daniel Routman - brainwallet.io
// Licensed under the MIT license
(function($){
	var gen_compressed = false;
	var PUBLIC_KEY_VERSION = 0;
	var PRIVATE_KEY_VERSION = 0x80;

	var mode = 0;
	var busy = 0;
	var passphrase;
	var salts = [];
	var salt;

	//scrypt parameters
	var N = Math.pow(2,18);
	var r = 8;
	var p = 1;
	var L = 32;
	var steps = 256;

	function pad(str, len, ch) {
        padding = '';
        for (var i = 0; i < len - str.length; i++) {
            padding += ch;
        }
        return padding + str;
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

    function makeAddr(phr) {
        var hash = Crypto.SHA256(phr, { asBytes: true });
        hash = Crypto.util.bytesToHex(hash);
        var hash_str = pad(hash, 64, '0');
        var hash = Crypto.util.hexToBytes(hash_str);
        eckey = new Bitcoin.ECKey(hash);
        gen_eckey = eckey;
        var curve = getSECCurveByName("secp256k1");
        gen_pt = curve.getG().multiply(eckey.priv);
        gen_eckey.pub = getEncoded(gen_pt, gen_compressed);
        gen_eckey.pubKeyHash = Bitcoin.Util.sha256ripe160(gen_eckey.pub);
        var eckey = gen_eckey;
        var compressed = gen_compressed;
        var hash160 = eckey.getPubKeyHash();
        var h160 = Crypto.util.bytesToHex(hash160);
        var addr = new Bitcoin.Address(hash160);
        addr.version = PUBLIC_KEY_VERSION;
        $('#addr').text(addr);
        var payload = hash;
        if (compressed)
            payload.push(0x01);
        var sec = new Bitcoin.Address(payload);
        sec.version = PRIVATE_KEY_VERSION;
        $('#private').text(sec);
        $('#privateQR').html('');
        privateQR = new QRCode("privateQR", {
            text: sec,
            width: 164,
            height: 164,
            colorDark : "#000000",
            colorLight : "#ffffff",
            correctLevel : QRCode.CorrectLevel.H
        }).makeCode(sec.toString());
        $('#addrQR').html('');
        addrQR = new QRCode("addrQR", {
            text: addr,
            width: 164,
            height: 164,
            colorDark : "#000000",
            colorLight : "#ffffff",
            correctLevel : QRCode.CorrectLevel.H
        }).makeCode(addr.toString());
        $('#submit').val('generate');
    }

    function hashFile(evt) {
        if (window.File && window.FileReader && window.FileList && window.Blob) {
            var f = evt.target.files[0];
            if (f) {
                var r = new FileReader();
                r.onload = function(e) { 
                    var contents = e.target.result;
                    console.log(f.name);
                    console.log(f.size + ' bytes');
                    setTimeout(function() {
                        var filehash = Crypto.SHA256(contents, { asBytes: true });
                        filehash = Crypto.util.bytesToHex(filehash).toUpperCase();
                        $('#passphrase').val(filehash);
                    }, 200);
                }
                r.readAsText(f);
            } 
            else { 
                alert("Failed to load file.");
            }
        } 
        else {
          alert('This feature is not supported by your browser.');
        }
    }

	$(document).ready( function() {
        $('#passform').submit(function(event) {
        	event.preventDefault();

        	if (busy == 0) {
        		busy = 1;
	            $('#result').hide();            

	            passphrase = $('#passphrase').val();

	            if (mode == 0) { //login salts
					salts[0] = $('#loginsalt1').val();
					salts[1] = $('#loginsalt2').val();
					salts[2] = $('#loginsalt3').val();
					salts[3] = "";
	            }

	            if (mode == 1) { //personal salts
	              	salts[0] = $('#personalsalt1').val();
	              	salts[1] = $('#personalsalt2').val();
	              	salts[2] = $('#personalsalt3').val();
	              	salts[3] = $('#personalsalt4').val(); 
	            }

	            if (mode == 2) { //generic salt
	              	salts[0] = $('#genericsalt1').val();
	              	salts[1] = "";
	              	salts[2] = "";
	              	salts[3] = "";
	            }

	            salt = salts[0]+salts[1]+salts[2]+salts[3];
	            
	            if (!passphrase) {
	              	alert("You must enter a passphrase");
	              	busy = 0;
	            }
	            else if (!salt) {
	              	alert("You must enter at least one salt")
	              	busy = 0;
	            }
	            else {
	            	$('#submit').val('running...');

	            	passphrase = scrypt.encode_utf8(passphrase);
            		salt = scrypt.encode_utf8(salt); 
	              	
	              	scrypt.crypto_scrypt_async(passphrase, salt, N, r, p, L,
			            function(success, result) {
				   			makeAddr(scrypt.to_hex(result));
					      	$('#result').show();
					      	busy = 0;
			            },
			            function(progress) {
			                $('#progressbar').width(progress +'%');
			            },
			        steps);
	            }
	        }
        });

        $('.saltinput').keydown(function(event){
            if(event.keyCode == 13) {
                event.preventDefault();
                return false;
            }
        });

        //MODE SELECTION
        $('#login').click(function() {
			mode = 0;
			$('#login').addClass("active");
			$('#personal').removeClass("active");
			$('#generic').removeClass("active");
			$('#loginsalt').show();
			$('#personalsalt').hide();
			$('#genericsalt').hide();
        });

        $('#personal').click(function() {
			mode = 1;
			$('#login').removeClass("active");
			$('#personal').addClass("active");
			$('#generic').removeClass("active");
			$('#loginsalt').hide();
			$('#personalsalt').show();
			$('#genericsalt').hide();
        });

        $('#generic').click(function() {
			mode = 2;
			$('#login').removeClass("active");
			$('#personal').removeClass("active");
			$('#generic').addClass("active");
			$('#loginsalt').hide();
			$('#personalsalt').hide();
			$('#genericsalt').show();
        });
        
        //FILE DROP
        var zone = new FileDrop('passphrase');
        zone.event('send', function (files) {
            files.each(function (file) {
                file.readData(
                function (str) {
                    setTimeout(function() {
                        var filehash = Crypto.SHA256(str);
                        $('#passphrase').val(filehash.toUpperCase());
                    }, 200); 
                },
                function (e) { alert('Error loading file') },
                'text'
                )
            })
        });

        document.getElementById('file').addEventListener('change', hashFile, false);
    });
})(jQuery);