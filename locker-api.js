link: https://luarmor.net/locker_api.js


// helper fns
let stringToArrayBuffer = function (str) {
    const encoder = new TextEncoder();
    return encoder.encode(str);
}
let arrayBufferToString = function (buffer) {
    const decoder = new TextDecoder();
    return decoder.decode(buffer);
}

let arrayBufferToBase64Depr = function (buffer) {
    const binary = String.fromCharCode(...new Uint8Array(buffer)); // causes stackoverflow due to arg # limit 64kb on chrome v8 and 32kb on firefox
    return btoa(binary);
}


let arrayBufferToBase64 = function (buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const chunkSize = 0x8000; // Process in 32KB chunks

    for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
    }

    return btoa(binary);
};



let base64ToArrayBuffer = function (base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}



// PBKDF2 for bip39 seed->aes gcm
async function deriveKey(bip39IdxArr, serverSalt) {
    //console.log("bip39IdxArr:", bip39IdxArr);
    //console.log("serverSalt:", serverSalt);
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        bip39IdxArr,
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: enc.encode(serverSalt),
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

async function encryptAESGCM(text, key) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encodedText = stringToArrayBuffer(text);

    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encodedText
    );


    const encryptedArray = new Uint8Array(iv.length + encrypted.byteLength);
    encryptedArray.set(iv);
    encryptedArray.set(new Uint8Array(encrypted), iv.length);

    return encryptedArray;
}


async function decryptAESGCM(encryptedArray, key) {
    //console.log("requested decr via ", encryptedArray, key);
    const iv = encryptedArray.slice(0, 12);
    const data = encryptedArray.slice(12);

    const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        data
    );

    return arrayBufferToString(decrypted);
}


let wordlistResp;
let wordList;

async function loadWordlist() {
    wordlistResp = await fetch('./bip39_wordlist.json');
    wordList = await wordlistResp.json();
    return true;
}

async function bip39WordsToUint8Array(mnemonicArray) {
    if (!wordList) {
        await loadWordlist();
    }
    try {

        if (!Array.isArray(wordList)) {
            throw new Error("Word list must be an array");
        }

        const indexArray = mnemonicArray.map(word => {
            const index = wordList.indexOf(word);
            if (index === -1) {
                Swal.fire("Error", "Invalid BIP39 word, reload the page and try again.", "error").then(() => {
                    location.reload();
                });
            }
            return index;
        });

        const byteArray = [];

        let bitStream = indexArray.map(num => num.toString(2).padStart(11, '0')).join('');


        for (let i = 0; i < bitStream.length; i += 8) {
            let byteChunk = bitStream.slice(i, i + 8);
            byteArray.push(parseInt(byteChunk.padEnd(8, '0'), 2)); // << (pad)
        }

        //console.log("aes deriv key:", byteArray);

        return new Uint8Array(byteArray);
    } catch (error) {
        console.error('Error:', error);
        return null;
    }
}


const mnemonicWords = ["abandon", "ability", "able", "about", "zoo"];  // Example BIP39 mnemonic words

bip39WordsToUint8Array(mnemonicWords).then(result => {
    //console.log('Uint8Array:', result);
});

async function generateRSAKeyPair() { // main keys responsible for the encryption & decryption of the master AES_GCM key(s) for each script.
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true, //extractable
        ["encrypt", "decrypt"]
    );

    const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

    return {
        publicKey: arrayBufferToBase64(publicKey),
        privateKey: arrayBufferToBase64(privateKey)
    };
};


async function encryptRSA(publicKeyBase64, data) {
    const publicKey = await crypto.subtle.importKey(
        "spki",
        base64ToArrayBuffer(publicKeyBase64),
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        false,
        ["encrypt"]
    );

    const encodedData = new TextEncoder().encode(data);
    const encryptedData = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        encodedData
    );

    return arrayBufferToBase64(encryptedData);
}

async function decryptRSA(privateKeyBase64, encryptedDataBase64) {
    //console.log("attempting to decrypt RSA data", privateKeyBase64, encryptedDataBase64);
    const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        base64ToArrayBuffer(privateKeyBase64),
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        false,
        ["decrypt"]
    );
    //console.log("key was imported fine")
    const encryptedData = base64ToArrayBuffer(encryptedDataBase64);
    const decryptedData = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        encryptedData
    );

    return new TextDecoder().decode(decryptedData);
}





let locker_session_id = "";
try {
    locker_session_id = localStorage.getItem("locker_session_id");
    if (!locker_session_id || typeof locker_session_id !== "string" || locker_session_id.length !== 60) {
        locker_session_id = undefined;
    }
} catch { }
let baseUrl2 = "https://luarmor.net/v3";
let Http2 = {
    auth: localStorage.getItem("api_key"),
    get: function (url, callback) {
        var xhr = new XMLHttpRequest();
        xhr.open("GET", url, callback != undefined);
        xhr.setRequestHeader("Authorization", this.auth);
        if (locker_session_id) {
            xhr.setRequestHeader("lockersessionid", locker_session_id);
        }
        xhr.setRequestHeader("Content-Type", "application/json");
        if (callback != undefined) {
            xhr.onload = function () {
                callback(xhr.responseText);
            }
        }
        xhr.send();
        if (!callback) {
            return xhr.responseText;
        }
    },
    post: function (url, data, callback) {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", url, callback != undefined);
        xhr.setRequestHeader("Authorization", this.auth);
        xhr.setRequestHeader("Content-Type", "application/json");
        if (locker_session_id) {
            xhr.setRequestHeader("lockersessionid", locker_session_id);
        }
        if (callback != undefined) {
            xhr.onload = function () {
                callback(xhr.responseText);
            }
        }
        xhr.send(JSON.stringify(data));
        if (!callback) {
            return xhr.responseText;
        }
    },
    delete: function (url, callback) {
        var xhr = new XMLHttpRequest();
        xhr.open("DELETE", url, callback != undefined);
        xhr.setRequestHeader("Authorization", this.auth);
        xhr.setRequestHeader("Content-Type", "application/json");
        if (locker_session_id) {
            xhr.setRequestHeader("lockersessionid", locker_session_id);
        }
        if (callback != undefined) {
            xhr.onload = function () {
                callback(xhr.responseText);
            }
        }
        xhr.send();
        if (!callback) {
            return xhr.responseText;
        }
    },
    put: function (url, data, callback) {
        var xhr = new XMLHttpRequest();
        xhr.open("PUT", url, callback != undefined);
        xhr.setRequestHeader("Authorization", this.auth);
        xhr.setRequestHeader("Content-Type", "application/json");
        if (locker_session_id) {
            xhr.setRequestHeader("lockersessionid", locker_session_id);
        }
        if (callback != undefined) {
            xhr.onload = function () {
                callback(xhr.responseText);
            }
        }
        xhr.send(JSON.stringify(data));
        if (!callback) {
            return xhr.responseText;
        }
    }
}


async function LockAndUpload(project_id, script, metadata, rsaPub, aesGcmServerSalt) {
    // generate random 
    let aesGcmKeySeed = window.crypto.getRandomValues(new Uint8Array(32));
    let aesGcmKey = await deriveKey(aesGcmKeySeed, aesGcmServerSalt);
    let encryptedScript = await encryptAESGCM(script, aesGcmKey);

    let rsaEncryptedAesGcmKey = await encryptRSA(rsaPub, arrayBufferToBase64(aesGcmKeySeed));
    // server will receive an encrypted aes gcm key, with no way to decrypt it since raw RSA private key is not shared with server. (RSA priv. key is only sent in an encrypted form during locker configuration process, encrypted with your master AES GCM key (derived from the 12-word seed.))

    let filename = metadata.file_name;
    let placeholder = { file_name_word_spacing: [] }
    // split the filename into spaces and add the length of each word to the placeholder
    filename.split(" ").forEach(word => {
        placeholder.file_name_word_spacing.push(word.length); // to make it look "real" behind the blurred div, kind of like an illusion.
    });

    // encrypt the metadata
    let encryptedMetadata = await encryptAESGCM(JSON.stringify(metadata), aesGcmKey);


    let uploadData = {
        encrypted_script: arrayBufferToBase64(encryptedScript),
        aes_gcm_with_rsa_pub: rsaEncryptedAesGcmKey,
        metadata: arrayBufferToBase64(encryptedMetadata),
        placeholder: placeholder,
        locker_salt: aesGcmServerSalt // this was received from the server upon script obfuscation, serves no actual purpose, just a way to prevent spam.
    };

    //console.log("uploadData:", uploadData);

    let resp = await Http2.post(`${baseUrl2}/projects/${project_id}/scripts/lock`, uploadData);
    //console.log("upload resp:", resp);
    return resp;


}

let initialData;

async function loadInitialData() {
    let resp = await Http2.get(`${baseUrl2}/locker/data`);
    let data = JSON.parse(resp);
    if (!data || !data.success) {
        Swal.fire("Error", data && data.message || "Failed to load locker data", "error");
        return;
    }
    if (!data.is_unlocked) {
        // delete session id
        try {
            localStorage.removeItem("locker_session_id");
        } catch { }
        initialData = data;
        return data;
    }

    initialData = data;
    return data;
}

async function InitLocker() {
    let resp = await Http2.post(`${baseUrl2}/locker/init`);
    let data = JSON.parse(resp);
    if (!data || !data.success) {
        Swal.fire("Error", data && data.message || "Failed to initialize locker", "error");
        return;
    }

    // check if mfa is required
    if (data.mfa_required) {
        let mfa_code = await Swal.fire({
            title: 'MFA Required',
            input: 'text',
            inputLabel: 'Enter MFA Code',
            inputPlaceholder: 'Enter your MFA code',
            showCancelButton: true,
            confirmButtonText: 'Submit',
            showLoaderOnConfirm: true,
            preConfirm: (mfa_code) => {
                // trim it nicee
                mfa_code = mfa_code.trim();
                return Http2.put(`${baseUrl2}/locker/init`, { mfa_code, mfa_callback_token: data.mfa_callback_token });
            },
            inputAttributes: {
                style: 'color: white; font-weight: bold; text-align: center; width: 60%; margin-left: 20%;'
            },
            inputValidator: (value) => {
                if (!value) {
                    return 'You need to enter the MFA code!';
                }
            }

        });
        try {
            mfa_code = { value: JSON.parse(mfa_code.value) };
        } catch { }
        if (mfa_code.value && mfa_code.value.success) {
            data = mfa_code.value
            if (!data || !data.success) {
                Swal.fire("Error", data && data.message || "Failed to initialize locker", "error");
                return;
            }


            if (data.encrypted_rsa_pair_required) {
                let done = false;
                // generate bip39 words
                if (!wordList) {
                    await loadWordlist();
                }

                while (!done) {
                    let bip39Words = [];
                    // generate secure bip39 words through crypto API randomness (math.random sucks)
                    for (let i = 0; i < 12; i++) {
                        let idx = window.crypto.getRandomValues(new Uint32Array(1))[0] % wordList.length;
                        bip39Words.push(wordList[idx]);
                    }
                    // show the bip39 words to the user, and ask them write them down or take a photo of them with their phone.
                    let swalCb = await Swal.fire({
                        title: 'BIP39 Passphrase',
                        width: '600px',
                        html: `
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                        <!-- left column (words 1 to 6) -->
                        <div style="display: grid; grid-template-columns: 30px 1fr; gap: 5px;">
                            <label for="word1">1</label><input type="text" id="wbipword1" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" value="${bip39Words[0]}" readonly>
                            <label for="word2">2</label><input type="text" id="wbipword2" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" value="${bip39Words[1]}" readonly>
                            <label for="word3">3</label><input type="text" id="wbipword3" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" value="${bip39Words[2]}" readonly>
                            <label for="word4">4</label><input type="text" id="wbipword4" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" value="${bip39Words[3]}" readonly>
                            <label for="word5">5</label><input type="text" id="wbipword5" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" value="${bip39Words[4]}" readonly>
                            <label for="word6">6</label><input type="text" id="wbipword6" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" value="${bip39Words[5]}" readonly>
                        </div>
                        <!-- Right col (7 to 12) -->
                        <div style="display: grid; grid-template-columns: 30px 1fr; gap: 5px;">
                            <label for="word7">7</label><input type="text" id="wbipword7" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" value="${bip39Words[6]}" readonly>
                            <label for="word8">8</label><input type="text" id="wbipword8" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" value="${bip39Words[7]}" readonly>
                            <label for="word9">9</label><input type="text" id="wbipword9" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" value="${bip39Words[8]}" readonly>
                            <label for="word10">10</label><input type="text" id="wbipword10" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" value="${bip39Words[9]}" readonly>
                            <label for="word11">11</label><input type="text" id="wbipword11" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" value="${bip39Words[10]}" readonly>
                            <label for="word12">12</label><input type="text" id="wbipword12" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" value="${bip39Words[11]}" readonly>
                        </div>
                    </div>
                    <p class="mt-4">Please write down these words and keep them safe, or take a photo of them with your phone. They will be used to derive the master AES GCM key for your locker.<br />If you lose these keys, nothing can decrypt the source codes.</p>
                    `,
                        showCancelButton: true,
                        cancelButtonText: 'Generate New',
                        confirmButtonText: 'I have saved them.',
                        allowOutsideClick: false,
                        allowEscapeKey: false
                    });

                    if (swalCb.isConfirmed) {
                        // encrypt the private key with the bip39 seed->aes gcm
                        done = true;
                        let rsaKeys = await generateRSAKeyPair();
                        //console.log("rsaKeys:", rsaKeys);

                        //console.log("bip39Words:", bip39Words);

                        let aesMasterKey = await deriveKey(await bip39WordsToUint8Array(bip39Words), "mkSalt");
                        let rsaPrivEncrypted = await encryptAESGCM(rsaKeys.privateKey, aesMasterKey);
                        locker_session_id = data.session_id;
                        let resp = await Http2.post(`${baseUrl2}/locker/associate_crypto_keys`, { rsa_pub: rsaKeys.publicKey, rsa_priv_aes_gcm: arrayBufferToBase64(rsaPrivEncrypted), ckassoc_callback_token: data.ckassoc_callback_token });
                        //console.log("associate_crypto_keys resp:", resp);
                        resp = JSON.parse(resp);
                        if (!resp || !resp.success) {
                            Swal.fire("Error", resp && resp.message || "Failed to associate crypto keys", "error");
                            return;
                        }
                        Swal.fire("Success", "Locker is now configured and ready to use.", "success").then(() => {
                            localStorage.setItem("locker_session_id", data.session_id);
                            location.reload();
                        });

                    } else {
                        done = false;
                    }
                }
            }

            // set session id
            localStorage.setItem("locker_session_id", data.session_id);
            Swal.fire("Success", "Access granted, now you will enter your decryption keys after clicking OK.", "success").then(() => {
                location.reload();
            });

        } else {
            Swal.fire("Error", mfa_code.value && mfa_code.value.message || "Failed to initialize locker (2)", "error");
            return;
        }
    }

}

async function requireBip39() {
    Swal.fire({
        title: 'Enter your BIP39 Passphrase',
        width: '600px',
        html: `
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                <!-- left column (words 1 to 6) -->
                <div style="display: grid; grid-template-columns: 30px 1fr; gap: 5px;">
                    <label for="word1">1</label><input type="text" id="bipword1" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" placeholder="Word 1">
                    <label for="word2">2</label><input type="text" id="bipword2" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" placeholder="Word 2">
                    <label for="word3">3</label><input type="text" id="bipword3" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" placeholder="Word 3">
                    <label for="word4">4</label><input type="text" id="bipword4" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" placeholder="Word 4">
                    <label for="word5">5</label><input type="text" id="bipword5" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" placeholder="Word 5">
                    <label for="word6">6</label><input type="text" id="bipword6" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" placeholder="Word 6">
                </div>
                <!-- Right col (7 to 12) -->
                <div style="display: grid; grid-template-columns: 30px 1fr; gap: 5px;">
                    <label for="word7">7</label><input type="text" id="bipword7" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" placeholder="Word 7">
                    <label for="word8">8</label><input type="text" id="bipword8" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" placeholder="Word 8">
                    <label for="word9">9</label><input type="text" id="bipword9" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" placeholder="Word 9">
                    <label for="word10">10</label><input type="text" id="bipword10" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" placeholder="Word 10">
                    <label for="word11">11</label><input type="text" id="bipword11" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" placeholder="Word 11">
                    <label for="word12">12</label><input type="text" id="bipword12" class="swal2-input" style="width: 120px; padding: 5px; font-size: 14px;" placeholder="Word 12">
                </div>
            </div>
<p class="mt-4">These words will be used as a seed to derive the 128-bit master AES key. <br />Server will never see this key</p>
        `,
        showCancelButton: true,
        cancelButtonText: 'Forgot?',
        confirmButtonText: 'OK',
        focusConfirm: false,
        allowOutsideClick: false,
        allowEscapeKey: false,
        preConfirm: () => {
            let words = [];
            for (let i = 1; i <= 12; i++) {
                let val = document.getElementById(`bipword${i}`).value;
                // trim nice and clean
                words.push(val.trim());
            }
            if (words.some(word => word === "")) {
                Swal.showValidationMessage('All fields must be filled out.');
                return null;
            }


            return words;
        }
    }).then((result) => {
        if (result.isConfirmed) {
            //console.log('Entered passphrase:', result.value);

            // get the Uint8Array from the words
            bip39WordsToUint8Array(result.value).then(async (bip39IdxArr) => {
                // generate a random AES GCM key from a seed
                let kittySeed = window.crypto.getRandomValues(new Uint8Array(32));
                let tempAesGcmKey = await deriveKey(kittySeed, "kitoSalt");

                // save kittySeed in localstorage
                localStorage.setItem("temp_enc_mk", arrayBufferToBase64(kittySeed));
                let attemptedMasterKey = await deriveKey(bip39IdxArr, "mkSalt"); // salt really doesn't matter with a 32 byte seed
                //console.log("attemptedMasterKey:", attemptedMasterKey);
                //console.log("rsapriv_initial_encrypted", initialData.rsa_priv_aes_gcm);
                // decrypt rsa private key
                let rsaPrivKey; try {
                    rsaPrivKey = await decryptAESGCM(base64ToArrayBuffer(initialData.rsa_priv_aes_gcm), attemptedMasterKey);
                } catch { 

                    rsaPrivKey = null;
                } 
                if (!rsaPrivKey) {
                    Swal.fire("Error", "Invalid decryption key, make sure you did not make any typos.", "error");
                    return;
                }
                //console.log("rsaPrivKey:", rsaPrivKey);
                // try to decrypt proof needed
                let proofNeeded = await decryptRSA(rsaPrivKey, initialData.temp_enc_mk_proof_needed);
                if (proofNeeded.length !== 60 || !proofNeeded.startsWith("**valid**,,")) {
                    Swal.fire("Error", "Invalid decryption key", "error");
                    return;
                }

                // encrypt bip39IdxArr with tempAesGcmKey
                let encryptedBip39 = await encryptAESGCM(arrayBufferToBase64(bip39IdxArr), tempAesGcmKey);

                // associate temp key & prove priv key ownership
                let resp = await Http2.post(`${baseUrl2}/locker/associate_temp_key`, { temp_enc_mk: arrayBufferToBase64(encryptedBip39), proof: proofNeeded });
                //console.log("associate temp key resp:", resp);

                resp = JSON.parse(resp);
                if (!resp || !resp.success) {
                    Swal.fire("Error", resp && resp.message || "Failed to associate temp key", "error");
                    return;
                }
                //reload page
                // swal fire success for 2 seconds and then reload the page
                // make duration 2 seconds
                Swal.fire({
                    title: 'Success',
                    icon: 'success',
                    text: 'Decryption key is valid.',
                    timer: 1000,
                    timerProgressBar: true,
                    showConfirmButton: false,
                    allowEscapeKey: false,
                    allowOutsideClick: false,
                    showCancelButton: false
                }).then(() => {
                    location.reload();
                });

            });

        } else if (result.dismiss === Swal.DismissReason.cancel) {
            //console.log('User clicked "Forgot?"');
            Swal.fire("Forgot your passphrase?", "Please contact support to reset your locker. It will delete all encrypted files in the locker with no way to recover them even if you find your Bip39 words later.", "info");
        }
    });
}

async function fetchAndDecrypt(file_id) {
    let resp = await Http2.get(`${baseUrl2}/locker/content?id=${file_id}`);
    let data = JSON.parse(resp);
    if (!data || !data.success) {
        alert(data && data.message || "failed to fetch file, reload page and try again.")
        return;
    }

    let localTempKey;
    try {
        localTempKey = localStorage.getItem("temp_enc_mk");
        if (!localTempKey) {
            error("Temp key not found, please unlock locker first.")
        }
        localTempKey = base64ToArrayBuffer(localTempKey);
        localTempKey = await deriveKey(localTempKey, "kitoSalt");

    } catch { alert("Temp key cant be derived from (2).."); localTempKey = null; }
    if (!localTempKey) {
        alert("Temp key not found, please unlock locker first.")
        return;
    }

    let decryptedMasterKey = await decryptAESGCM(base64ToArrayBuffer(initialData.temp_enc_mk), localTempKey);

    decryptedMasterKey = await deriveKey(base64ToArrayBuffer(decryptedMasterKey), "mkSalt");
    //console.log("derived master::", decryptedMasterKey);

    let rsaPrivKey = await decryptAESGCM(base64ToArrayBuffer(initialData.rsa_priv_aes_gcm), decryptedMasterKey);

    //console.log("rsa priv key::", rsaPrivKey);
    let aesGcmKey = await decryptRSA(rsaPrivKey, data.aes_gcm_rsad);
    aesGcmKey = await deriveKey(base64ToArrayBuffer(aesGcmKey), data.locker_salt);

    let decryptedScript = await decryptAESGCM(base64ToArrayBuffer(data.raw), aesGcmKey);
    return decryptedScript;
}

async function loadPage(from) {
    let resp = await Http2.get(`${baseUrl2}/locker/page?from=${from}`);
    let data = JSON.parse(resp);
    if (!data || !data.success) {
        alert(data && data.message || "failed to fetch page data.")
        return;
    }

    if (!data.files.length) {
        return [];
    }
    let decrypted_metadata_and_stuff = [];

    let localTempKey;
    try {
        localTempKey = localStorage.getItem("temp_enc_mk");
        if (!localTempKey) {
            error("Temp key not found, please unlock locker first.")
        }
        localTempKey = base64ToArrayBuffer(localTempKey);
        localTempKey = await deriveKey(localTempKey, "kitoSalt");

    } catch { alert("Temp key cant be derived from.."); localTempKey = null; }
    if (!localTempKey) {
        alert("Temp key not found, please unlock locker first.")
        return;
    }

    //console.log("decrypting md", initialData.temp_enc_mk);
    //console.log("local temp key", localTempKey);

    let decryptedMasterKey = await decryptAESGCM(base64ToArrayBuffer(initialData.temp_enc_mk), localTempKey);
    //console.log("here", decryptedMasterKey);
    //console.log("rsa priv aes gcm", initialData.rsa_priv_aes_gcm);
    decryptedMasterKey = await deriveKey(base64ToArrayBuffer(decryptedMasterKey), "mkSalt");
    let rsaPrivKey = await decryptAESGCM(base64ToArrayBuffer(initialData.rsa_priv_aes_gcm), decryptedMasterKey);
    //console.log("rsa priv key:", rsaPrivKey);
    for (let i = 0; i < data.files.length; i++) {
        let file = data.files[i];
        try {

            let aesGcmKey = await decryptRSA(rsaPrivKey, file.aes_gcm_rsad);
            aesGcmKey = await deriveKey(base64ToArrayBuffer(aesGcmKey), file.locker_salt);
            let decryptedMetadata = await decryptAESGCM(base64ToArrayBuffer(file.metadata), aesGcmKey);
            decrypted_metadata_and_stuff.push({ metadata: JSON.parse(decryptedMetadata), file_id: file.file_id });
        } catch (error) {
            //console.log("md decr error:", error);
            decrypted_metadata_and_stuff.push({ metadata: { file_name: "âš ï¸ Can't read metadata", file_size: 0, created_at: 0 }, file_id: file.file_id });
        }
    }

    return decrypted_metadata_and_stuff;
}

async function deleteFile(file_id) {
    let resp = await Http2.delete(`${baseUrl2}/locker/content?id=${file_id}`);
    let data = JSON.parse(resp);
    return data;
}

async function killSession() {
    let resp = await Http2.post(`${baseUrl2}/locker/kill_session`);
    let data = JSON.parse(resp);
    return data;
}

let moduleObject = {
    LockAndUpload,
    loadInitialData,
    InitLocker,
    requireBip39,
    fetchAndDecrypt,
    loadPage,
    deleteFile,
    killSession
}
// make it global
window.locker_api = moduleObject;