async function encryptFile(file, password) {
    const keyMaterial = await getKeyMaterial(password);
    const key = await getEncryptionKey(keyMaterial);

    const fileData = await file.arrayBuffer();

    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedData = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        fileData
    );

    const combinedData = new Uint8Array(iv.byteLength + encryptedData.byteLength);
    combinedData.set(iv, 0);
    combinedData.set(new Uint8Array(encryptedData), iv.byteLength);

    return combinedData;
}

async function decryptFile(encryptedFile, password) {
    const keyMaterial = await getKeyMaterial(password);
    const key = await getEncryptionKey(keyMaterial);

    const iv = encryptedFile.slice(0, 12);
    const encryptedData = encryptedFile.slice(12);

    const decryptedData = await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        encryptedData
    );

    return decryptedData;
}

async function getKeyMaterial(password) {
    const encoder = new TextEncoder();
    return window.crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
}

async function getEncryptionKey(keyMaterial) {
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: new TextEncoder().encode("securefiles-salt"),
            iterations: 100000,
            hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

let processedFileBlob = null;
let GisEncrypt = false;

function handleFileUpload(isEncrypt) {
    const file = document.getElementById("file").files[0];
    const password = document.getElementById("password").value;
    if (!file || !password) {
        alert("Please upload a file and enter a password.");
        return;
    }

    const reader = new FileReader();

    reader.onload = async function () {
        const fileData = new Uint8Array(reader.result);

        try {
            const result = isEncrypt
                ? await encryptFile(file, password)
                : await decryptFile(fileData, password);
            processedFileBlob = new Blob([result], { type: file.type });

            const downloadButton = document.getElementById("downloadButton");
            downloadButton.style.display = "inline-block";
            downloadButton.textContent = isEncrypt ? "Download Encrypted File" : "Download Decrypted File";
            GisEncrypt = isEncrypt;
        } catch (error) {
            alert("Error: " + error.message);
        }
    };

    reader.readAsArrayBuffer(file);
}

function downloadProcessedFile() {
    if (processedFileBlob) {
        const downloadLink = document.createElement("a");
        const url = URL.createObjectURL(processedFileBlob);

        downloadLink.href = url;
        downloadLink.download = GisEncrypt
            ? document.getElementById("file").files[0].name + ".enc"
            : document.getElementById("file").files[0].name.replace(".enc", "");
        downloadLink.click();

        URL.revokeObjectURL(url);
    } else {
        alert("No file is ready to download. Please encrypt or decrypt a file first.");
    }
}

function evaluatePasswordStrength(password) {
    const strengthIndicator = document.getElementById("strength-indicator");
    const strength = calculatePasswordStrength(password);

    strengthIndicator.style.width = `${strength.percentage}%`;

    strengthIndicator.className = "";
    if (strength.strength === "Weak") {
        strengthIndicator.classList.add("strength-weak");
    } else if (strength.strength === "Medium") {
        strengthIndicator.classList.add("strength-medium");
    } else {
        strengthIndicator.classList.add("strength-strong");
    }
}

function calculatePasswordStrength(password) {
    let strength = 0;
    const lengthCriteria = password.length >= 8;
    const numberCriteria = /\d/.test(password);
    const lowercaseCriteria = /[a-z]/.test(password);
    const uppercaseCriteria = /[A-Z]/.test(password);
    const specialCharCriteria = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (lengthCriteria) strength += 1;
    if (numberCriteria) strength += 1;
    if (lowercaseCriteria) strength += 1;
    if (uppercaseCriteria) strength += 1;
    if (specialCharCriteria) strength += 1;

    let strengthLevel = "Weak";
    let percentage = (strength / 5) * 100;

    if (strength >= 4) {
        strengthLevel = "Strong";
    } else if (strength >= 3) {
        strengthLevel = "Medium";
    }

    return { strength: strengthLevel, percentage: percentage };
}

document.getElementById("password").addEventListener("input", function () {
    const password = this.value;
    evaluatePasswordStrength(password);
});
