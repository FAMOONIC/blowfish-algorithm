import Blowfish from './blowfish.js';
import { stringToBytes, bytesToString, bytesToHex, hexToBytes } from './konversi.js';

//enkripsi
document.getElementById('encryptBtn').addEventListener('click', () => {
  const key = document.getElementById('enc-key').value;
  const plaintext = document.getElementById('enc-plaintext').value;

  if (!key || !plaintext) {
    alert('Harap isi kunci dan plaintext!');
    return;
  }

  try {
    const keyBytes = stringToBytes(key);
    const bf = new Blowfish(keyBytes);
    const plainBytes = stringToBytes(plaintext);
    const cipherBytes = bf.encrypt(plainBytes);
    document.getElementById('enc-ciphertext').value = bytesToHex(cipherBytes);
  } catch (e) {
    alert('Error enkripsi: ' + e.message);
  }
});

//dekripsi
document.getElementById('decryptBtn').addEventListener('click', () => {
  const key = document.getElementById('dec-key').value;
  const hexCipher = document.getElementById('dec-ciphertext').value.trim();

  if (!key || !hexCipher) {
    alert('Harap isi kunci dan ciphertext!');
    return;
  }

  // Validasi hex
  if (hexCipher.length % 2 !== 0 || !/^[0-9A-Fa-f]*$/.test(hexCipher)) {
    alert('Ciphertext harus dalam format hex yang valid!');
    return;
  }

  try {
    const keyBytes = stringToBytes(key);
    const bf = new Blowfish(keyBytes);
    const cipherBytes = hexToBytes(hexCipher);
    const plainBytes = bf.decrypt(cipherBytes);
    document.getElementById('dec-plaintext').value = bytesToString(plainBytes);
  } catch (e) {
    alert('Error dekripsi: ' + e.message);
  }
});

//untuk salin cipertext
document.getElementById('copyToDecrypt').addEventListener('click', () => {
  const cipher = document.getElementById('enc-ciphertext').value.trim();
  if (!cipher) {
    alert('Tidak ada ciphertext untuk disalin!');
    return;
  }
  document.getElementById('dec-ciphertext').value = cipher;
  alert('Ciphertext berhasil disalin ke form dekripsi!');
});