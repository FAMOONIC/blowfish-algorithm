import { DIGIT_PHI_HEX } from './digit-phi.js';

class Blowfish {
  constructor(keyBytes) {
    if (keyBytes.length < 4 || keyBytes.length > 56) {
      throw new Error('Kunci harus 4–56 byte (32–448 bit)');
    }

    this.P = new Array(18);
    this.S = [new Array(256), new Array(256), new Array(256), new Array(256)];

    this._initFromPhi();
    this._keySchedule(keyBytes);
    this._buildSubkeys();
  }

  _initFromPhi() {
    const phiBytes = this._hexToBytes(DIGIT_PHI_HEX);
    let idx = 0;

    // Inisialisasi P-array (18 × 32-bit = 72 byte)
    for (let i = 0; i < 18; i++) {
      this.P[i] = this._bytesToWord(phiBytes.slice(idx, idx + 4));
      idx += 4;
    }

    // Inisialisasi 4 S-box (4 × 256 × 4 = 4096 byte)
    for (let box = 0; box < 4; box++) {
      for (let i = 0; i < 256; i++) {
        this.S[box][i] = this._bytesToWord(phiBytes.slice(idx, idx + 4));
        idx += 4;
      }
    }
  }

  _keySchedule(keyBytes) {
    // XOR P-array dengan kunci (diulang jika kunci lebih pendek)
    for (let i = 0; i < 18; i++) {
      let word = 0;
      for (let j = 0; j < 4; j++) {
        const k = keyBytes[(i * 4 + j) % keyBytes.length];
        word = (word << 8) | k;
      }
      this.P[i] ^= (word >>> 0);
    }
  }

  _buildSubkeys() {
    // membuat P dan S menggunakan enkripsi internal berantai
    let xl = 0, xr = 0;

    // Isi ulang P[1]–P[18]
    for (let i = 0; i < 18; i += 2) {
      [xl, xr] = this._encryptBlock(xl, xr);
      this.P[i] = xl;
      this.P[i + 1] = xr;
    }

    // Isi ulang S-box
    for (let box = 0; box < 4; box++) {
      for (let i = 0; i < 256; i += 2) {
        [xl, xr] = this._encryptBlock(xl, xr);
        this.S[box][i] = xl;
        this.S[box][i + 1] = xr;
      }
    }
  }

  _encryptBlock(xl, xr) {
    // 16-round Feistel Network
    for (let i = 0; i < 16; i++) {
      xl ^= this.P[i];
      xr ^= this._F(xl);
      [xl, xr] = [xr, xl]; // swap
    }
    // Undo last swap
    [xl, xr] = [xr, xl];
    // Final XOR
    xr ^= this.P[16];
    xl ^= this.P[17];
    return [xl, xr];
  }

  _decryptBlock(xl, xr) {
    // Gunakan P-array dalam urutan terbalik
    for (let i = 17; i > 1; i--) {
      xl ^= this.P[i];
      xr ^= this._F(xl);
      [xl, xr] = [xr, xl];
    }
    [xl, xr] = [xr, xl];
    xr ^= this.P[1];
    xl ^= this.P[0];
    return [xl, xr];
  }

  _F(x) {
    // Fungsi F: non-linear substitution
    const a = (x >> 24) & 0xFF;
    const b = (x >> 16) & 0xFF;
    const c = (x >> 8) & 0xFF;
    const d = x & 0xFF;

    let r = (this.S[0][a] + this.S[1][b]) & 0xFFFFFFFF;
    r ^= this.S[2][c];
    r = (r + this.S[3][d]) & 0xFFFFFFFF;
    return r;
  }

  _bytesToWord(b) {
    return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
  }

  _wordToBytes(w) {
    return [
      (w >> 24) & 0xFF,
      (w >> 16) & 0xFF,
      (w >> 8) & 0xFF,
      w & 0xFF
    ];
  }

  _hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
      bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
  }

  _padTo64Bit(bytes) {
    // Padding null hingga kelipatan 8 byte (64 bit)
    while (bytes.length % 8 !== 0) {
      bytes.push(0);
    }
    return bytes;
  }

  encrypt(plainBytes) {
    const padded = this._padTo64Bit([...plainBytes]);
    const out = [];
    for (let i = 0; i < padded.length; i += 8) {
      const xl = this._bytesToWord(padded.slice(i, i + 4));
      const xr = this._bytesToWord(padded.slice(i + 4, i + 8));
      const [cl, cr] = this._encryptBlock(xl, xr);
      out.push(...this._wordToBytes(cl), ...this._wordToBytes(cr));
    }
    return out;
  }

  decrypt(cipherBytes) {
    const out = [];
    for (let i = 0; i < cipherBytes.length; i += 8) {
      const xl = this._bytesToWord(cipherBytes.slice(i, i + 4));
      const xr = this._bytesToWord(cipherBytes.slice(i + 4, i + 8));
      const [pl, pr] = this._decryptBlock(xl, xr);
      out.push(...this._wordToBytes(pl), ...this._wordToBytes(pr));
    }
    // Hapus padding null di akhir
    while (out.length > 0 && out[out.length - 1] === 0) {
      out.pop();
    }
    return out;
  }
}

export default Blowfish;