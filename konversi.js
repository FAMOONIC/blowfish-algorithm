export function stringToBytes(str) {
  const encoder = new TextEncoder();
  return Array.from(encoder.encode(str));
}

export function bytesToString(bytes) {
  const decoder = new TextDecoder();
  return decoder.decode(new Uint8Array(bytes));
}

export function hexToBytes(hex) {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return bytes;
}

export function bytesToHex(bytes) {
  return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
}

export function padTo64Bit(bytes) {
  while (bytes.length % 8 !== 0) bytes.push(0);
  return bytes;
}