export function Uint8ArrayToBase64(data: Uint8Array | ArrayBuffer): string {
  const uint8 = data instanceof Uint8Array ? data : new Uint8Array(data);
  const binary = String.fromCharCode(...uint8);
  return btoa(binary);
}

export function hexToUint8Array(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("Hex string contains invalid characters");
  }

  if (hex.length % 2 !== 0) {
    throw new Error("Hex string must have an even length");
  }

  const uint8Array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < uint8Array.length; i++) {
    uint8Array[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return uint8Array;
}

export function Uint8ArrayToHex(uint8Array: Uint8Array): string {
  return [...uint8Array].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function stringToUint8Array(str: string): Uint8Array {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

export function hexToBase64(hex: string): string {
  return Uint8ArrayToBase64(hexToUint8Array(hex));
}
