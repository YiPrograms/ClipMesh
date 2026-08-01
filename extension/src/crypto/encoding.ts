const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export const utf8 = (value: string): Uint8Array => encoder.encode(value);
export const decodeUtf8 = (value: Uint8Array): string => decoder.decode(value);

export function concat(...values: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(values.reduce((sum, value) => sum + value.length, 0));
  let offset = 0;
  for (const value of values) { result.set(value, offset); offset += value.length; }
  return result;
}

export function base64(value: Uint8Array): string {
  let binary = '';
  for (let offset = 0; offset < value.length; offset += 0x8000) binary += String.fromCharCode(...value.subarray(offset, offset + 0x8000));
  return btoa(binary);
}

export function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function uuidBytes(value: string): Uint8Array {
  const compact = value.replaceAll('-', '');
  if (!/^[0-9a-f]{32}$/i.test(compact)) throw new Error('Invalid UUID');
  return Uint8Array.from(compact.match(/.{2}/g) ?? [], (pair) => Number.parseInt(pair, 16));
}

export function u16(value: number): Uint8Array {
  const result = new Uint8Array(2); new DataView(result.buffer).setUint16(0, value); return result;
}

export function u32(value: number): Uint8Array {
  const result = new Uint8Array(4); new DataView(result.buffer).setUint32(0, value); return result;
}

export function i64(value: number): Uint8Array {
  if (!Number.isSafeInteger(value)) throw new Error('Unsafe i64 value');
  const result = new Uint8Array(8); new DataView(result.buffer).setBigInt64(0, BigInt(value)); return result;
}

export function u64(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('Unsafe u64 value');
  const result = new Uint8Array(8); new DataView(result.buffer).setBigUint64(0, BigInt(value)); return result;
}

export function uuidFromBytes(value: Uint8Array): string {
  if (value.length !== 16) throw new Error('Invalid UUID bytes');
  const hex=[...value].map((byte)=>byte.toString(16).padStart(2,'0')).join('');
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

export function buffer(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer;
}

export function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function uuidv7(now=Date.now()):string{
  const bytes=randomBytes(16);let timestamp=BigInt(now);
  for(let index=5;index>=0;index--){bytes[index]=Number(timestamp&0xffn);timestamp>>=8n;}
  bytes[6]=((bytes[6]??0)&0x0f)|0x70;bytes[8]=((bytes[8]??0)&0x3f)|0x80;
  const hex=[...bytes].map((value)=>value.toString(16).padStart(2,'0')).join('');
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}
