import { BitArray } from "./gleam.mjs";
import { Ok, Error } from "./gleam.mjs";
import * as crypto from "node:crypto";

export function strong_random_bytes(n) {
  return new BitArray(crypto.randomBytes(32));
}

export function encrypt_internal(input, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('chacha20-poly1305', key.rawBuffer, iv);
  let encrypted = cipher.update(input.rawBuffer);
  cipher.final();
  const tag = cipher.getAuthTag();
  return new BitArray(Buffer.concat([iv, tag, Buffer.from(encrypted)]));
}

export function encrypt_with_internal(input, associatedData, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('chacha20-poly1305', key.rawBuffer, iv);
  cipher.setAAD(associatedData.rawBuffer);
  let encrypted = cipher.update(input.rawBuffer);
  cipher.final();
  const tag = cipher.getAuthTag();
  return new BitArray(Buffer.concat([iv, tag, Buffer.from(encrypted)]));
}

export function decrypt_internal(input, key) {
  try {
    const iv = Buffer.copyBytesFrom(input.rawBuffer, 0, 12);
    const tag = Buffer.copyBytesFrom(input.rawBuffer, 12, 16);
    const encrypted = Buffer.copyBytesFrom(input.rawBuffer, 28);
    const decipher = crypto.createDecipheriv('chacha20-poly1305', key.rawBuffer, iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(encrypted);
    decipher.final();
    return new Ok(new BitArray(decrypted));
  } catch {
    return new Error(null);
  }
}

export function decrypt_with_internal(input, associatedData, key) {
  try {
    const iv = Buffer.copyBytesFrom(input.rawBuffer, 0, 12);
    const tag = Buffer.copyBytesFrom(input.rawBuffer, 12, 16);
    const encrypted = Buffer.copyBytesFrom(input.rawBuffer, 28);
    const decipher = crypto.createDecipheriv('chacha20-poly1305', key.rawBuffer, iv);
    decipher.setAuthTag(tag);
    decipher.setAAD(associatedData.rawBuffer);
    let decrypted = decipher.update(encrypted);
    decipher.final();
    return new Ok(new BitArray(decrypted));
  } catch {
    return new Error(null);
  }
}
