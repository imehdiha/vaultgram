import type { Env, Document, SecureValue } from "../types";
import { base64url, unbase64url } from "./crypto";

const text = new TextEncoder();
const fileDomain = "vaultgram:file:v1";
const valueDomain = "vaultgram:secret:v1";
const chunkSize = 256 * 1024;
const tagSize = 16;
const hkdfSalt = text.encode("vaultgram:hkdf:v1");

async function recordKey(
  secret: string,
  domain: string,
  vaultId: string,
  recordId: string,
  revision: string,
): Promise<CryptoKey> {
  const master = unbase64url(secret);
  if (master.byteLength !== 32) throw new Error("Invalid vault encryption key");
  const base = await crypto.subtle.importKey("raw", master, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: hkdfSalt,
      info: text.encode(`${domain}\0${vaultId}\0${recordId}\0${revision}`),
    },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function fileIv(prefix: Uint8Array, index: number): Uint8Array<ArrayBuffer> {
  if (prefix.byteLength !== 8 || index > 0xffffffff) throw new Error("Invalid file nonce");
  const iv = new Uint8Array(12);
  iv.set(prefix);
  new DataView(iv.buffer).setUint32(8, index, false);
  return iv;
}

function fileAad(
  vaultId: string,
  documentId: string,
  storageKey: string,
  size: number,
  index: number,
): Uint8Array<ArrayBuffer> {
  return text.encode(`${fileDomain}\0${vaultId}\0${documentId}\0${storageKey}\0${size}\0${index}`);
}

type ReaderState = { carry: Uint8Array<ArrayBuffer> };
async function take(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  state: ReaderState,
  length: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const out = new Uint8Array(length);
  let written = 0;
  while (written < length) {
    if (state.carry.byteLength === 0) {
      const next = await reader.read();
      if (next.done) throw new Error("Truncated encrypted stream");
      state.carry = new Uint8Array(next.value);
      continue;
    }
    const count = Math.min(length - written, state.carry.byteLength);
    out.set(state.carry.subarray(0, count), written);
    written += count;
    state.carry = state.carry.slice(count);
  }
  return out;
}

async function ensureEnd(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  state: ReaderState,
): Promise<void> {
  if (state.carry.byteLength || !(await reader.read()).done)
    throw new Error("Encrypted stream length mismatch");
}

export type FileCrypto = { encryption_version: 1; crypto_iv: string };
export async function encryptFileStream(
  env: Env,
  vaultId: string,
  documentId: string,
  storageKey: string,
  size: number,
  source: ReadableStream<Uint8Array>,
): Promise<{ stream: ReadableStream<Uint8Array>; metadata: FileCrypto }> {
  if (!Number.isSafeInteger(size) || size < 0 || size > 20_000_000)
    throw new Error("Invalid document size");
  const key = await recordKey(env.VAULT_ENCRYPTION_KEY, fileDomain, vaultId, documentId, storageKey);
  const prefix = crypto.getRandomValues(new Uint8Array(8));
  const reader = source.getReader();
  const state: ReaderState = { carry: new Uint8Array(0) };
  const chunks = Math.max(1, Math.ceil(size / chunkSize));
  let index = 0;
  return {
    metadata: { encryption_version: 1, crypto_iv: base64url(prefix) },
    stream: new ReadableStream<Uint8Array>({
      async pull(controller) {
        if (index >= chunks) {
          await ensureEnd(reader, state);
          controller.close();
          return;
        }
        const length = size === 0 ? 0 : Math.min(chunkSize, size - index * chunkSize);
        const plain = await take(reader, state, length);
        const cipher = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv: fileIv(prefix, index), additionalData: fileAad(vaultId, documentId, storageKey, size, index) },
          key,
          plain,
        );
        index++;
        controller.enqueue(new Uint8Array(cipher));
      },
      cancel(reason) { return reader.cancel(reason); },
    }),
  };
}

export async function decryptFileStream(
  env: Env,
  document: Document,
  encrypted: ReadableStream<Uint8Array>,
): Promise<ReadableStream<Uint8Array>> {
  if (document.encryption_version !== 1) throw new Error("Unsupported file encryption version");
  const prefix = unbase64url(document.crypto_iv);
  if (prefix.byteLength !== 8) throw new Error("Invalid file nonce");
  const key = await recordKey(env.VAULT_ENCRYPTION_KEY, fileDomain, document.vault_id, document.id, document.storage_key);
  const reader = encrypted.getReader();
  const state: ReaderState = { carry: new Uint8Array(0) };
  const chunks = Math.max(1, Math.ceil(document.size_bytes / chunkSize));
  let index = 0;
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (index >= chunks) {
        await ensureEnd(reader, state);
        controller.close();
        return;
      }
      const length = document.size_bytes === 0 ? 0 : Math.min(chunkSize, document.size_bytes - index * chunkSize);
      const cipher = await take(reader, state, length + tagSize);
      const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fileIv(prefix, index), additionalData: fileAad(document.vault_id, document.id, document.storage_key, document.size_bytes, index) },
        key,
        cipher,
      );
      index++;
      controller.enqueue(new Uint8Array(plain));
    },
    cancel(reason) { return reader.cancel(reason); },
  });
}

export type ValueCrypto = Pick<SecureValue, "ciphertext" | "crypto_iv" | "crypto_revision" | "encryption_version">;
export async function encryptSecureValue(
  env: Env,
  vaultId: string,
  valueId: string,
  plain: string,
): Promise<ValueCrypto> {
  if (text.encode(plain).byteLength > 3000) throw new Error("Secure value is too long");
  const revision = crypto.randomUUID();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await recordKey(env.VAULT_ENCRYPTION_KEY, valueDomain, vaultId, valueId, revision);
  const aad = text.encode(`${valueDomain}\0${vaultId}\0${valueId}\0${revision}`);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, key, text.encode(plain));
  return { ciphertext: base64url(new Uint8Array(cipher)), crypto_iv: base64url(iv), crypto_revision: revision, encryption_version: 1 };
}

export async function decryptSecureValue(env: Env, value: SecureValue): Promise<string> {
  if (value.encryption_version !== 1) throw new Error("Unsupported value encryption version");
  const iv = unbase64url(value.crypto_iv);
  if (iv.byteLength !== 12) throw new Error("Invalid value nonce");
  const key = await recordKey(env.VAULT_ENCRYPTION_KEY, valueDomain, value.vault_id, value.id, value.crypto_revision);
  const aad = text.encode(`${valueDomain}\0${value.vault_id}\0${value.id}\0${value.crypto_revision}`);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad }, key, unbase64url(value.ciphertext));
  return new TextDecoder("utf-8", { fatal: true }).decode(plain);
}
