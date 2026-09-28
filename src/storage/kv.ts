import type { Document, Env } from "../types";
import { decryptFileStream, encryptFileStream, type FileCrypto } from "../security/vault-crypto";

export function storageKey(): string {
  return `documents/${crypto.randomUUID()}`;
}

function checkKey(key: string): void {
  if (!/^documents\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(key))
    throw new Error("Invalid storage key");
}

export async function storeDocument(
  env: Env,
  vaultId: string,
  documentId: string,
  key: string,
  source: ReadableStream<Uint8Array>,
  size: number,
): Promise<FileCrypto> {
  checkKey(key);
  const { stream, metadata } = await encryptFileStream(env, vaultId, documentId, key, size, source);
  await env.DOCUMENTS.put(key, stream);
  return metadata;
}

export async function loadDocument(
  env: Env,
  document: Document,
): Promise<ReadableStream<Uint8Array> | null> {
  checkKey(document.storage_key);
  const encrypted = await env.DOCUMENTS.get(document.storage_key, "stream");
  return encrypted ? decryptFileStream(env, document, encrypted) : null;
}

export async function removeDocument(env: Env, key: string): Promise<void> {
  checkKey(key);
  await env.DOCUMENTS.delete(key);
}

export async function documentExists(env: Env, key: string): Promise<boolean> {
  checkKey(key);
  const stream = await env.DOCUMENTS.get(key, "stream");
  if (!stream) return false;
  await stream.cancel();
  return true;
}
