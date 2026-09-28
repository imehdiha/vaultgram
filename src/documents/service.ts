import type { Category, Document, Env, Message, User } from "../types";
import { id, now, safeName } from "../security/crypto";
import { audit, category, document, Forbidden, one, requireLevel, run } from "../db/repo";
import { file } from "../telegram/api";
import { loadDocument, removeDocument, storageKey, storeDocument } from "../storage/kv";
import { pinRequired, PinRequired } from "../security/pin";
import { vault } from "../db/repo";

export class UploadTooLarge extends Error {
  constructor() { super("Upload exceeds configured size limit"); }
}

const maxBytes = (env: Env) => Math.min(Number(env.MAX_FILE_BYTES) || 20_000_000, 20_000_000);

export async function saveUploadedDocument(
  env: Env,
  user: User,
  msg: Message,
  categoryId?: string,
  documentId?: string,
): Promise<{ documentId: string; categoryId: string; duplicate: boolean }> {
  const db=env.VAULTGRAM_DB;
  const old=documentId?await document(db,documentId):null;
  const c:Category|null=old?await category(db,old.category_id):categoryId?await category(db,categoryId):null;
  if(!c)throw new Forbidden();
  await requireLevel(db,user,c.vault_id,"EDIT");
  const vaultRow=await vault(db,c.vault_id);
  if(!vaultRow)throw new Forbidden();
  if(await pinRequired(env,user,vaultRow,"edit"))throw new PinRequired();
  const receipt=await one<{document_id:string}>(db,"SELECT document_id FROM upload_receipts WHERE chat_id=? AND message_id=?",user.telegram_id,msg.message_id);
  if(receipt)return {documentId:receipt.document_id,categoryId:c.id,duplicate:true};
  const attachment=msg.document??msg.photo?.at(-1);
  if(!attachment)throw new Error("No document in message");
  if(attachment.file_size!==undefined&&attachment.file_size>maxBytes(env))throw new UploadTooLarge();
  const filename=safeName(msg.document?.file_name??`photo-${msg.message_id}.jpg`);
  const suppliedMime=msg.document?.mime_type??(msg.photo?"image/jpeg":"application/octet-stream");
  const mime=suppliedMime.length<=127&&/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/i.test(suppliedMime)?suppliedMime:"application/octet-stream";
  const info=await file(env,attachment.file_id);
  if(info.file_size!==undefined&&info.file_size>maxBytes(env))throw new UploadTooLarge();
  if(!info.file_path||! /^[a-zA-Z0-9_.\/-]+$/.test(info.file_path)||info.file_path.includes("..")||info.file_path.startsWith("/"))
    throw new Error("Invalid Telegram file path");
  const response=await fetch(`https://api.telegram.org/file/bot${env.TELEGRAM_BOT_TOKEN}/${info.file_path}`);
  if(!response.ok||!response.body)throw new Error(`Telegram file HTTP ${response.status}`);
  const size=Number(response.headers.get("content-length")??attachment.file_size??info.file_size);
  if(!Number.isSafeInteger(size)||size<0)throw new Error("Unknown upload size");
  if(size>maxBytes(env))throw new UploadTooLarge();
  const documentIdToWrite=old?.id??id(),key=storageKey(),timestamp=now();
  const cryptoMeta=await storeDocument(env,c.vault_id,documentIdToWrite,key,response.body,size);
  try{
    if(old){
      const cleanupId=id();
      const results=await db.batch([
        db.prepare("INSERT INTO kv_cleanup_jobs(id,storage_key,reason,created_at) VALUES(?,?,?,?)").bind(cleanupId,old.storage_key,"replaced",timestamp),
        db.prepare("UPDATE documents SET title=?,original_filename=?,mime_type=?,size_bytes=?,storage_key=?,encryption_version=?,crypto_iv=?,status='ACTIVE',updated_at=? WHERE id=? AND storage_key=?")
          .bind(filename,filename,mime,size,key,cryptoMeta.encryption_version,cryptoMeta.crypto_iv,timestamp,old.id,old.storage_key),
        db.prepare("INSERT INTO upload_receipts(chat_id,message_id,document_id,created_at) SELECT ?,?,?,? WHERE EXISTS (SELECT 1 FROM documents WHERE id=? AND storage_key=?)")
          .bind(user.telegram_id,msg.message_id,old.id,timestamp,old.id,key),
        db.prepare("INSERT INTO audit_logs(id,actor_user_id,event,target_id,created_at) SELECT ?,?,'DOCUMENT_REPLACED',?,? WHERE EXISTS (SELECT 1 FROM upload_receipts WHERE chat_id=? AND message_id=?)")
          .bind(id(),user.id,old.id,timestamp,user.telegram_id,msg.message_id),
      ]);
      if(results[1]?.meta.changes!==1||results[2]?.meta.changes!==1)throw new Error("Replacement conflict");
      try{await removeDocument(env,old.storage_key);await run(db,"UPDATE kv_cleanup_jobs SET completed_at=? WHERE id=?",now(),cleanupId)}catch{/* reconcile later */}
    }else{
      await db.batch([
        db.prepare("INSERT INTO documents(id,vault_id,category_id,title,original_filename,mime_type,size_bytes,storage_key,encryption_version,crypto_iv,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
          .bind(documentIdToWrite,c.vault_id,c.id,filename,filename,mime,size,key,cryptoMeta.encryption_version,cryptoMeta.crypto_iv,user.id,timestamp,timestamp),
        db.prepare("INSERT INTO upload_receipts(chat_id,message_id,document_id,created_at) VALUES(?,?,?,?)").bind(user.telegram_id,msg.message_id,documentIdToWrite,timestamp),
        db.prepare("INSERT INTO audit_logs(id,actor_user_id,event,target_id,created_at) VALUES(?,?,'DOCUMENT_UPLOADED',?,?)").bind(id(),user.id,documentIdToWrite,timestamp),
      ]);
    }
  }catch(error){
    try{
      const cleanupId=id();
      await run(db,"INSERT INTO kv_cleanup_jobs(id,storage_key,reason,created_at) VALUES(?,?,?,?)",cleanupId,key,"metadata_failed",timestamp);
      try{await removeDocument(env,key);await run(db,"UPDATE kv_cleanup_jobs SET completed_at=? WHERE id=?",now(),cleanupId)}catch{/* reconcile later */}
    }catch{
      try{await removeDocument(env,key)}catch{console.error(JSON.stringify({event:"orphan_cleanup_failed",documentId:documentIdToWrite}))}
    }
    throw error;
  }
  return {documentId:documentIdToWrite,categoryId:c.id,duplicate:false};
}

export async function readDocument(
  env:Env,user:User,documentId:string,
):Promise<{document:Document;stream:ReadableStream<Uint8Array>|null}>{
  const d=await document(env.VAULTGRAM_DB,documentId);
  if(!d)throw new Forbidden();
  await requireLevel(env.VAULTGRAM_DB,user,d.vault_id,"VIEW");
  const vaultRow=await vault(env.VAULTGRAM_DB,d.vault_id);
  if(!vaultRow)throw new Forbidden();
  if(await pinRequired(env,user,vaultRow,"download"))throw new PinRequired();
  return {document:d,stream:await loadDocument(env,d)};
}

export async function permanentlyDeleteDocument(env:Env,user:User,documentId:string):Promise<Document>{
  const db=env.VAULTGRAM_DB;
  const d=await one<Document>(db,"SELECT * FROM documents WHERE id=?",documentId);
  if(!d)throw new Forbidden();
  await requireLevel(db,user,d.vault_id,"MANAGE");
  await run(db,"UPDATE documents SET status='DELETING',updated_at=? WHERE id=?",now(),d.id);
  await removeDocument(env,d.storage_key);
  await run(db,"DELETE FROM documents WHERE id=?",d.id);
  await audit(db,user.id,"DOCUMENT_DELETED",d.id);
  return d;
}
