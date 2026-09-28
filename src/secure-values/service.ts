import type { Env, Level, SecureValue, User } from "../types";
import { id, now } from "../security/crypto";
import { decryptSecureValue, encryptSecureValue } from "../security/vault-crypto";
import { all, audit, category, Forbidden, one, requireLevel, run, vault } from "../db/repo";
import { pinRequired, PinRequired } from "../security/pin";

function validLabel(label: string): boolean {
  return label.length >= 1 && label.length <= 100 && !/[\u0000-\u001f\u007f]/.test(label);
}

async function authorize(
  env: Env,
  user: User,
  vaultId: string,
  level: Level,
  mode: "browse" | "download" | "edit",
): Promise<void> {
  await requireLevel(env.VAULTGRAM_DB, user, vaultId, level);
  const v = await vault(env.VAULTGRAM_DB, vaultId);
  if (!v) throw new Forbidden();
  if (await pinRequired(env, user, v, mode)) throw new PinRequired();
}

async function valueRow(env: Env, valueId: string): Promise<SecureValue> {
  const row = await one<SecureValue>(env.VAULTGRAM_DB,"SELECT * FROM secure_values WHERE id=?",valueId);
  if (!row) throw new Forbidden();
  return row;
}

export async function listSecureValues(
  env: Env,
  user: User,
  vaultId: string,
  page = 0,
  archived = false,
): Promise<SecureValue[]> {
  await authorize(env,user,vaultId,archived?"MANAGE":"VIEW","browse");
  return all<SecureValue>(env.VAULTGRAM_DB,
    `SELECT * FROM secure_values WHERE vault_id=? AND archived_at IS ${archived?"NOT NULL":"NULL"} ORDER BY label,id LIMIT 21 OFFSET ?`,
    vaultId,page*20);
}

export async function getSecureValue(
  env: Env,
  user: User,
  valueId: string,
): Promise<{ label: string; value: string; vaultId: string }> {
  const row = await valueRow(env,valueId);
  if (row.archived_at !== null) throw new Forbidden();
  await authorize(env,user,row.vault_id,"VIEW","download");
  const value = await decryptSecureValue(env,row);
  await audit(env.VAULTGRAM_DB,user.id,"SECURE_VALUE_REVEALED",row.id);
  return { label: row.label, value, vaultId: row.vault_id };
}

export async function createSecureValue(
  env: Env,
  user: User,
  vaultId: string,
  label: string,
  plain: string,
  categoryId: string | null = null,
): Promise<string> {
  await authorize(env,user,vaultId,"EDIT","edit");
  if (!validLabel(label) || !plain || new TextEncoder().encode(plain).byteLength > 3000)
    throw new Error("Invalid secure value input");
  if (categoryId) {
    const c=await category(env.VAULTGRAM_DB,categoryId);
    if (!c || c.vault_id !== vaultId) throw new Forbidden();
  }
  const valueId=id(), encrypted=await encryptSecureValue(env,vaultId,valueId,plain), timestamp=now();
  await env.VAULTGRAM_DB.batch([
    env.VAULTGRAM_DB.prepare("INSERT INTO secure_values(id,vault_id,category_id,label,kind,ciphertext,crypto_iv,crypto_revision,encryption_version,created_by,created_at,updated_at) VALUES(?,?,?,?,'TEXT',?,?,?,?,?,?,?)")
      .bind(valueId,vaultId,categoryId,label,encrypted.ciphertext,encrypted.crypto_iv,encrypted.crypto_revision,encrypted.encryption_version,user.id,timestamp,timestamp),
    env.VAULTGRAM_DB.prepare("INSERT INTO audit_logs(id,actor_user_id,event,target_id,created_at) VALUES(?,?,'SECURE_VALUE_CREATED',?,?)")
      .bind(id(),user.id,valueId,timestamp),
  ]);
  return valueId;
}

export async function updateSecureValue(
  env: Env,
  user: User,
  valueId: string,
  plain: string,
): Promise<void> {
  const row=await valueRow(env,valueId);
  if (row.archived_at !== null) throw new Forbidden();
  await authorize(env,user,row.vault_id,"EDIT","edit");
  if (!plain || new TextEncoder().encode(plain).byteLength > 3000)
    throw new Error("Invalid secure value input");
  const encrypted=await encryptSecureValue(env,row.vault_id,row.id,plain);
  const changed=await run(env.VAULTGRAM_DB,
    "UPDATE secure_values SET ciphertext=?,crypto_iv=?,crypto_revision=?,encryption_version=?,updated_at=? WHERE id=? AND crypto_revision=? AND archived_at IS NULL",
    encrypted.ciphertext,encrypted.crypto_iv,encrypted.crypto_revision,encrypted.encryption_version,now(),row.id,row.crypto_revision);
  if (changed.meta.changes!==1) throw new Forbidden();
  await audit(env.VAULTGRAM_DB,user.id,"SECURE_VALUE_UPDATED",row.id);
}

export async function renameSecureValue(env:Env,user:User,valueId:string,label:string):Promise<void>{
  const row=await valueRow(env,valueId);
  if(row.archived_at!==null)throw new Forbidden();
  await authorize(env,user,row.vault_id,"EDIT","edit");
  if(!validLabel(label))throw new Error("Invalid secure value label");
  await run(env.VAULTGRAM_DB,"UPDATE secure_values SET label=?,updated_at=? WHERE id=?",label,now(),row.id);
  await audit(env.VAULTGRAM_DB,user.id,"SECURE_VALUE_RENAMED",row.id);
}

export async function archiveSecureValue(env:Env,user:User,valueId:string):Promise<void>{
  const row=await valueRow(env,valueId);
  if(row.archived_at!==null)throw new Forbidden();
  await authorize(env,user,row.vault_id,"MANAGE","edit");
  await run(env.VAULTGRAM_DB,"UPDATE secure_values SET archived_at=?,updated_at=? WHERE id=?",now(),now(),row.id);
  await audit(env.VAULTGRAM_DB,user.id,"SECURE_VALUE_ARCHIVED",row.id);
}

export async function restoreSecureValue(env:Env,user:User,valueId:string):Promise<void>{
  const row=await valueRow(env,valueId);
  if(row.archived_at===null)throw new Forbidden();
  await authorize(env,user,row.vault_id,"MANAGE","edit");
  await run(env.VAULTGRAM_DB,"UPDATE secure_values SET archived_at=NULL,updated_at=? WHERE id=?",now(),row.id);
  await audit(env.VAULTGRAM_DB,user.id,"SECURE_VALUE_RESTORED",row.id);
}

export async function deleteSecureValue(env:Env,user:User,valueId:string):Promise<void>{
  const row=await valueRow(env,valueId);
  await authorize(env,user,row.vault_id,"MANAGE","edit");
  await run(env.VAULTGRAM_DB,"DELETE FROM secure_values WHERE id=?",row.id);
  await audit(env.VAULTGRAM_DB,user.id,"SECURE_VALUE_DELETED",row.id);
}
