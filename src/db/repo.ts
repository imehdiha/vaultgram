import type { Env, User, Vault, Category, Document, Level } from "../types";
import { id, now } from "../security/crypto";
export const one = async <T>(
  db: D1Database,
  sql: string,
  ...args: unknown[]
): Promise<T | null> =>
  db
    .prepare(sql)
    .bind(...args)
    .first<T>();
export const all = async <T>(
  db: D1Database,
  sql: string,
  ...args: unknown[]
): Promise<T[]> =>
  (
    await db
      .prepare(sql)
      .bind(...args)
      .all<T>()
  ).results;
export const run = async (db: D1Database, sql: string, ...args: unknown[]) =>
  db
    .prepare(sql)
    .bind(...args)
    .run();
export const userByTelegram = (db: D1Database, tid: string) =>
  one<User>(db, "SELECT * FROM users WHERE telegram_id=?", tid);
export const vault = (db: D1Database, vid: string) =>
  one<Vault>(
    db,
    "SELECT * FROM vaults WHERE id=? AND archived_at IS NULL",
    vid,
  );
export const category = (db: D1Database, cid: string) =>
  one<Category>(db, "SELECT * FROM categories WHERE id=?", cid);
export const document = (db: D1Database, did: string) =>
  one<Document>(
    db,
    "SELECT * FROM documents WHERE id=? AND status IN ('ACTIVE','MISSING')",
    did,
  );
export async function level(
  db: D1Database,
  user: User,
  vaultId: string,
): Promise<Level | null> {
  if (user.disabled || user.removed) return null;
  if (user.role === "OWNER") return "MANAGE";
  const r = await one<{ level: Level }>(
    db,
    "SELECT level FROM vault_permissions WHERE user_id=? AND vault_id=?",
    user.id,
    vaultId,
  );
  return r?.level ?? null;
}
const ranks: Record<Level, number> = { VIEW: 1, EDIT: 2, MANAGE: 3 };
export async function requireLevel(
  db: D1Database,
  user: User,
  vaultId: string,
  want: Level,
): Promise<void> {
  const v = await vault(db, vaultId);
  const actual = v ? await level(db, user, vaultId) : null;
  if (!actual || ranks[actual] < ranks[want]) throw new Forbidden();
}
export function requireOwner(user: User): void {
  if (user.role !== "OWNER" || user.disabled) throw new Forbidden();
}
export class Forbidden extends Error {
  constructor() {
    super("Access denied");
  }
}
export async function visibleVaults(
  db: D1Database,
  user: User,
  page = 0,
): Promise<Vault[]> {
  if (user.role === "OWNER")
    return all(
      db,
      "SELECT * FROM vaults WHERE archived_at IS NULL ORDER BY name LIMIT 21 OFFSET ?",
      page * 20,
    );
  return all(
    db,
    "SELECT v.* FROM vaults v JOIN vault_permissions p ON p.vault_id=v.id WHERE p.user_id=? AND v.archived_at IS NULL ORDER BY v.name LIMIT 21 OFFSET ?",
    user.id,
    page * 20,
  );
}
export async function audit(
  db: D1Database,
  actor: string | null,
  event: string,
  target: string | null,
  context?: Record<string, unknown>,
): Promise<void> {
  await run(
    db,
    "INSERT INTO audit_logs(id,actor_user_id,event,target_id,context,created_at) VALUES(?,?,?,?,?,?)",
    id(),
    actor,
    event,
    target,
    context ? JSON.stringify(context) : null,
    now(),
  );
}
export async function setting(db: D1Database, key: string): Promise<string> {
  const v = await one<{ value: string }>(
    db,
    "SELECT value FROM settings WHERE key=?",
    key,
  );
  if (!v) throw new Error(`Missing setting ${key}`);
  return v.value;
}
export async function setSetting(
  db: D1Database,
  key: string,
  value: string,
): Promise<void> {
  await run(db, "UPDATE settings SET value=? WHERE key=?", value, key);
}
export async function createPending(
  db: D1Database,
  userId: string,
  kind: string,
  payload: unknown,
  seconds = 300,
): Promise<string> {
  const pid = id();
  await run(
    db,
    "INSERT INTO pending_actions(id,user_id,kind,payload,expires_at) VALUES(?,?,?,?,?)",
    pid,
    userId,
    kind,
    JSON.stringify(payload),
    now() + seconds,
  );
  return pid;
}
export async function consumePending<T>(
  db: D1Database,
  pid: string,
  userId: string,
  kind: string,
): Promise<T> {
  const r = await one<{ payload: string }>(
    db,
    "SELECT payload FROM pending_actions WHERE id=? AND user_id=? AND kind=? AND consumed_at IS NULL AND expires_at>?",
    pid,
    userId,
    kind,
    now(),
  );
  if (!r) throw new Forbidden();
  const done = await run(
    db,
    "UPDATE pending_actions SET consumed_at=? WHERE id=? AND consumed_at IS NULL",
    now(),
    pid,
  );
  if (done.meta.changes !== 1) throw new Forbidden();
  return JSON.parse(r.payload) as T;
}
export async function bootstrap(
  env: Env,
  telegramId: string,
  name: string,
): Promise<User | null> {
  const uid = id();
  const t = now();
  const result = await run(
    env.VAULTGRAM_DB,
    "UPDATE workspaces SET owner_user_id=?,bootstrap_closed=1 WHERE id='default' AND owner_user_id IS NULL AND bootstrap_closed=0",
    uid,
  );
  if (result.meta.changes !== 1) return null;
  try {
    await run(
      env.VAULTGRAM_DB,
      "INSERT INTO users(id,telegram_id,display_name,role,created_at) VALUES(?,?,?,'OWNER',?)",
      uid,
      telegramId,
      name,
      t,
    );
    await audit(env.VAULTGRAM_DB, uid, "OWNER_BOOTSTRAPPED", uid);
    return userByTelegram(env.VAULTGRAM_DB, telegramId);
  } catch (e) {
    await run(
      env.VAULTGRAM_DB,
      "UPDATE workspaces SET owner_user_id=NULL,bootstrap_closed=0 WHERE id='default' AND owner_user_id=?",
      uid,
    );
    throw e;
  }
}
