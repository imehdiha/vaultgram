import type {
  Env,
  User,
  Message,
  Update,
  Vault,
  Category,
  Document,
  SecureValue,
  Level,
} from "../types";
import {
  id,
  now,
  equal,
  sha256,
  randomToken,
} from "../security/crypto";
import {
  one,
  all,
  run,
  userByTelegram,
  vault,
  category,
  document,
  level,
  requireLevel,
  requireOwner,
  visibleVaults,
  audit,
  setting,
  setSetting,
  createPending,
  consumePending,
  bootstrap,
  Forbidden,
} from "../db/repo";
import { pinRequired, PinRequired, setPin, verifyPin } from "../security/pin";
import { documentExists, removeDocument } from "../storage/kv";
import { permanentlyDeleteDocument, readDocument, saveUploadedDocument, UploadTooLarge } from "../documents/service";
import { archiveSecureValue, createSecureValue, deleteSecureValue, getSecureValue, listSecureValues, renameSecureValue, restoreSecureValue, updateSecureValue } from "../secure-values/service";
import {
  send as sendTelegram,
  sendInvite,
  sendProtectedText,
  edit,
  answer,
  deleteMessage,
  scheduleDelete,
  sendDocumentStream,
  type Keyboard,
} from "../telegram/api";
import { t } from "../i18n";

type Session = {
  state: string | null;
  payload: string | null;
  expires_at: number;
  menu_message_id: number | null;
};
const b = (text: string, data: string) => ({ text, callback_data: data });
const navigation = (user: User, back: string) => [
  b(t(user, "back"), back),
  b(t(user, "goHome"), "home"),
];
const tr = (
  user: User,
  key: Parameters<typeof t>[1],
  fields: Record<string, string | number>,
): string =>
  Object.entries(fields).reduce(
    (value, [name, replacement]) =>
      value.replaceAll(`{${name}}`, String(replacement)),
    t(user, key),
  );
const yes = (v: unknown) => v === "true";
const onOff = (user: User, v: unknown) => t(user, yes(v) ? "on" : "off");
function policyName(user: User, v: unknown): string {
  return v === "DOWNLOADS"
    ? t(user, "policyDownloads")
    : v === "SENSITIVE_VAULTS"
      ? t(user, "policySensitive")
      : v === "ALWAYS"
        ? t(user, "policyAlways")
        : t(user, "off");
}
const pageValue = (raw?: string) => {
  const n = Number(raw ?? 0);
  return Number.isSafeInteger(n) && n >= 0 && n <= 10000 ? n : 0;
};
const locale = async (env: Env) => setting(env.VAULTGRAM_DB, "default_locale");
async function discard(env: Env, chat: string, messageId: number): Promise<void> {
  try {
    await deleteMessage(env, { chat_id: chat, message_id: messageId });
  } catch {
    /* Telegram may already have removed this message. */
  }
}
async function clearTransient(env: Env, user: User, chat: string): Promise<void> {
  const row = await one<{ transient_message_id: number | null }>(
    env.VAULTGRAM_DB,
    "SELECT transient_message_id FROM user_sessions WHERE user_id=?",
    user.id,
  );
  if (!row?.transient_message_id) return;
  await run(
    env.VAULTGRAM_DB,
    "UPDATE user_sessions SET transient_message_id=NULL WHERE user_id=? AND transient_message_id=?",
    user.id,
    row.transient_message_id,
  );
  await discard(env, chat, row.transient_message_id);
}
async function send(
  env: Env,
  chat: string,
  text: string,
  keyboard?: Keyboard,
): Promise<Message> {
  const recipient = await userByTelegram(env.VAULTGRAM_DB, chat);
  const message = await sendTelegram(env, chat, text, keyboard);
  if (recipient)
    await run(
      env.VAULTGRAM_DB,
      "INSERT INTO user_sessions(user_id,transient_message_id) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET transient_message_id=excluded.transient_message_id",
      recipient.id,
      message.message_id,
    );
  try {
    await scheduleDelete(env, { chat_id: chat, message_id: message.message_id }, 120);
  } catch {
    console.error(JSON.stringify({ event: "transient_deletion_schedule_failed" }));
  }
  return message;
}
async function say(
  env: Env,
  user: User,
  chat: string,
  text: string,
  k?: Keyboard,
  messageId?: number,
): Promise<void> {
  const previous = await one<{ menu_message_id: number | null }>(
    env.VAULTGRAM_DB,
    "SELECT menu_message_id FROM user_sessions WHERE user_id=?",
    user.id,
  );
  if (messageId) {
    try {
      await edit(env, chat, messageId, text, k);
      await run(
        env.VAULTGRAM_DB,
        "INSERT INTO user_sessions(user_id,menu_message_id) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET menu_message_id=excluded.menu_message_id",
        user.id,
        messageId,
      );
      if (previous?.menu_message_id && previous.menu_message_id !== messageId)
        await discard(env, chat, previous.menu_message_id);
      return;
    } catch {
      /* stale menu */
    }
  }
  const m = await sendTelegram(env, chat, text, k);
  await run(
    env.VAULTGRAM_DB,
    "INSERT INTO user_sessions(user_id,menu_message_id) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET menu_message_id=excluded.menu_message_id",
    user.id,
    m.message_id,
  );
  if (previous?.menu_message_id && previous.menu_message_id !== m.message_id)
    await discard(env, chat, previous.menu_message_id);
}
async function session(env: Env, user: User): Promise<Session | null> {
  return one(
    env.VAULTGRAM_DB,
    "SELECT state,payload,expires_at,menu_message_id FROM user_sessions WHERE user_id=?",
    user.id,
  );
}
async function setState(
  env: Env,
  user: User,
  state: string,
  payload: unknown = {},
  seconds = 600,
): Promise<void> {
  await run(
    env.VAULTGRAM_DB,
    "INSERT INTO user_sessions(user_id,state,payload,expires_at) VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET state=excluded.state,payload=excluded.payload,expires_at=excluded.expires_at",
    user.id,
    state,
    JSON.stringify(payload),
    now() + seconds,
  );
}
async function clearState(env: Env, user: User): Promise<void> {
  await run(
    env.VAULTGRAM_DB,
    "UPDATE user_sessions SET state=NULL,payload=NULL,expires_at=0 WHERE user_id=?",
    user.id,
  );
}
async function home(
  env: Env,
  user: User,
  chat: string,
  messageId?: number,
): Promise<void> {
  const l = await locale(env);
  const w = await one<{ name: string }>(
    env.VAULTGRAM_DB,
    "SELECT name FROM workspaces WHERE id='default'",
  );
  const keys: Keyboard = [[b(t(user, "vaults", l), "vaults")]];
  if (user.role === "OWNER")
    keys.push(
      [b(t(user, "newVault", l), "newvault")],
      [
        b(t(user, "members", l), "members"),
        b(t(user, "activity", l), "activity"),
      ],
      [b(t(user, "settings", l), "settings")],
    );
  if (user.role !== "OWNER")
    keys.push([b(t(user, "settings", l), "settings")]);
  await say(
    env,
    user,
    chat,
    `🔐 ${w?.name ?? t(user, "home", l)}`,
    keys,
    messageId,
  );
}
async function vaultList(
  env: Env,
  user: User,
  chat: string,
  messageId?: number,
  page = 0,
): Promise<void> {
  const rows = await visibleVaults(env.VAULTGRAM_DB, user, page);
  const keys: Keyboard = rows
    .slice(0, 20)
    .map((v) => [b(`📂 ${v.name}`, `v:${v.id}`)]);
  if (page > 0 || rows.length > 20)
    keys.push([
      ...(page > 0 ? [b(t(user, "previous"), `vaults:${page - 1}`)] : []),
      ...(rows.length > 20 ? [b(t(user, "next"), `vaults:${page + 1}`)] : []),
    ]);
  if (user.role === "OWNER")
    keys.push([b(t(user, "archivedVaults"), "archivedvaults")]);
  keys.push([b(t(user, "back"), "home")]);
  await say(
    env,
    user,
    chat,
    rows.length ? t(user, "vaults") : t(user, "noAccess"),
    keys,
    messageId,
  );
}
async function archivedVaults(
  env: Env,
  user: User,
  chat: string,
  messageId?: number,
  page = 0,
): Promise<void> {
  requireOwner(user);
  const vs = await all<Vault>(
    env.VAULTGRAM_DB,
    "SELECT * FROM vaults WHERE archived_at IS NOT NULL ORDER BY archived_at DESC LIMIT 21 OFFSET ?",
    page * 20,
  );
  const keys: Keyboard = [];
  for (const v of vs.slice(0, 20))
    keys.push([
      b(`📂 ${v.name}`, `restorev:${v.id}`),
      b(t(user, "deleteVault"), `deletev:${v.id}`),
    ]);
  if (page > 0 || vs.length > 20)
    keys.push([
      ...(page > 0
        ? [b(t(user, "previous"), `archivedvaults:${page - 1}`)]
        : []),
      ...(vs.length > 20
        ? [b(t(user, "next"), `archivedvaults:${page + 1}`)]
        : []),
    ]);
  keys.push([b(t(user, "back"), "vaults")]);
  await say(env, user, chat, t(user, "archivedVaults"), keys, messageId);
}
async function showVault(
  env: Env,
  user: User,
  chat: string,
  vaultId: string,
  messageId?: number,
): Promise<void> {
  await requireLevel(env.VAULTGRAM_DB, user, vaultId, "VIEW");
  const v = await vault(env.VAULTGRAM_DB, vaultId);
  if (!v) throw new Forbidden();
  if (await pinRequired(env, user, v, "browse")) {
    await setState(env, user, "pin_action", { action: `v:${vaultId}` });
    await say(env, user, chat, t(user, "pinNeeded"));
    return;
  }
  const keys: Keyboard = [
    [b(t(user,"documents"),`vdocs:${vaultId}`)],
    [b(t(user,"information"),`info:${vaultId}`)],
  ];
  if (user.role === "OWNER")
    keys.push(
      [b(t(user,"renameVault"),`renamev:${vaultId}`),b(t(user,"archiveVault"),`archivev:${vaultId}`)],
      [b(t(user,"togglePin"),`vpin:${vaultId}`)],
    );
  keys.push(navigation(user,"vaults"));
  await say(env,user,chat,`📂 ${v.name}`,keys,messageId);
}
async function showVaultDocuments(
  env: Env,
  user: User,
  chat: string,
  vaultId: string,
  messageId?: number,
  page = 0,
): Promise<void> {
  await requireLevel(env.VAULTGRAM_DB,user,vaultId,"VIEW");
  const v=await vault(env.VAULTGRAM_DB,vaultId);
  if(!v)throw new Forbidden();
  const cats = await all<Category>(
    env.VAULTGRAM_DB,
    "SELECT * FROM categories WHERE vault_id=? ORDER BY sort_order,name LIMIT 21 OFFSET ?",
    vaultId,
    page * 20,
  );
  const keys: Keyboard = cats
    .slice(0, 20)
    .map((c) => [b(`📁 ${c.name}`, `c:${c.id}`)]);
  if (page > 0 || cats.length > 20)
    keys.push([
      ...(page > 0 ? [b(t(user, "previous"), `vdocs:${vaultId}:${page - 1}`)] : []),
      ...(cats.length > 20
        ? [b(t(user, "next"), `vdocs:${vaultId}:${page + 1}`)]
        : []),
    ]);
  const can = await level(env.VAULTGRAM_DB, user, vaultId);
  if (can === "MANAGE")
    keys.push([b(t(user, "addCategory"), `newcat:${vaultId}`)]);
  keys.push(navigation(user, `v:${vaultId}`));
  await say(env, user, chat, `📄 ${v.name}`, keys, messageId);
}
async function showInformation(
  env:Env,user:User,chat:string,vaultId:string,messageId?:number,page=0,archived=false,
):Promise<void>{
  const rows=await listSecureValues(env,user,vaultId,page,archived);
  const can=await level(env.VAULTGRAM_DB,user,vaultId);
  const keys:Keyboard=rows.slice(0,20).map(row=>[b(`🔐 ${row.label}`,`sv:${row.id}`)]);
  const route=archived?"svtrash":"info";
  if(page>0||rows.length>20)keys.push([
    ...(page>0?[b(t(user,"previous"),`${route}:${vaultId}:${page-1}`)]:[]),
    ...(rows.length>20?[b(t(user,"next"),`${route}:${vaultId}:${page+1}`)]:[]),
  ]);
  if(!archived&&(can==="EDIT"||can==="MANAGE"))keys.push([b(t(user,"addSecureValue"),`svnew:${vaultId}`)]);
  if(!archived&&can==="MANAGE")keys.push([b(t(user,"archivedInformation"),`svtrash:${vaultId}`)]);
  keys.push(navigation(user, archived?`info:${vaultId}`:`v:${vaultId}`));
  await say(env,user,chat,archived?t(user,"archivedInformation"):t(user,"information"),keys,messageId);
}
async function showSecureValue(
  env:Env,user:User,chat:string,valueId:string,messageId?:number,
):Promise<void>{
  const row=await one<SecureValue>(env.VAULTGRAM_DB,"SELECT * FROM secure_values WHERE id=?",valueId);
  if(!row)throw new Forbidden();
  await requireLevel(env.VAULTGRAM_DB,user,row.vault_id,row.archived_at===null?"VIEW":"MANAGE");
  const can=await level(env.VAULTGRAM_DB,user,row.vault_id);
  const keys:Keyboard=[];
  if(row.archived_at===null){
    keys.push([b(t(user,"showSecureValue"),`svshow:${row.id}`)]);
    if(can==="EDIT"||can==="MANAGE")keys.push([b(t(user,"editSecureValue"),`svedit:${row.id}`),b(t(user,"renameSecureValue"),`svrename:${row.id}`)]);
    if(can==="MANAGE")keys.push([b(t(user,"archive"),`svarchive:${row.id}`),b(t(user,"delete"),`svdelete:${row.id}`)]);
  }else keys.push([b(t(user,"restore"),`svrestore:${row.id}`),b(t(user,"delete"),`svdelete:${row.id}`)]);
  keys.push(navigation(user, `${row.archived_at===null?"info":"svtrash"}:${row.vault_id}`));
  await say(env,user,chat,`🔐 ${row.label}`,keys,messageId);
}
async function showCategory(
  env: Env,
  user: User,
  chat: string,
  categoryId: string,
  messageId?: number,
  page = 0,
): Promise<void> {
  const c = await category(env.VAULTGRAM_DB, categoryId);
  if (!c) throw new Forbidden();
  await requireLevel(env.VAULTGRAM_DB, user, c.vault_id, "VIEW");
  const docs = await all<Document>(
    env.VAULTGRAM_DB,
    "SELECT * FROM documents WHERE category_id=? AND status IN ('ACTIVE','MISSING') ORDER BY created_at DESC LIMIT 21 OFFSET ?",
    c.id,
    page * 20,
  );
  const keys: Keyboard = docs
    .slice(0, 20)
    .map((d) => [
      b(`📄 ${d.title}${d.status === "MISSING" ? " ⚠️" : ""}`, `d:${d.id}`),
    ]);
  if (page > 0 || docs.length > 20)
    keys.push([
      ...(page > 0 ? [b(t(user, "previous"), `c:${c.id}:${page - 1}`)] : []),
      ...(docs.length > 20
        ? [b(t(user, "next"), `c:${c.id}:${page + 1}`)]
        : []),
    ]);
  const lvl = await level(env.VAULTGRAM_DB, user, c.vault_id);
  if (lvl !== "VIEW") keys.push([b(t(user, "addDocument"), `add:${c.id}`)]);
  if (lvl === "MANAGE")
    keys.push(
      [b(t(user, "trash"), `trash:${c.id}`)],
      [
        b(t(user, "moveUp"), `catup:${c.id}`),
        b(t(user, "moveDown"), `catdown:${c.id}`),
      ],
      [
        b(t(user, "renameCategory"), `renamec:${c.id}`),
        b(t(user, "deleteCategory"), `delc:${c.id}`),
      ],
    );
  keys.push(navigation(user, `vdocs:${c.vault_id}`));
  await say(env, user, chat, `📁 ${c.name}`, keys, messageId);
}
async function showDocument(
  env: Env,
  user: User,
  chat: string,
  documentId: string,
  messageId?: number,
): Promise<void> {
  const d = await document(env.VAULTGRAM_DB, documentId);
  if (!d) throw new Forbidden();
  await requireLevel(env.VAULTGRAM_DB, user, d.vault_id, "VIEW");
  const lvl = await level(env.VAULTGRAM_DB, user, d.vault_id);
  const keys: Keyboard = [[b(t(user, "get"), `get:${d.id}`)]];
  if (lvl === "EDIT" || lvl === "MANAGE")
    keys.push([
      b(t(user, "editTitle"), `renamed:${d.id}`),
      b(t(user, "replace"), `replace:${d.id}`),
    ]);
  if (lvl === "MANAGE")
    keys.push([
      b(t(user, "archive"), `archived:${d.id}`),
      b(t(user, "delete"), `deleted:${d.id}`),
    ]);
  keys.push(navigation(user, `c:${d.category_id}`));
  await say(
    env,
    user,
    chat,
    `📄 ${d.title}\n${d.original_filename} · ${Math.ceil(d.size_bytes / 1024)} KB`,
    keys,
    messageId,
  );
}
async function showTrash(
  env: Env,
  user: User,
  chat: string,
  categoryId: string,
  messageId?: number,
  page = 0,
): Promise<void> {
  const c = await category(env.VAULTGRAM_DB, categoryId);
  if (!c) throw new Forbidden();
  await requireLevel(env.VAULTGRAM_DB, user, c.vault_id, "MANAGE");
  const docs = await all<Document>(
    env.VAULTGRAM_DB,
    "SELECT * FROM documents WHERE category_id=? AND status='ARCHIVED' ORDER BY updated_at DESC LIMIT 21 OFFSET ?",
    c.id,
    page * 20,
  );
  const keys: Keyboard = docs
    .slice(0, 20)
    .map((d) => [b(`📄 ${d.title}`, `trashdoc:${d.id}`)]);
  if (page > 0 || docs.length > 20)
    keys.push([
      ...(page > 0
        ? [b(t(user, "previous"), `trash:${c.id}:${page - 1}`)]
        : []),
      ...(docs.length > 20
        ? [b(t(user, "next"), `trash:${c.id}:${page + 1}`)]
        : []),
    ]);
  keys.push(navigation(user, `c:${c.id}`));
  await say(env, user, chat, `🗑 ${c.name} · Trash`, keys, messageId);
}
async function showTrashDocument(
  env: Env,
  user: User,
  chat: string,
  documentId: string,
  messageId?: number,
): Promise<void> {
  const d = await one<Document>(
    env.VAULTGRAM_DB,
    "SELECT * FROM documents WHERE id=? AND status='ARCHIVED'",
    documentId,
  );
  if (!d) throw new Forbidden();
  await requireLevel(env.VAULTGRAM_DB, user, d.vault_id, "MANAGE");
  await say(
    env,
    user,
    chat,
    `🗑 ${d.title}`,
    [
      [b(t(user, "restore"), `restore:${d.id}`)],
      [b(t(user, "delete"), `deleted:${d.id}`)],
      navigation(user, `trash:${d.category_id}`),
    ],
    messageId,
  );
}
async function createInvite(env: Env, user: User, chat: string): Promise<void> {
  requireOwner(user);
  const token = randomToken(32),
    inviteId = id(),
    hours = Number(await setting(env.VAULTGRAM_DB, "invite_expiry_hours"));
  await run(
    env.VAULTGRAM_DB,
    "INSERT INTO invites(id,token_hash,expires_at,created_by,created_at) VALUES(?,?,?,?,?)",
    inviteId,
    await sha256(token),
    now() + hours * 3600,
    user.id,
    now(),
  );
  await audit(env.VAULTGRAM_DB, user.id, "MEMBER_INVITED", inviteId);
  const me = await import("../telegram/api").then((m) =>
    m.telegram<{ username: string }>(env, "getMe", {}),
  );
  const url = `https://t.me/${me.username}?start=${token}`;
  const message = await sendInvite(
    env,
    chat,
    `${t(user, "invite")}\n${url}\n${t(user, "inviteGrantHint").replace("{hours}", String(hours))}`,
    url,
    t(user, "openInvite"),
    t(user, "copyInvite"),
  );
  try {
    await scheduleDelete(env, { chat_id: chat, message_id: message.message_id }, 120);
  } catch {
    console.error(JSON.stringify({ event: "invite_deletion_schedule_failed" }));
  }
}
export async function acceptInvite(
  env: Env,
  msg: Message,
  token: string,
): Promise<User | null> {
  if (!msg.from) return null;
  const hash = await sha256(token);
  const inv = await one<{ id: string }>(
    env.VAULTGRAM_DB,
    "SELECT id FROM invites WHERE token_hash=? AND used_at IS NULL AND revoked_at IS NULL AND expires_at>?",
    hash,
    now(),
  );
  if (!inv) return null;
  const uid = id();
  const memberLocale = msg.from.language_code?.toLowerCase().startsWith("fa")
    ? "fa"
    : await locale(env);
  const claimed = await run(
    env.VAULTGRAM_DB,
    "UPDATE invites SET used_at=?,used_by=? WHERE id=? AND used_at IS NULL AND revoked_at IS NULL AND expires_at>?",
    now(),
    uid,
    inv.id,
    now(),
  );
  if (claimed.meta.changes !== 1) return null;
  try {
    await env.VAULTGRAM_DB.batch([
      env.VAULTGRAM_DB.prepare(
        "INSERT INTO users(id,telegram_id,display_name,role,locale,created_at) VALUES(?,?,?,'MEMBER',?,?)",
      ).bind(uid, String(msg.from.id), msg.from.first_name, memberLocale, now()),
      env.VAULTGRAM_DB.prepare(
        "INSERT INTO vault_permissions(user_id,vault_id,level) SELECT ?,vault_id,level FROM invite_permissions WHERE invite_id=?",
      ).bind(uid, inv.id),
    ]);
    await audit(env.VAULTGRAM_DB, uid, "MEMBER_JOINED", inv.id);
    return userByTelegram(env.VAULTGRAM_DB, String(msg.from.id));
  } catch (e) {
    await run(
      env.VAULTGRAM_DB,
      "UPDATE invites SET used_at=NULL,used_by=NULL WHERE id=? AND used_by=?",
      inv.id,
      uid,
    );
    throw e;
  }
}
async function members(
  env: Env,
  user: User,
  chat: string,
  messageId?: number,
  page = 0,
): Promise<void> {
  requireOwner(user);
  const users = await all<User>(
    env.VAULTGRAM_DB,
    "SELECT * FROM users WHERE role='MEMBER' ORDER BY display_name LIMIT 21 OFFSET ?",
    page * 20,
  );
  const keys: Keyboard = users
    .slice(0, 20)
    .map((u) => [
      b(
        `${u.removed ? "🗑" : u.disabled ? "🚫" : "👤"} ${u.display_name}`,
        `member:${u.id}`,
      ),
    ]);
  if (page > 0 || users.length > 20)
    keys.push([
      ...(page > 0 ? [b(t(user, "previous"), `members:${page - 1}`)] : []),
      ...(users.length > 20 ? [b(t(user, "next"), `members:${page + 1}`)] : []),
    ]);
  keys.push(
    [b(t(user, "createInvite"), "invite")],
    [b(t(user, "pendingInvites"), "invites")],
    [b(t(user, "back"), "home")],
  );
  await say(env, user, chat, t(user, "members"), keys, messageId);
}
async function member(
  env: Env,
  user: User,
  chat: string,
  memberId: string,
  messageId?: number,
): Promise<void> {
  requireOwner(user);
  const m = await one<User>(
    env.VAULTGRAM_DB,
    "SELECT * FROM users WHERE id=? AND role='MEMBER'",
    memberId,
  );
  if (!m) throw new Forbidden();
  const perms = await all<{ name: string; level: Level }>(
    env.VAULTGRAM_DB,
    "SELECT v.name,p.level FROM vault_permissions p JOIN vaults v ON v.id=p.vault_id WHERE p.user_id=? AND v.archived_at IS NULL",
    m.id,
  );
  const keys: Keyboard = m.removed
    ? [[b(t(user, "restoreMember"), `restoremember:${m.id}`)]]
    : [
        [b(t(user, "permissions"), `perm:${m.id}`)],
        ...(m.pin_hash
          ? [[b(t(user, "resetMemberPin"), `resetmemberpin:${m.id}`)]]
          : []),
        [
          b(
            m.disabled ? t(user, "enableMember") : t(user, "disableMember"),
            `disable:${m.id}`,
          ),
        ],
        [b(t(user, "removeMember"), `removemember:${m.id}`)],
      ];
  keys.push([b(t(user, "back"), "members")]);
  await say(
    env,
    user,
    chat,
    `${m.display_name} · ${m.telegram_id}\n${perms.map((p) => `${p.name}: ${p.level}`).join("\n") || t(user, "noVaultAccess")}`,
    keys,
    messageId,
  );
}
async function permissionMenu(
  env: Env,
  user: User,
  chat: string,
  memberId: string,
  messageId?: number,
  page = 0,
): Promise<void> {
  requireOwner(user);
  const m = await one<User>(
    env.VAULTGRAM_DB,
    "SELECT * FROM users WHERE id=? AND role='MEMBER'",
    memberId,
  );
  if (!m || m.removed) throw new Forbidden();
  const vs = await all<Vault & { level: Level | null }>(
    env.VAULTGRAM_DB,
    "SELECT v.*,p.level FROM vaults v LEFT JOIN vault_permissions p ON p.vault_id=v.id AND p.user_id=? WHERE v.archived_at IS NULL ORDER BY v.name LIMIT 21 OFFSET ?",
    m.id,
    page * 20,
  );
  const keys: Keyboard = [];
  for (const v of vs.slice(0, 20)) {
    const actionId = await createPending(
      env.VAULTGRAM_DB,
      user.id,
      "grant_target",
      { memberId: m.id, vaultId: v.id },
      900,
    );
    keys.push([b(`${v.name} · ${v.level ?? "None"}`, `grantv:${actionId}`)]);
  }
  if (page > 0 || vs.length > 20)
    keys.push([
      ...(page > 0 ? [b(t(user, "previous"), `perm:${m.id}:${page - 1}`)] : []),
      ...(vs.length > 20
        ? [b(t(user, "next"), `perm:${m.id}:${page + 1}`)]
        : []),
    ]);
  keys.push([b(t(user, "back"), `member:${m.id}`)]);
  await say(
    env,
    user,
    chat,
    t(user, "permissionsFor").replace("{name}", m.display_name),
    keys,
    messageId,
  );
}
async function grantTarget(
  env: Env,
  user: User,
  actionId: string,
): Promise<{ memberId: string; vaultId: string }> {
  requireOwner(user);
  const r = await one<{ payload: string }>(
    env.VAULTGRAM_DB,
    "SELECT payload FROM pending_actions WHERE id=? AND user_id=? AND kind='grant_target' AND consumed_at IS NULL AND expires_at>?",
    actionId,
    user.id,
    now(),
  );
  if (!r) throw new Forbidden();
  const p = JSON.parse(r.payload) as { memberId: string; vaultId: string };
  if (!p.memberId || !p.vaultId) throw new Forbidden();
  return p;
}
async function grantMenu(
  env: Env,
  user: User,
  chat: string,
  actionId: string,
  messageId?: number,
): Promise<void> {
  const { memberId, vaultId } = await grantTarget(env, user, actionId);
  const m = await one<User>(
      env.VAULTGRAM_DB,
      "SELECT * FROM users WHERE id=? AND role='MEMBER'",
      memberId,
    ),
    v = await vault(env.VAULTGRAM_DB, vaultId);
  if (!m || m.removed || !v) throw new Forbidden();
  await say(
    env,
    user,
    chat,
    `${m.display_name} → ${v.name}`,
    [
      [
        b("VIEW", `grant:${actionId}:VIEW`),
        b("EDIT", `grant:${actionId}:EDIT`),
        b("MANAGE", `grant:${actionId}:MANAGE`),
      ],
      [b(t(user, "revokeAccess"), `revoke:${actionId}`)],
      [b(t(user, "back"), `perm:${memberId}`)],
    ],
    messageId,
  );
}
async function settings(
  env: Env,
  user: User,
  chat: string,
  messageId?: number,
): Promise<void> {
  if (user.role !== "OWNER") {
    await say(
      env,
      user,
      chat,
      t(user, "settings"),
      [
        [b(t(user, "security"), "security")],
        [b("English", "userlang:en"), b("فارسی", "userlang:fa")],
        [b(t(user, "back"), "home")],
      ],
      messageId,
    );
    return;
  }
  requireOwner(user);
  const rows = await all<{ key: string; value: string }>(
    env.VAULTGRAM_DB,
    "SELECT * FROM settings",
  );
  const s = Object.fromEntries(rows.map((r) => [r.key, r.value]));
  const w = await one<{ name: string }>(
    env.VAULTGRAM_DB,
    "SELECT name FROM workspaces WHERE id='default'",
  );
  await say(
    env,
    user,
    chat,
    `⚙️ ${w?.name}\n${t(user, "language")}: ${s.default_locale}\n${t(user, "autoDelete")}: ${s.delete_after_seconds === "0" ? t(user, "off") : `${s.delete_after_seconds}s`}\n${t(user, "incomingDeletion")}: ${onOff(user, s.delete_incoming)}\n${t(user, "protectedSend")}: ${onOff(user, s.protect_content)}\n${t(user, "pinPolicy")}: ${policyName(user, s.pin_policy)}\n${t(user, "inviteExpiry")}: ${s.invite_expiry_hours}h\n${t(user, "pinSession")}: ${s.pin_session_seconds}s`,
    [
      [
        b(t(user, "workspaceName"), "setname"),
        b(t(user, "language"), "language"),
      ],
      [b(t(user, "autoDelete"), "autodelete")],
      [
        b(t(user, "incomingDeletion"), "toggleincoming"),
        b(t(user, "protectedSend"), "toggleprotect"),
      ],
      [
        b(t(user, "pinPolicy"), "pinpolicy"),
        b(t(user, "pinSession"), "pinsession"),
      ],
      [b(t(user, "security"), "security")],
      [b(t(user, "inviteExpiry"), "inviteexpiry")],
      [b(t(user, "reconcile"), "reconcile")],
      [b(t(user, "back"), "home")],
    ],
    messageId,
  );
}
async function activity(
  env: Env,
  user: User,
  chat: string,
  messageId?: number,
  page = 0,
): Promise<void> {
  requireOwner(user);
  const rows = await all<{
    event: string;
    created_at: number;
    actor: string | null;
  }>(
    env.VAULTGRAM_DB,
    "SELECT a.event,a.created_at,u.display_name AS actor FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_user_id ORDER BY a.created_at DESC LIMIT 21 OFFSET ?",
    page * 20,
  );
  const keys: Keyboard = [];
  if (page > 0 || rows.length > 20)
    keys.push([
      ...(page > 0 ? [b(t(user, "previous"), `activity:${page - 1}`)] : []),
      ...(rows.length > 20 ? [b(t(user, "next"), `activity:${page + 1}`)] : []),
    ]);
  keys.push([b(t(user, "back"), "home")]);
  await say(
    env,
    user,
    chat,
    `📜 ${t(user, "recentActivity")}\n${
      rows
        .slice(0, 20)
        .map(
          (r) =>
            `${new Date(r.created_at * 1000).toISOString().slice(0, 16)} ${r.event} ${r.actor ?? ""}`,
        )
        .join("\n") || "—"
    }`,
    keys,
    messageId,
  );
}
async function security(
  env: Env,
  user: User,
  chat: string,
  messageId?: number,
): Promise<void> {
  await say(
    env,
    user,
    chat,
    `🔐 PIN: ${user.pin_hash ? t(user, "pinConfigured") : t(user, "off")}`,
    [
      [b(user.pin_hash ? t(user, "resetPin") : t(user, "setPin"), "setpin")],
      [b(t(user, "back"), "settings")],
    ],
    messageId,
  );
}
async function getDocument(
  env: Env,
  user: User,
  chat: string,
  d: Document,
): Promise<void> {
  const v = await vault(env.VAULTGRAM_DB, d.vault_id);
  if (!v) throw new Forbidden();
  await requireLevel(env.VAULTGRAM_DB, user, d.vault_id, "VIEW");
  if (await pinRequired(env, user, v, "download")) {
    await setState(env, user, "pin_action", { action: `get:${d.id}` });
    await send(env, chat, user.pin_hash ? t(user, "pinNeeded") : t(user, "noPin"));
    return;
  }
  const result = await readDocument(env, user, d.id);
  if (!result.stream) {
    if (now() - d.updated_at < 120) {
      await send(env, chat, t(user, "filePropagating"));
      return;
    }
    await run(env.VAULTGRAM_DB, "UPDATE documents SET status='MISSING' WHERE id=?", d.id);
    await audit(env.VAULTGRAM_DB, user.id, "DOCUMENT_MISSING", d.id);
    await send(env, chat, t(user, "missing"));
    return;
  }
  const protect = yes(await setting(env.VAULTGRAM_DB, "protect_content"));
  const seconds = Number(await setting(env.VAULTGRAM_DB, "delete_after_seconds"));
  const sent = await sendDocumentStream(env, chat, result.stream, d.original_filename, d.title, protect, d.size_bytes);
  try {
    await scheduleDelete(env, { chat_id: chat, message_id: sent.message_id }, seconds);
  } catch {
    try { await send(env, chat, t(user, "deletionScheduleFailed")); } catch { /* Telegram unavailable */ }
  }
  try { await audit(env.VAULTGRAM_DB, user.id, "DOCUMENT_DOWNLOADED", d.id); }
  catch { console.error(JSON.stringify({ event: "download_audit_failed", documentId: d.id })); }
}

async function ingest(
  env: Env,
  user: User,
  msg: Message,
  state: Session,
): Promise<void> {
  const payload = JSON.parse(state.payload ?? "{}") as { categoryId?: string; documentId?: string };
  const old = payload.documentId ? await document(env.VAULTGRAM_DB, payload.documentId) : null;
  const c = old ? await category(env.VAULTGRAM_DB, old.category_id) : payload.categoryId ? await category(env.VAULTGRAM_DB, payload.categoryId) : null;
  if (!c) throw new Forbidden();
  await requireLevel(env.VAULTGRAM_DB, user, c.vault_id, "EDIT");
  const v = await vault(env.VAULTGRAM_DB, c.vault_id);
  if (!v) throw new Forbidden();
  if (await pinRequired(env, user, v, "edit")) {
    await setState(env, user, "pin_action", { action: old ? `replace:${old.id}` : `add:${c.id}` });
    await send(env, user.telegram_id, user.pin_hash ? t(user, "pinNeeded") : t(user, "noPin"));
    return;
  }
  if (!msg.document && !msg.photo?.length) {
    await send(env, user.telegram_id, t(user, "sendFile"));
    return;
  }
  let saved: Awaited<ReturnType<typeof saveUploadedDocument>>;
  try {
    saved = await saveUploadedDocument(env, user, msg, payload.categoryId, payload.documentId);
  } catch (error) {
    if (error instanceof UploadTooLarge) {
      await send(env, user.telegram_id, t(user, "tooLarge"));
      return;
    }
    throw error;
  }
  await clearState(env, user);
  if (yes(await setting(env.VAULTGRAM_DB, "delete_incoming")))
    try { await deleteMessage(env, { chat_id: user.telegram_id, message_id: msg.message_id }); }
    catch { /* Telegram can decline deletion */ }
  await send(env, user.telegram_id, `✅ ${t(user, "saved")}`);
  await showCategory(env, user, user.telegram_id, saved.categoryId);
}

async function input(
  env: Env,
  user: User,
  msg: Message,
  s: Session,
): Promise<void> {
  const rawText = msg.text ?? "";
  const text = rawText.trim();
  const p = JSON.parse(s.payload ?? "{}") as {
    vaultId?: string;
    categoryId?: string;
    documentId?: string;
    valueId?: string;
    label?: string;
    action?: string;
    after?: "home";
  };
  const db = env.VAULTGRAM_DB;
  const state = s.state;
  if (state === "upload" || state === "replace") {
    await ingest(env, user, msg, s);
    return;
  }
  if (state === "pin_action" || state === "pin_reset_auth") {
    try {
      await deleteMessage(env, {
        chat_id: user.telegram_id,
        message_id: msg.message_id,
      });
    } catch {
      /* best effort */
    }
    if (!/^\d{6,12}$/.test(text)) {
      await send(env, user.telegram_id, t(user, "pinWrong"));
      return;
    }
    if (await verifyPin(env, user, text)) {
      if (state === "pin_reset_auth") {
        await setState(env, user, "pin_new");
        await send(env, user.telegram_id, t(user, "newPinPrompt"));
      } else {
        await clearState(env, user);
        if (p.action) await dispatch(env, user, user.telegram_id, p.action);
      }
    } else await send(env, user.telegram_id, t(user, "pinWrong"));
    return;
  }
  if (state === "pin_new") {
    try {
      await deleteMessage(env, {
        chat_id: user.telegram_id,
        message_id: msg.message_id,
      });
    } catch {
      /* best effort */
    }
    if (!/^\d{6,12}$/.test(text)) {
      await send(env, user.telegram_id, t(user, "invalidPin"));
      return;
    }
    await setPin(env, user, text);
    await clearState(env, user);
    await send(env, user.telegram_id, t(user, "pinSet"));
    const updated = (await userByTelegram(db, user.telegram_id)) ?? user;
    const localized = { ...updated, locale: updated.locale ?? user.locale };
    if (p.after === "home") await home(env, localized, user.telegram_id);
    else await security(env, localized, user.telegram_id);
    return;
  }
  if (state === "secure_label" && p.vaultId) {
    await requireLevel(db,user,p.vaultId,"EDIT");
    if(text.length<1||text.length>100||/[\u0000-\u001f\u007f]/.test(text)){
      await send(env,user.telegram_id,t(user,"inputLength"));return;
    }
    await setState(env,user,"secure_create_value",{vaultId:p.vaultId,label:text});
    await send(env,user.telegram_id,tr(user,"secureValuePrompt",{label:text}));
    return;
  }
  if ((state === "secure_create_value" && p.vaultId && p.label) ||
      (state === "secure_edit_value" && p.valueId)) {
    if(!rawText||new TextEncoder().encode(rawText).byteLength>3000){
      try{await deleteMessage(env,{chat_id:user.telegram_id,message_id:msg.message_id})}catch{/* best effort */}
      await send(env,user.telegram_id,t(user,"secureValueInvalid"));
      return;
    }
    let valueId:string;
    try{
      if(state==="secure_create_value"&&p.vaultId&&p.label)
        valueId=await createSecureValue(env,user,p.vaultId,p.label,rawText);
      else if(p.valueId){await updateSecureValue(env,user,p.valueId,rawText);valueId=p.valueId}
      else throw new Forbidden();
    }catch(error){
      try{await deleteMessage(env,{chat_id:user.telegram_id,message_id:msg.message_id})}catch{/* best effort */}
      if(error instanceof PinRequired){
        await setState(env,user,"pin_action",{action:p.valueId?`svedit:${p.valueId}`:`svnew:${p.vaultId}`});
        await send(env,user.telegram_id,user.pin_hash?t(user,"pinNeeded"):t(user,"noPin"));
        return;
      }
      throw error;
    }
    let removed=true;
    try{await deleteMessage(env,{chat_id:user.telegram_id,message_id:msg.message_id})}catch{removed=false}
    await clearState(env,user);
    if(!removed)await send(env,user.telegram_id,t(user,"secureValueDeleteFailed"));
    await send(env,user.telegram_id,t(user,"secureValueSaved"));
    await showSecureValue(env,user,user.telegram_id,valueId);
    return;
  }
  if(state==="secure_rename_label"&&p.valueId){
    await renameSecureValue(env,user,p.valueId,text);
    await clearState(env,user);
    await showSecureValue(env,user,user.telegram_id,p.valueId);
    return;
  }
  const inputAction =
    state === "newcat" && p.vaultId
      ? `newcat:${p.vaultId}`
      : state === "renamev" && p.vaultId
        ? `renamev:${p.vaultId}`
        : state === "renamec" && p.categoryId
          ? `renamec:${p.categoryId}`
          : state === "renamed" && p.documentId
            ? `renamed:${p.documentId}`
            : null;
  if (inputAction) {
    const [, target] = inputAction.split(":");
    if (target) {
      const vid =
        p.vaultId ??
        (p.categoryId ? (await category(db, p.categoryId))?.vault_id : null) ??
        (p.documentId ? (await document(db, p.documentId))?.vault_id : null);
      const v = vid ? await vault(db, vid) : null;
      if (v && (await pinRequired(env, user, v, "edit"))) {
        await setState(env, user, "pin_action", { action: inputAction });
        await send(
          env,
          user.telegram_id,
          user.pin_hash ? t(user, "pinNeeded") : t(user, "noPin"),
        );
        return;
      }
    }
  }
  if (text.length < 1 || text.length > 100 || /[\u0000-\u001f]/.test(text)) {
    await send(env, user.telegram_id, t(user, "inputLength"));
    return;
  }
  if (state === "newvault") {
    requireOwner(user);
    const vid = id();
    await run(
      db,
      "INSERT INTO vaults(id,name,created_at) VALUES(?,?,?)",
      vid,
      text,
      now(),
    );
    await audit(db, user.id, "VAULT_CREATED", vid);
    await clearState(env, user);
    await showVault(env, user, user.telegram_id, vid);
    return;
  }
  if (state === "newcat" && p.vaultId) {
    await requireLevel(db, user, p.vaultId, "MANAGE");
    const cid = id();
    await run(
      db,
      "INSERT INTO categories(id,vault_id,name,sort_order,created_at) VALUES(?,?,?,(SELECT COALESCE(MAX(sort_order),0)+1 FROM categories WHERE vault_id=?),?)",
      cid,
      p.vaultId,
      text,
      p.vaultId,
      now(),
    );
    await audit(db, user.id, "CATEGORY_CREATED", cid);
    await clearState(env, user);
    await showCategory(env, user, user.telegram_id, cid);
    return;
  }
  if (state === "renamev" && p.vaultId) {
    requireOwner(user);
    if (!(await vault(db, p.vaultId))) throw new Forbidden();
    await run(db, "UPDATE vaults SET name=? WHERE id=?", text, p.vaultId);
    await audit(db, user.id, "VAULT_UPDATED", p.vaultId);
    await clearState(env, user);
    await showVault(env, user, user.telegram_id, p.vaultId);
    return;
  }
  if (state === "renamec" && p.categoryId) {
    const c = await category(db, p.categoryId);
    if (!c) throw new Forbidden();
    await requireLevel(db, user, c.vault_id, "MANAGE");
    await run(db, "UPDATE categories SET name=? WHERE id=?", text, c.id);
    await audit(db, user.id, "CATEGORY_UPDATED", c.id);
    await clearState(env, user);
    await showCategory(env, user, user.telegram_id, c.id);
    return;
  }
  if (state === "renamed" && p.documentId) {
    const d = await document(db, p.documentId);
    if (!d) throw new Forbidden();
    await requireLevel(db, user, d.vault_id, "EDIT");
    await run(
      db,
      "UPDATE documents SET title=?,updated_at=? WHERE id=?",
      text,
      now(),
      d.id,
    );
    await audit(db, user.id, "DOCUMENT_UPDATED", d.id);
    await clearState(env, user);
    await showDocument(env, user, user.telegram_id, d.id);
    return;
  }
  if (state === "setname") {
    requireOwner(user);
    await run(db, "UPDATE workspaces SET name=? WHERE id='default'", text);
    await audit(db, user.id, "SETTINGS_CHANGED", null, {
      key: "workspace_name",
    });
    await clearState(env, user);
    await settings(env, user, user.telegram_id);
    return;
  }
  await clearState(env, user);
  await home(env, user, user.telegram_id);
}
async function confirm(
  env: Env,
  user: User,
  chat: string,
  kind: string,
  payload: unknown,
  label: string,
): Promise<void> {
  const pid = await createPending(env.VAULTGRAM_DB, user.id, kind, payload);
  await say(env, user, chat, `${t(user, "confirmPrompt")}: ${label}`, [
    [b(t(user, "confirm"), `ok:${pid}`), b(t(user, "cancel"), "home")],
  ]);
}
export async function executePending(
  env: Env,
  user: User,
  chat: string,
  pid: string,
): Promise<void> {
  const row = await one<{ kind: string; payload: string }>(
    env.VAULTGRAM_DB,
    "SELECT kind,payload FROM pending_actions WHERE id=? AND user_id=? AND consumed_at IS NULL AND expires_at>?",
    pid,
    user.id,
    now(),
  );
  if (!row) throw new Forbidden();
  const preview = JSON.parse(row.payload) as { id?: string; vaultId?: string };
  let pinVaultId = preview.vaultId ?? null;
  if (["archive_vault", "delete_vault"].includes(row.kind) && preview.id)
    pinVaultId = preview.id;
  if (
    ["archive_doc", "delete_doc", "replace_prompt"].includes(row.kind) &&
    preview.id
  )
    pinVaultId =
      (
        await one<Document>(
          env.VAULTGRAM_DB,
          "SELECT * FROM documents WHERE id=?",
          preview.id,
        )
      )?.vault_id ?? null;
  if (row.kind === "delete_category" && preview.id)
    pinVaultId =
      (await category(env.VAULTGRAM_DB, preview.id))?.vault_id ?? null;
  if (["archive_secure_value","delete_secure_value"].includes(row.kind) && preview.id)
    pinVaultId = (await one<SecureValue>(env.VAULTGRAM_DB,"SELECT * FROM secure_values WHERE id=?",preview.id))?.vault_id??null;
  if (pinVaultId) {
    const v =
      row.kind === "delete_vault"
        ? await one<Vault>(
            env.VAULTGRAM_DB,
            "SELECT * FROM vaults WHERE id=? AND archived_at IS NOT NULL",
            pinVaultId,
          )
        : await vault(env.VAULTGRAM_DB, pinVaultId);
    if (!v) throw new Forbidden();
    if (await pinRequired(env, user, v, "edit")) {
      await setState(env, user, "pin_action", { action: `ok:${pid}` });
      await send(
        env,
        chat,
        user.pin_hash ? t(user, "pinNeeded") : t(user, "noPin"),
      );
      return;
    }
  }
  const p = await consumePending<{
    id?: string;
    memberId?: string;
    vaultId?: string;
  }>(env.VAULTGRAM_DB, pid, user.id, row.kind);
  const db = env.VAULTGRAM_DB;
  if (row.kind === "replace_prompt" && p.id) {
    const d = await document(db, p.id);
    if (!d) throw new Forbidden();
    await requireLevel(db, user, d.vault_id, "EDIT");
    await setState(env, user, "replace", { documentId: d.id }, 1800);
    await send(env, chat, t(user, "sendFile"));
    return;
  }
  if (row.kind === "archive_doc" && p.id) {
    const d = await document(db, p.id);
    if (!d) throw new Forbidden();
    await requireLevel(db, user, d.vault_id, "MANAGE");
    await run(
      db,
      "UPDATE documents SET status='ARCHIVED',updated_at=? WHERE id=?",
      now(),
      d.id,
    );
    await audit(db, user.id, "DOCUMENT_ARCHIVED", d.id);
    await showCategory(env, user, chat, d.category_id);
    return;
  }
  if (row.kind === "delete_doc" && p.id) {
    const d = await one<Document>(
      db,
      "SELECT * FROM documents WHERE id=?",
      p.id,
    );
    if (!d) throw new Forbidden();
    try {
      await permanentlyDeleteDocument(env,user,d.id);
      await showCategory(env, user, chat, d.category_id);
    } catch (error) {
      if (error instanceof Forbidden) throw error;
      await send(env, chat, t(user, "deletionPending"));
    }
    return;
  }
  if (row.kind === "archive_vault" && p.id) {
    requireOwner(user);
    const v = await vault(db, p.id);
    if (!v) throw new Forbidden();
    await run(db, "UPDATE vaults SET archived_at=? WHERE id=?", now(), v.id);
    await audit(db, user.id, "VAULT_ARCHIVED", v.id);
    await vaultList(env, user, chat);
    return;
  }
  if (row.kind === "delete_vault" && p.id) {
    requireOwner(user);
    const v = await one<Vault>(
      db,
      "SELECT * FROM vaults WHERE id=? AND archived_at IS NOT NULL",
      p.id,
    );
    if (!v) throw new Forbidden();
    const count = await one<{ n: number }>(
      db,
      "SELECT (SELECT COUNT(*) FROM documents WHERE vault_id=?) + (SELECT COUNT(*) FROM secure_values WHERE vault_id=?) AS n",
      v.id,
      v.id,
    );
    if ((count?.n ?? 0) > 0) {
      await send(env, chat, t(user, "archivedNotEmpty"));
      return;
    }
    await db.batch([
      db.prepare("DELETE FROM invite_permissions WHERE vault_id=?").bind(v.id),
      db.prepare("DELETE FROM vault_permissions WHERE vault_id=?").bind(v.id),
      db.prepare("DELETE FROM categories WHERE vault_id=?").bind(v.id),
      db
        .prepare("DELETE FROM vaults WHERE id=? AND archived_at IS NOT NULL")
        .bind(v.id),
      db
        .prepare(
          "INSERT INTO audit_logs(id,actor_user_id,event,target_id,created_at) VALUES(?,?,'VAULT_DELETED',?,?)",
        )
        .bind(id(), user.id, v.id, now()),
    ]);
    await archivedVaults(env, user, chat);
    return;
  }
  if (row.kind === "delete_category" && p.id) {
    const c = await category(db, p.id);
    if (!c) throw new Forbidden();
    await requireLevel(db, user, c.vault_id, "MANAGE");
    const docs = await one<{ n: number }>(
      db,
      "SELECT (SELECT COUNT(*) FROM documents WHERE category_id=?) + (SELECT COUNT(*) FROM secure_values WHERE category_id=?) AS n",
      c.id,
      c.id,
    );
    if ((docs?.n ?? 0) > 0) {
      await send(env, chat, t(user, "emptyCategory"));
      return;
    }
    await run(db, "DELETE FROM categories WHERE id=?", c.id);
    await audit(db, user.id, "CATEGORY_DELETED", c.id);
    await showVault(env, user, chat, c.vault_id);
    return;
  }
  if(row.kind==="archive_secure_value"&&p.id){
    const row=await one<SecureValue>(db,"SELECT * FROM secure_values WHERE id=?",p.id);
    if(!row)throw new Forbidden();
    await archiveSecureValue(env,user,row.id);
    await showInformation(env,user,chat,row.vault_id);
    return;
  }
  if(row.kind==="delete_secure_value"&&p.id){
    const row=await one<SecureValue>(db,"SELECT * FROM secure_values WHERE id=?",p.id);
    if(!row)throw new Forbidden();
    await deleteSecureValue(env,user,row.id);
    await showInformation(env,user,chat,row.vault_id);
    return;
  }
  if (row.kind === "revoke" && p.memberId && p.vaultId) {
    requireOwner(user);
    await run(
      db,
      "DELETE FROM vault_permissions WHERE user_id=? AND vault_id=?",
      p.memberId,
      p.vaultId,
    );
    await audit(db, user.id, "PERMISSION_REVOKED", p.memberId, {
      vault_id: p.vaultId,
    });
    await permissionMenu(env, user, chat, p.memberId);
    return;
  }
  if (row.kind === "disable" && p.id) {
    requireOwner(user);
    const m = await one<User>(
      db,
      "SELECT * FROM users WHERE id=? AND role='MEMBER'",
      p.id,
    );
    if (!m || m.removed) throw new Forbidden();
    await run(
      db,
      "UPDATE users SET disabled=? WHERE id=?",
      m.disabled ? 0 : 1,
      m.id,
    );
    await audit(
      db,
      user.id,
      m.disabled ? "MEMBER_ENABLED" : "MEMBER_DISABLED",
      m.id,
    );
    await member(env, user, chat, m.id);
    return;
  }
  if (row.kind === "remove_member" && p.id) {
    requireOwner(user);
    const m = await one<User>(
      db,
      "SELECT * FROM users WHERE id=? AND role='MEMBER'",
      p.id,
    );
    if (!m) throw new Forbidden();
    await db.batch([
      db.prepare("DELETE FROM vault_permissions WHERE user_id=?").bind(m.id),
      db.prepare("UPDATE users SET disabled=1,removed=1 WHERE id=?").bind(m.id),
    ]);
    await audit(db, user.id, "MEMBER_REMOVED", m.id);
    await member(env, user, chat, m.id);
    return;
  }
  if (row.kind === "reset_pin" && p.id) {
    requireOwner(user);
    const m = await one<User>(
      db,
      "SELECT * FROM users WHERE id=? AND role='MEMBER' AND removed=0",
      p.id,
    );
    if (!m || !m.pin_hash) throw new Forbidden();
    await db.batch([
      db
        .prepare(
          "UPDATE users SET pin_salt=NULL,pin_hash=NULL,pin_failures=0,pin_locked_until=0 WHERE id=?",
        )
        .bind(m.id),
      db
        .prepare(
          "UPDATE user_sessions SET pin_unlocked_until=0 WHERE user_id=?",
        )
        .bind(m.id),
    ]);
    await audit(db, user.id, "PIN_RESET_BY_OWNER", m.id);
    await member(env, user, chat, m.id);
    return;
  }
  if (row.kind === "revoke_invite" && p.id) {
    requireOwner(user);
    await run(
      db,
      "UPDATE invites SET revoked_at=? WHERE id=? AND used_at IS NULL",
      now(),
      p.id,
    );
    await audit(db, user.id, "INVITE_REVOKED", p.id);
    await dispatch(env, user, chat, "invites");
    return;
  }
  throw new Forbidden();
}
async function reconcile(env: Env, user: User, chat: string): Promise<void> {
  requireOwner(user);
  const db=env.VAULTGRAM_DB;
  const jobs=await all<{id:string;storage_key:string}>(db,
    "SELECT id,storage_key FROM kv_cleanup_jobs WHERE completed_at IS NULL ORDER BY created_at LIMIT 5");
  let cleaned=0;
  for(const job of jobs){
    try{
      const referenced=await one<{id:string}>(db,"SELECT id FROM documents WHERE storage_key=? LIMIT 1",job.storage_key);
      if(!referenced){await removeDocument(env,job.storage_key);cleaned++}
      await run(db,"UPDATE kv_cleanup_jobs SET completed_at=? WHERE id=?",now(),job.id);
    }catch{/* retry next run */}
  }
  const deleting=await all<Document>(db,"SELECT * FROM documents WHERE status='DELETING' LIMIT 5");
  for(const d of deleting){
    try{await removeDocument(env,d.storage_key);await run(db,"DELETE FROM documents WHERE id=?",d.id);await audit(db,user.id,"DOCUMENT_DELETED",d.id)}
    catch{/* retry next run */}
  }
  const docs=await all<Document>(db,
    "SELECT * FROM documents WHERE status='ACTIVE' AND updated_at<? ORDER BY last_checked_at,id LIMIT 10",now()-120);
  let missing=0;
  for(const d of docs){
    try{
      if(!(await documentExists(env,d.storage_key))){
        await run(db,"UPDATE documents SET status='MISSING',last_checked_at=? WHERE id=?",now(),d.id);
        missing++;
      }else await run(db,"UPDATE documents SET last_checked_at=? WHERE id=?",now(),d.id);
    }catch{/* do not treat temporary KV failure as missing */}
  }
  await audit(db,user.id,"RECONCILIATION_RUN",null,{cleaned,missing});
  await send(env,chat,tr(user,"reconciliationResult",{missing,cleaned,retried:deleting.length,checked:docs.length}));
}

async function dispatch(
  env: Env,
  user: User,
  chat: string,
  data: string,
  messageId?: number,
): Promise<void> {
  const parts = data.split(":");
  const action = parts[0] ?? "",
    a = parts[1],
    bv = parts[2];
  const db = env.VAULTGRAM_DB;
  if (a && ["restorev", "deletev"].includes(action)) {
    requireOwner(user);
    const archived = await one<Vault>(
      db,
      "SELECT * FROM vaults WHERE id=? AND archived_at IS NOT NULL",
      a,
    );
    if (!archived) throw new Forbidden();
    if (await pinRequired(env, user, archived, "edit")) {
      await setState(env, user, "pin_action", { action: data });
      await send(
        env,
        chat,
        user.pin_hash ? t(user, "pinNeeded") : t(user, "noPin"),
      );
      return;
    }
  }
  if (a) {
    let vaultId: string | null = null;
    if (["v", "vdocs", "info", "svtrash", "svnew", "newcat", "renamev", "archivev", "vpin"].includes(action))
      vaultId = a;
    if (["sv", "svshow", "svedit", "svrename", "svarchive", "svrestore", "svdelete"].includes(action))
      vaultId=(await one<SecureValue>(db,"SELECT * FROM secure_values WHERE id=?",a))?.vault_id??null;
    if (
      ["c", "trash", "add", "renamec", "delc", "catup", "catdown"].includes(
        action,
      )
    )
      vaultId = (await category(db, a))?.vault_id ?? null;
    if (
      [
        "d",
        "get",
        "trashdoc",
        "restore",
        "replace",
        "renamed",
        "archived",
        "deleted",
      ].includes(action)
    )
      vaultId =
        (await one<Document>(db, "SELECT * FROM documents WHERE id=?", a))
          ?.vault_id ?? null;
    if (vaultId) {
      await requireLevel(db, user, vaultId, "VIEW");
      const v = await vault(db, vaultId);
      if (!v) throw new Forbidden();
      const kind =
        action === "get" || action === "svshow"
          ? "download"
          : ["v", "vdocs", "info", "svtrash", "sv", "c", "d"].includes(action)
            ? "browse"
            : "edit";
      if (await pinRequired(env, user, v, kind)) {
        await setState(env, user, "pin_action", { action: data });
        await send(
          env,
          chat,
          user.pin_hash ? t(user, "pinNeeded") : t(user, "noPin"),
        );
        return;
      }
    }
  }
  if (action === "home") {
    await home(env, user, chat, messageId);
    return;
  }
  if (action === "vaults") {
    await vaultList(env, user, chat, messageId, pageValue(a));
    return;
  }
  if (action === "archivedvaults") {
    await archivedVaults(env, user, chat, messageId, pageValue(a));
    return;
  }
  if (action === "restorev" && a) {
    requireOwner(user);
    const v = await one<Vault>(
      db,
      "SELECT * FROM vaults WHERE id=? AND archived_at IS NOT NULL",
      a,
    );
    if (!v) throw new Forbidden();
    await run(db, "UPDATE vaults SET archived_at=NULL WHERE id=?", v.id);
    await audit(db, user.id, "VAULT_RESTORED", v.id);
    await showVault(env, user, chat, v.id, messageId);
    return;
  }
  if (action === "deletev" && a) {
    requireOwner(user);
    const v = await one<Vault>(
      db,
      "SELECT * FROM vaults WHERE id=? AND archived_at IS NOT NULL",
      a,
    );
    if (!v) throw new Forbidden();
    await confirm(
      env,
      user,
      chat,
      "delete_vault",
      { id: v.id },
      tr(user, "deleteVaultConfirm", { name: v.name }),
    );
    return;
  }
  if (action === "v" && a) {
    await showVault(env, user, chat, a, messageId);
    return;
  }
  if(action==="vdocs"&&a){await showVaultDocuments(env,user,chat,a,messageId,pageValue(bv));return}
  if(action==="info"&&a){await showInformation(env,user,chat,a,messageId,pageValue(bv));return}
  if(action==="svtrash"&&a){await showInformation(env,user,chat,a,messageId,pageValue(bv),true);return}
  if(action==="sv"&&a){await showSecureValue(env,user,chat,a,messageId);return}
  if(action==="svshow"&&a){
    let revealed:Awaited<ReturnType<typeof getSecureValue>>;
    try{revealed=await getSecureValue(env,user,a)}
    catch(error){
      if(error instanceof PinRequired){await setState(env,user,"pin_action",{action:data});await send(env,chat,user.pin_hash?t(user,"pinNeeded"):t(user,"noPin"));return}
      throw error;
    }
    const protect=yes(await setting(db,"protect_content"));
    const seconds=Number(await setting(db,"delete_after_seconds"));
    const sent=await sendProtectedText(env,chat,`🔐 ${revealed.label}\n\n${revealed.value}${seconds>0?`\n\n${t(user,"secureValueAutoDelete")}`:""}`,protect);
    try{await scheduleDelete(env,{chat_id:chat,message_id:sent.message_id},seconds)}
    catch{try{await send(env,chat,t(user,"deletionScheduleFailed"))}catch{/* Telegram unavailable */}}
    return;
  }
  if(action==="svnew"&&a){await requireLevel(db,user,a,"EDIT");await setState(env,user,"secure_label",{vaultId:a});await send(env,chat,t(user,"secureLabelPrompt"));return}
  if(action==="svedit"&&a){
    const row=await one<SecureValue>(db,"SELECT * FROM secure_values WHERE id=? AND archived_at IS NULL",a);
    if(!row)throw new Forbidden();
    await requireLevel(db,user,row.vault_id,"EDIT");
    await setState(env,user,"secure_edit_value",{valueId:a});
    await send(env,chat,tr(user,"secureValuePrompt",{label:row.label}));return;
  }
  if(action==="svrename"&&a){
    const row=await one<SecureValue>(db,"SELECT * FROM secure_values WHERE id=? AND archived_at IS NULL",a);
    if(!row)throw new Forbidden();
    await requireLevel(db,user,row.vault_id,"EDIT");
    await setState(env,user,"secure_rename_label",{valueId:a});
    await send(env,chat,t(user,"secureLabelPrompt"));return;
  }
  if(action==="svarchive"&&a){
    const row=await one<SecureValue>(db,"SELECT * FROM secure_values WHERE id=? AND archived_at IS NULL",a);
    if(!row)throw new Forbidden();await requireLevel(db,user,row.vault_id,"MANAGE");
    await confirm(env,user,chat,"archive_secure_value",{id:a},tr(user,"archiveSecureValueConfirm",{name:row.label}));return;
  }
  if(action==="svdelete"&&a){
    const row=await one<SecureValue>(db,"SELECT * FROM secure_values WHERE id=?",a);
    if(!row)throw new Forbidden();await requireLevel(db,user,row.vault_id,"MANAGE");
    await confirm(env,user,chat,"delete_secure_value",{id:a},tr(user,"deleteSecureValueConfirm",{name:row.label}));return;
  }
  if(action==="svrestore"&&a){await restoreSecureValue(env,user,a);await showSecureValue(env,user,chat,a,messageId);return}
  if (action === "c" && a) {
    await showCategory(env, user, chat, a, messageId, pageValue(bv));
    return;
  }
  if ((action === "catup" || action === "catdown") && a) {
    const cat = await category(db, a);
    if (!cat) throw new Forbidden();
    await requireLevel(db, user, cat.vault_id, "MANAGE");
    const rows = await all<Category>(
      db,
      "SELECT * FROM categories WHERE vault_id=? ORDER BY sort_order,name",
      cat.vault_id,
    );
    const current = rows.findIndex((x) => x.id === a),
      other = current + (action === "catup" ? -1 : 1);
    if (current >= 0 && other >= 0 && other < rows.length) {
      [rows[current], rows[other]] = [rows[other]!, rows[current]!];
      await db.batch(
        rows.map((r, i) =>
          db
            .prepare("UPDATE categories SET sort_order=? WHERE id=?")
            .bind(i + 1, r.id),
        ),
      );
      await audit(db, user.id, "CATEGORY_REORDERED", a);
    }
    await showVault(env, user, chat, cat.vault_id, messageId);
    return;
  }
  if (action === "d" && a) {
    const d = await document(db, a);
    if (!d) throw new Forbidden();
    if (user.role === "MEMBER" && (await level(db, user, d.vault_id)) === "VIEW") {
      await getDocument(env, user, chat, d);
      return;
    }
    await showDocument(env, user, chat, a, messageId);
    return;
  }
  if (action === "trash" && a) {
    await showTrash(env, user, chat, a, messageId, pageValue(bv));
    return;
  }
  if (action === "trashdoc" && a) {
    await showTrashDocument(env, user, chat, a, messageId);
    return;
  }
  if (action === "restore" && a) {
    const d = await one<Document>(
      db,
      "SELECT * FROM documents WHERE id=? AND status='ARCHIVED'",
      a,
    );
    if (!d) throw new Forbidden();
    await requireLevel(db, user, d.vault_id, "MANAGE");
    await run(
      db,
      "UPDATE documents SET status='ACTIVE',updated_at=? WHERE id=?",
      now(),
      d.id,
    );
    await audit(db, user.id, "DOCUMENT_RESTORED", d.id);
    await showCategory(env, user, chat, d.category_id, messageId);
    return;
  }
  if (action === "get" && a) {
    const d = await document(db, a);
    if (!d) throw new Forbidden();
    await getDocument(env, user, chat, d);
    return;
  }
  if (action === "newvault") {
    requireOwner(user);
    await setState(env, user, "newvault");
    await send(env, chat, t(user, "sendName"));
    return;
  }
  if (action === "newcat" && a) {
    await requireLevel(db, user, a, "MANAGE");
    await setState(env, user, "newcat", { vaultId: a });
    await send(env, chat, t(user, "sendName"));
    return;
  }
  if (action === "add" && a) {
    const cat = await category(db, a);
    if (!cat) throw new Forbidden();
    await requireLevel(db, user, cat.vault_id, "EDIT");
    await setState(env, user, "upload", { categoryId: a }, 1800);
    await send(env, chat, t(user, "sendFile"));
    return;
  }
  if (action === "replace" && a) {
    const d = await document(db, a);
    if (!d) throw new Forbidden();
    await requireLevel(db, user, d.vault_id, "EDIT");
    await confirm(
      env,
      user,
      chat,
      "replace_prompt",
      { id: d.id },
      tr(user, "replaceConfirm", { name: d.title }),
    );
    return;
  }
  if (action === "renamev" && a) {
    requireOwner(user);
    if (!(await vault(db, a))) throw new Forbidden();
    await setState(env, user, "renamev", { vaultId: a });
    await send(env, chat, t(user, "sendName"));
    return;
  }
  if (action === "renamec" && a) {
    const cat = await category(db, a);
    if (!cat) throw new Forbidden();
    await requireLevel(db, user, cat.vault_id, "MANAGE");
    await setState(env, user, "renamec", { categoryId: a });
    await send(env, chat, t(user, "sendName"));
    return;
  }
  if (action === "renamed" && a) {
    const d = await document(db, a);
    if (!d) throw new Forbidden();
    await requireLevel(db, user, d.vault_id, "EDIT");
    await setState(env, user, "renamed", { documentId: a });
    await send(env, chat, t(user, "sendName"));
    return;
  }
  if (action === "archived" && a) {
    const d = await document(db, a);
    if (!d) throw new Forbidden();
    await requireLevel(db, user, d.vault_id, "MANAGE");
    await confirm(
      env,
      user,
      chat,
      "archive_doc",
      { id: a },
      tr(user, "archiveDocumentConfirm", { name: d.title }),
    );
    return;
  }
  if (action === "deleted" && a) {
    const d = await one<Document>(db, "SELECT * FROM documents WHERE id=?", a);
    if (!d) throw new Forbidden();
    await requireLevel(db, user, d.vault_id, "MANAGE");
    await confirm(
      env,
      user,
      chat,
      "delete_doc",
      { id: a },
      tr(user, "deleteDocumentConfirm", { name: d.title }),
    );
    return;
  }
  if (action === "archivev" && a) {
    requireOwner(user);
    const v = await vault(db, a);
    if (!v) throw new Forbidden();
    await confirm(
      env,
      user,
      chat,
      "archive_vault",
      { id: a },
      tr(user, "archiveVaultConfirm", { name: v.name }),
    );
    return;
  }
  if (action === "delc" && a) {
    const cat = await category(db, a);
    if (!cat) throw new Forbidden();
    await requireLevel(db, user, cat.vault_id, "MANAGE");
    await confirm(
      env,
      user,
      chat,
      "delete_category",
      { id: a },
      tr(user, "deleteCategoryConfirm", { name: cat.name }),
    );
    return;
  }
  if (action === "vpin" && a) {
    requireOwner(user);
    const v = await vault(db, a);
    if (!v) throw new Forbidden();
    await run(
      db,
      "UPDATE vaults SET requires_pin=? WHERE id=?",
      v.requires_pin ? 0 : 1,
      a,
    );
    await audit(db, user.id, "VAULT_UPDATED", a, {
      requires_pin: !v.requires_pin,
    });
    await showVault(env, user, chat, a, messageId);
    return;
  }
  if (action === "ok" && a) {
    await executePending(env, user, chat, a);
    return;
  }
  if (action === "members") {
    await members(env, user, chat, messageId, pageValue(a));
    return;
  }
  if (action === "member" && a) {
    await member(env, user, chat, a, messageId);
    return;
  }
  if (action === "perm" && a) {
    await permissionMenu(env, user, chat, a, messageId, pageValue(bv));
    return;
  }
  if (action === "grantv" && a) {
    await grantMenu(env, user, chat, a, messageId);
    return;
  }
  if (
    action === "grant" &&
    a &&
    bv &&
    ["VIEW", "EDIT", "MANAGE"].includes(bv)
  ) {
    const { memberId, vaultId } = await grantTarget(env, user, a);
    const m = await one<User>(
        db,
        "SELECT * FROM users WHERE id=? AND role='MEMBER'",
        memberId,
      ),
      v = await vault(db, vaultId);
    if (!m || m.removed || !v) throw new Forbidden();
    await run(
      db,
      "INSERT INTO vault_permissions(user_id,vault_id,level) VALUES(?,?,?) ON CONFLICT(user_id,vault_id) DO UPDATE SET level=excluded.level",
      memberId,
      vaultId,
      bv,
    );
    await audit(db, user.id, "PERMISSION_GRANTED", memberId, {
      vault_id: vaultId,
      level: bv,
    });
    await permissionMenu(env, user, chat, memberId, messageId);
    return;
  }
  if (action === "revoke" && a) {
    const target = await grantTarget(env, user, a);
    await confirm(
      env,
      user,
      chat,
      "revoke",
      target,
      t(user, "revokeAccessConfirm"),
    );
    return;
  }
  if (action === "disable" && a) {
    requireOwner(user);
    const m = await one<User>(
      db,
      "SELECT * FROM users WHERE id=? AND role='MEMBER'",
      a,
    );
    if (!m) throw new Forbidden();
    await confirm(
      env,
      user,
      chat,
      "disable",
      { id: a },
      tr(user, m.disabled ? "enableMemberConfirm" : "disableMemberConfirm", {
        name: m.display_name,
      }),
    );
    return;
  }
  if (action === "removemember" && a) {
    requireOwner(user);
    const m = await one<User>(
      db,
      "SELECT * FROM users WHERE id=? AND role='MEMBER' AND removed=0",
      a,
    );
    if (!m) throw new Forbidden();
    await confirm(
      env,
      user,
      chat,
      "remove_member",
      { id: a },
      tr(user, "removeMemberConfirm", { name: m.display_name }),
    );
    return;
  }
  if (action === "resetmemberpin" && a) {
    requireOwner(user);
    const m = await one<User>(
      db,
      "SELECT * FROM users WHERE id=? AND role='MEMBER' AND removed=0",
      a,
    );
    if (!m || !m.pin_hash) throw new Forbidden();
    await confirm(
      env,
      user,
      chat,
      "reset_pin",
      { id: m.id },
      `${t(user, "resetMemberPin")}: ${m.display_name}`,
    );
    return;
  }
  if (action === "restoremember" && a) {
    requireOwner(user);
    const m = await one<User>(
      db,
      "SELECT * FROM users WHERE id=? AND role='MEMBER' AND removed=1",
      a,
    );
    if (!m) throw new Forbidden();
    await run(db, "UPDATE users SET disabled=0,removed=0 WHERE id=?", a);
    await audit(db, user.id, "MEMBER_RESTORED", a);
    await member(env, user, chat, a, messageId);
    return;
  }
  if (action === "invite") {
    await createInvite(env, user, chat);
    return;
  }
  if (action === "invites") {
    requireOwner(user);
    const rows = await all<{ id: string; expires_at: number }>(
      db,
      "SELECT id,expires_at FROM invites WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at>? ORDER BY created_at DESC LIMIT 30",
      now(),
    );
    await say(
      env,
      user,
      chat,
      `${t(user, "pendingInvites")}: ${rows.length}`,
      [
        ...rows.map((r) => [
          b(
            tr(user, "revokeInviteButton", {
              date: new Date(r.expires_at * 1000).toISOString().slice(0, 16),
            }),
            `revokeinvite:${r.id}`,
          ),
        ]),
        [b(t(user, "back"), "members")],
      ],
      messageId,
    );
    return;
  }
  if (action === "revokeinvite" && a) {
    requireOwner(user);
    await confirm(
      env,
      user,
      chat,
      "revoke_invite",
      { id: a },
      t(user, "revokeInviteConfirm"),
    );
    return;
  }
  if (action === "activity") {
    await activity(env, user, chat, messageId, pageValue(a));
    return;
  }
  if (action === "security") {
    await security(env, user, chat, messageId);
    return;
  }
  if (action === "setpin") {
    await setState(env, user, user.pin_hash ? "pin_reset_auth" : "pin_new");
    await send(
      env,
      chat,
      user.pin_hash ? t(user, "oldPinPrompt") : t(user, "newPinPrompt"),
    );
    return;
  }
  if (action === "userlang" && a && ["en", "fa"].includes(a)) {
    await run(db, "UPDATE users SET locale=? WHERE id=?", a, user.id);
    await home(env, { ...user, locale: a as "en" | "fa" }, chat, messageId);
    return;
  }
  if (action === "settings") {
    await settings(env, user, chat, messageId);
    return;
  }
  if (action === "setname") {
    requireOwner(user);
    await setState(env, user, "setname");
    await send(env, chat, t(user, "sendName"));
    return;
  }
  if (action === "reconcile") {
    await reconcile(env, user, chat);
    return;
  }
  if (action === "language") {
    requireOwner(user);
    await say(
      env,
      user,
      chat,
      t(user, "defaultLanguage"),
      [
        [
          b("English", "setting:default_locale:en"),
          b("فارسی", "setting:default_locale:fa"),
        ],
        [b(t(user, "back"), "settings")],
      ],
      messageId,
    );
    return;
  }
  if (action === "autodelete") {
    requireOwner(user);
    await say(
      env,
      user,
      chat,
      t(user, "autoDeletePrompt"),
      [
        [30, 60, 120, 300, 600, 0].map((n) =>
          b(n ? `${n}s` : t(user, "off"), `setting:delete_after_seconds:${n}`),
        ),
        [b(t(user, "back"), "settings")],
      ],
      messageId,
    );
    return;
  }
  if (action === "pinpolicy") {
    requireOwner(user);
    await say(
      env,
      user,
      chat,
      t(user, "pinPolicy"),
      [
        [
          ...["OFF", "DOWNLOADS", "SENSITIVE_VAULTS", "ALWAYS"].map((v) =>
            b(policyName(user, v), `setting:pin_policy:${v}`),
          ),
        ],
        [b(t(user, "back"), "settings")],
      ],
      messageId,
    );
    return;
  }
  if (action === "pinsession") {
    requireOwner(user);
    await say(
      env,
      user,
      chat,
      t(user, "pinSessionPrompt"),
      [
        [300, 600, 900].map((n) =>
          b(`${n / 60} min`, `setting:pin_session_seconds:${n}`),
        ),
        [b(t(user, "back"), "settings")],
      ],
      messageId,
    );
    return;
  }
  if (action === "inviteexpiry") {
    requireOwner(user);
    await say(
      env,
      user,
      chat,
      t(user, "inviteExpiryPrompt"),
      [
        [24, 48, 168].map((n) =>
          b(`${n}h`, `setting:invite_expiry_hours:${n}`),
        ),
        [b(t(user, "back"), "settings")],
      ],
      messageId,
    );
    return;
  }
  if (action === "toggleincoming" || action === "toggleprotect") {
    requireOwner(user);
    const key =
      action === "toggleincoming" ? "delete_incoming" : "protect_content";
    await setSetting(db, key, yes(await setting(db, key)) ? "false" : "true");
    await audit(db, user.id, "SETTINGS_CHANGED", null, { key });
    await settings(env, user, chat, messageId);
    return;
  }
  if (action === "setting" && a && bv) {
    requireOwner(user);
    const allowed: Record<string, string[]> = {
      default_locale: ["en", "fa"],
      delete_after_seconds: ["0", "30", "60", "120", "300", "600"],
      pin_policy: ["OFF", "DOWNLOADS", "SENSITIVE_VAULTS", "ALWAYS"],
      pin_session_seconds: ["300", "600", "900"],
      invite_expiry_hours: ["24", "48", "168"],
    };
    if (!allowed[a]?.includes(bv)) throw new Forbidden();
    await setSetting(db, a, bv);
    await audit(db, user.id, "SETTINGS_CHANGED", null, { key: a });
    if (a === "default_locale") {
      const persisted = await one<{ locale: string | null }>(
        db,
        "SELECT locale FROM users WHERE id=?",
        user.id,
      );
      if (!persisted?.locale) user = { ...user, locale: bv as "en" | "fa" };
    }
    await settings(env, user, chat, messageId);
    return;
  }
  throw new Forbidden();
}
async function handleUpdateInner(env: Env, update: Update): Promise<void> {
  const msg = update.message,
    cb = update.callback_query;
  const source = msg ?? cb?.message;
  if (!source || source.chat.type !== "private") return;
  const from = msg?.from ?? cb?.from;
  if (!from) return;
  const chat = String(source.chat.id);
  let user = await userByTelegram(env.VAULTGRAM_DB, String(from.id));
  if (user) await clearTransient(env, user, chat);
  if (!user) {
    if (msg?.text?.startsWith("/claim ")) {
      const secret = msg.text.slice(7).trim();
      try {
        await deleteMessage(env, { chat_id: chat, message_id: msg.message_id });
      } catch {
        /* best effort */
      }
      if (
        env.BOOTSTRAP_SECRET.length < 32 ||
        !equal(secret, env.BOOTSTRAP_SECRET)
      ) {
        await send(env, chat, t(user, "invalidClaim"));
        return;
      }
      user = await bootstrap(env, String(from.id), from.first_name);
      if (user) {
        user = { ...user, locale: (await locale(env)) as "en" | "fa" };
        await home(env, user, chat);
        return;
      }
    }
    if (msg?.text?.startsWith("/start ")) {
      user = await acceptInvite(env, msg, msg.text.slice(7).trim());
      if (user) {
        await send(env, chat, t(user, "joined"));
        await setState(env, user, "pin_new", { after: "home" });
        await send(env, chat, t(user, "newPinPrompt"));
        return;
      }
    }
    const closed = await one<{ bootstrap_closed: number }>(
      env.VAULTGRAM_DB,
      "SELECT bootstrap_closed FROM workspaces WHERE id='default'",
    );
    await send(
      env,
      chat,
      closed?.bootstrap_closed ? t(user, "privateBot") : t(null, "bootstrap"),
    );
    return;
  }
  if (!user.locale)
    user = { ...user, locale: (await locale(env)) as "en" | "fa" };
  if (user.disabled || user.removed) {
    await send(env, chat, t(user, "denied"));
    return;
  }
  if (user.role === "MEMBER" && !user.pin_hash) {
    const current = await session(env, user);
    if (current?.state !== "pin_new" || current.expires_at <= now())
      await setState(env, user, "pin_new", { after: "home" });
    if (cb) {
      await send(env, chat, t(user, "newPinPrompt"));
      await answer(env, cb.id);
      return;
    }
    if (msg?.text?.startsWith("/")) {
      await send(env, chat, t(user, "newPinPrompt"));
      return;
    }
    if (msg) {
      const pending = await session(env, user);
      if (pending) await input(env, user, msg, pending);
    }
    return;
  }
  if (cb) {
    try {
      await dispatch(env, user, chat, cb.data ?? "", cb.message?.message_id);
      await answer(env, cb.id);
    } catch (e) {
      await answer(
        env,
        cb.id,
        e instanceof Forbidden ? t(user, "denied") : t(user, "error"),
      );
      if (e instanceof Forbidden) return;
      throw e;
    }
    return;
  }
  if (!msg) return;
  if (msg.text === "/start" || msg.text === "/menu" || msg.text === "/cancel") {
    await clearState(env, user);
    await home(env, user, chat);
    return;
  }
  const s = await session(env, user);
  if (s?.state && s.expires_at > now()) {
    await input(env, user, msg, s);
    return;
  }
  await home(env, user, chat);
}
export async function handleUpdate(env: Env, update: Update): Promise<void> {
  try {
    await handleUpdateInner(env, update);
  } finally {
    const msg = update.message;
    if (msg?.text && msg.chat.type === "private") {
      try {
        await deleteMessage(env, { chat_id: String(msg.chat.id), message_id: msg.message_id });
      } catch {
        try {
          await scheduleDelete(env, { chat_id: String(msg.chat.id), message_id: msg.message_id }, 30);
        } catch {
          console.error(JSON.stringify({ event: "incoming_text_deletion_schedule_failed" }));
        }
      }
    }
  }
}
