import { describe, it, expect, vi } from "vitest";
import { env as bindings } from "cloudflare:workers";
import type { Env, User } from "../src/types";
import {
  safeName,
  sha256,
  equal,
  randomToken,
} from "../src/security/crypto";
import {
  bootstrap,
  requireLevel,
  visibleVaults,
  createPending,
  consumePending,
  Forbidden,
  run,
  one,
} from "../src/db/repo";
import { setPin, verifyPin, pinRequired } from "../src/security/pin";
import { encryptSecureValue, decryptSecureValue, encryptFileStream, decryptFileStream } from "../src/security/vault-crypto";
import { createSecureValue, getSecureValue, updateSecureValue } from "../src/secure-values/service";
import { readDocument } from "../src/documents/service";
import type { Document, SecureValue } from "../src/types";
import { acceptInvite, executePending, handleUpdate } from "../src/app/bot";
import worker from "../src/index";
import { assertKeyboard, sendDocumentStream, sendProtectedText, scheduleDelete } from "../src/telegram/api";

const key = randomToken(32);
const testEnv = () =>
  ({
    ...bindings,
    TELEGRAM_BOT_TOKEN: "test",
    TELEGRAM_WEBHOOK_SECRET: "test",
    BOOTSTRAP_SECRET: randomToken(),
    VAULT_ENCRYPTION_KEY: key,
    PIN_PEPPER: randomToken(),
  }) as Env;
describe("security and D1 integration", () => {
  it("encrypts secure values with record binding and rejects tampering", async () => {
    const e=testEnv(),vaultId=crypto.randomUUID(),valueId=crypto.randomUUID();
    const a=await encryptSecureValue(e,vaultId,valueId,"secret");
    const b=await encryptSecureValue(e,vaultId,valueId,"secret");
    expect(a.ciphertext).not.toBe(b.ciphertext);
    const row={...a,id:valueId,vault_id:vaultId} as SecureValue;
    expect(await decryptSecureValue(e,row)).toBe("secret");
    await expect(decryptSecureValue(e,{...row,vault_id:crypto.randomUUID()})).rejects.toThrow();
    await expect(decryptSecureValue(e,{...row,ciphertext:a.ciphertext.slice(0,-2)+"AA"})).rejects.toThrow();
  });
  it("streams multi-chunk encrypted files and rejects swapped metadata", async () => {
    const e=testEnv(),vaultId=crypto.randomUUID(),documentId=crypto.randomUUID();
    const storageKey=`documents/${crypto.randomUUID()}`;
    const plain=new Uint8Array(300_000);
    crypto.getRandomValues(plain.subarray(0, 65_536));
    const sealed=await encryptFileStream(e,vaultId,documentId,storageKey,plain.byteLength,new Blob([plain]).stream());
    const ciphertext=await new Response(sealed.stream).arrayBuffer();
    expect(ciphertext.byteLength).toBe(plain.byteLength+32);
    expect(new Uint8Array(ciphertext).slice(0,32)).not.toEqual(plain.slice(0,32));
    const doc={id:documentId,vault_id:vaultId,storage_key:storageKey,size_bytes:plain.byteLength,...sealed.metadata} as Document;
    const restored=await decryptFileStream(e,doc,new Blob([ciphertext]).stream());
    expect(new Uint8Array(await new Response(restored).arrayBuffer())).toEqual(plain);
    const swapped=await decryptFileStream(e,{...doc,id:crypto.randomUUID()},new Blob([ciphertext]).stream());
    await expect(new Response(swapped).arrayBuffer()).rejects.toThrow();
  });
  it("protects Secure Value delivery and queues only Telegram deletion identifiers", async () => {
    const e=testEnv();
    let body: Record<string,unknown>|null=null;
    vi.stubGlobal("fetch",vi.fn(async (_url:RequestInfo|URL,init?:RequestInit)=>{
      body=JSON.parse(String(init?.body)) as Record<string,unknown>;
      return Response.json({ok:true,result:{message_id:123,chat:{id:10001,type:"private"}}});
    }));
    const message=await sendProtectedText(e,"10001","private-example",true);
    expect(body).toMatchObject({protect_content:true,text:"private-example"});
    const sent:unknown[]=[];
    const queueEnv={...e,DELETE_QUEUE:{send:async(job:unknown,opts:unknown)=>{sent.push({job,opts})}}} as unknown as Env;
    await scheduleDelete(queueEnv,{chat_id:"10001",message_id:message.message_id},120);
    expect(sent).toEqual([{job:{chat_id:"10001",message_id:123},opts:{delaySeconds:120}}]);
    vi.unstubAllGlobals();
  });
  it("rejects unsafe paths and supports constant-time style comparisons", () => {
    expect(safeName("../passport.pdf")).toBe("_passport.pdf");
    expect(safeName("a/b\\c")).toBe("a_b_c");
    expect(() => safeName("..")).toThrow();
    expect(equal("abc", "abc")).toBe(true);
    expect(equal("abc", "abx")).toBe(false);
  });
  it("keeps Telegram callbacks within the Bot API limit", () => {
    assertKeyboard([
      [{ text: "Grant", callback_data: `grant:${crypto.randomUUID()}:MANAGE` }],
    ]);
    expect(() =>
      assertKeyboard([
        [
          {
            text: "Too long",
            callback_data: `grant:${crypto.randomUUID()}:${crypto.randomUUID()}:VIEW`,
          },
        ],
      ]),
    ).toThrow();
  });
  it("streams a bounded multipart document to Telegram", async () => {
    const e = testEnv();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("abc"));
        controller.close();
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
        expect(new Headers(init?.headers).get("Content-Type")).toContain(
          "multipart/form-data; boundary=",
        );
        const body = await new Response(init?.body).text();
        expect(body).toContain('name="document"; filename="doc.pdf"');
        expect(body).toContain("\r\n\r\nabc\r\n");
        expect(body).toContain('name="protect_content"\r\n\r\ntrue');
        return Response.json({
          ok: true,
          result: { message_id: 99, chat: { id: 10001, type: "private" } },
        });
      }),
    );
    expect(
      (
        await sendDocumentStream(
          e,
          "10001",
          stream,
          "doc.pdf",
          "Title",
          true,
          3,
        )
      ).message_id,
    ).toBe(99);
    vi.unstubAllGlobals();
  });
  it("boots exactly one owner and enforces explicit vault ACL", async () => {
    const e = testEnv();
    const owner = await bootstrap(e, "10001", "Owner");
    expect(owner?.role).toBe("OWNER");
    expect(await bootstrap(e, "10002", "Other")).toBeNull();
    await expect(
      run(
        e.VAULTGRAM_DB,
        "INSERT INTO users(id,telegram_id,display_name,role,created_at) VALUES(?,?,?,'OWNER',0)",
        crypto.randomUUID(),
        "10002",
        "Other",
      ),
    ).rejects.toThrow();
    const memberId = crypto.randomUUID(),
      vaultId = crypto.randomUUID();
    await run(
      e.VAULTGRAM_DB,
      "INSERT INTO users(id,telegram_id,display_name,role,created_at) VALUES(?,?,?,'MEMBER',0)",
      memberId,
      "10003",
      "Member",
    );
    await run(
      e.VAULTGRAM_DB,
      "INSERT INTO vaults(id,name,created_at) VALUES(?,?,0)",
      vaultId,
      "Secret",
    );
    const member = await one<User>(
      e.VAULTGRAM_DB,
      "SELECT * FROM users WHERE id=?",
      memberId,
    );
    expect(member).not.toBeNull();
    await expect(
      requireLevel(e.VAULTGRAM_DB, member!, vaultId, "VIEW"),
    ).rejects.toBeInstanceOf(Forbidden);
    expect(await visibleVaults(e.VAULTGRAM_DB, member!)).toHaveLength(0);
    await run(
      e.VAULTGRAM_DB,
      "INSERT INTO vault_permissions(user_id,vault_id,level) VALUES(?,?,'VIEW')",
      memberId,
      vaultId,
    );
    await requireLevel(e.VAULTGRAM_DB, member!, vaultId, "VIEW");
    await expect(
      requireLevel(e.VAULTGRAM_DB, member!, vaultId, "EDIT"),
    ).rejects.toBeInstanceOf(Forbidden);
    expect(await visibleVaults(e.VAULTGRAM_DB, member!)).toHaveLength(1);
    await run(
      e.VAULTGRAM_DB,
      "DELETE FROM vault_permissions WHERE user_id=? AND vault_id=?",
      memberId,
      vaultId,
    );
    expect(await visibleVaults(e.VAULTGRAM_DB, member!)).toHaveLength(0);
  });
  it("consumes confirmation nonce only once", async () => {
    const e = testEnv();
    const u = await one<User>(
      e.VAULTGRAM_DB,
      "SELECT * FROM users WHERE role='OWNER'",
    );
    const pid = await createPending(
      e.VAULTGRAM_DB,
      u!.id,
      "delete",
      { id: "target" },
      60,
    );
    expect(
      await consumePending<{ id: string }>(
        e.VAULTGRAM_DB,
        pid,
        u!.id,
        "delete",
      ),
    ).toEqual({ id: "target" });
    await expect(
      consumePending(e.VAULTGRAM_DB, pid, u!.id, "delete"),
    ).rejects.toBeInstanceOf(Forbidden);
  });
  it("consumes an invite once and assigns only selected vault permission", async () => {
    const e = testEnv();
    const owner = (await one<User>(
      e.VAULTGRAM_DB,
      "SELECT * FROM users WHERE role='OWNER'",
    )) ?? (await bootstrap(e, "10001", "Owner"))!;
    const token = randomToken(),
      inviteId = crypto.randomUUID(),
      vaultId = crypto.randomUUID();
    await run(
      e.VAULTGRAM_DB,
      "INSERT INTO vaults(id,name,created_at) VALUES(?,?,0)",
      vaultId,
      "Invite vault",
    );
    await run(
      e.VAULTGRAM_DB,
      "INSERT INTO invites(id,token_hash,expires_at,created_by,created_at) VALUES(?,?,?,?,0)",
      inviteId,
      await sha256(token),
      Math.floor(Date.now() / 1000) + 3600,
      owner.id,
    );
    await run(
      e.VAULTGRAM_DB,
      "INSERT INTO invite_permissions(invite_id,vault_id,level) VALUES(?,?,'VIEW')",
      inviteId,
      vaultId,
    );
    const msg = {
      message_id: 1,
      chat: { id: 10004, type: "private" },
      from: { id: 10004, first_name: "Joiner", language_code: "fa" },
    };
    const joined = await acceptInvite(e, msg, token);
    expect(joined?.role).toBe("MEMBER");
    expect(joined?.locale).toBe("fa");
    expect(await visibleVaults(e.VAULTGRAM_DB, joined!)).toHaveLength(1);
    expect(
      await acceptInvite(
        e,
        { ...msg, from: { id: 10005, first_name: "Replay" } },
        token,
      ),
    ).toBeNull();
    expect((await one<{ used: number }>(e.VAULTGRAM_DB, "SELECT COUNT(*) AS used FROM invites WHERE id=? AND used_at IS NOT NULL", inviteId))?.used).toBe(1);
  });
  it("asks a newly invited member for a PIN before showing the menu and keeps Persian", async () => {
    const e = testEnv();
    const owner = (await one<User>(e.VAULTGRAM_DB, "SELECT * FROM users WHERE role='OWNER'"))
      ?? (await bootstrap(e, "10001", "Owner"))!;
    const token = randomToken(), inviteId = crypto.randomUUID();
    await run(e.VAULTGRAM_DB,
      "INSERT INTO invites(id,token_hash,expires_at,created_by,created_at) VALUES(?,?,?,?,0)",
      inviteId, await sha256(token), Math.floor(Date.now() / 1000) + 3600, owner.id);
    const sent: Record<string, unknown>[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      const method = String(url).split("/").at(-1);
      if (method === "sendMessage") sent.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return Response.json({ ok: true, result: { message_id: 120, chat: { id: 10014, type: "private" } } });
    }));
    await handleUpdate(e, { update_id: 94001, message: {
      message_id: 30, chat: { id: 10014, type: "private" },
      from: { id: 10014, first_name: "New member", language_code: "fa" },
      text: `/start ${token}`,
    } });
    const member = (await one<User>(e.VAULTGRAM_DB, "SELECT * FROM users WHERE telegram_id='10014'"))!;
    expect(member.locale).toBe("fa");
    expect(member.pin_hash).toBeNull();
    expect((await one<{ state: string }>(e.VAULTGRAM_DB, "SELECT state FROM user_sessions WHERE user_id=?", member.id))?.state).toBe("pin_new");
    expect(sent.map((body) => String(body.text))).toContain("رمز ۶ تا ۱۲ رقمی جدید را بفرستید. پیام حذف می‌شود.");
    expect(sent.some((body) => body.reply_markup !== undefined)).toBe(false);
    await handleUpdate(e, { update_id: 94002, message: {
      message_id: 31, chat: { id: 10014, type: "private" },
      from: { id: 10014, first_name: "New member" }, text: "123456",
    } });
    expect((await one<User>(e.VAULTGRAM_DB, "SELECT * FROM users WHERE id=?", member.id))?.pin_hash).toBeTruthy();
    const homeKeyboard = sent.at(-1)?.reply_markup as { inline_keyboard: { text: string; callback_data: string }[][] };
    expect(homeKeyboard.inline_keyboard.flat()).toContainEqual({ text: "📁 گاوصندوق‌ها", callback_data: "vaults" });
    expect((await one<{ state: string | null }>(e.VAULTGRAM_DB, "SELECT state FROM user_sessions WHERE user_id=?", member.id))?.state).toBeNull();
    vi.unstubAllGlobals();
  });
  it("opens a VIEW document through the PIN prompt and delivers it without a detail menu", async () => {
    const e = testEnv(), db = e.VAULTGRAM_DB;
    const owner = (await one<User>(db, "SELECT * FROM users WHERE role='OWNER'"))
      ?? (await bootstrap(e, "10001", "Owner"))!;
    const memberId = crypto.randomUUID(), vaultId = crypto.randomUUID();
    const categoryId = crypto.randomUUID(), documentId = crypto.randomUUID();
    const storageKey = `documents/${crypto.randomUUID()}`;
    await run(db, "INSERT INTO users(id,telegram_id,display_name,role,locale,created_at) VALUES(?,?,?,'MEMBER','fa',0)", memberId, "10015", "Viewer");
    const member = (await one<User>(db, "SELECT * FROM users WHERE id=?", memberId))!;
    await setPin(e, member, "123456");
    await run(db, "INSERT INTO vaults(id,name,created_at) VALUES(?,?,0)", vaultId, "Viewer vault");
    await run(db, "INSERT INTO vault_permissions(user_id,vault_id,level) VALUES(?,?,'VIEW')", memberId, vaultId);
    await run(db, "INSERT INTO categories(id,vault_id,name,created_at) VALUES(?,?,?,0)", categoryId, vaultId, "Cards");
    const sealed = await encryptFileStream(e, vaultId, documentId, storageKey, 3, new Blob(["abc"]).stream());
    await e.DOCUMENTS.put(storageKey, await new Response(sealed.stream).arrayBuffer());
    await run(db, "INSERT INTO documents(id,vault_id,category_id,title,original_filename,mime_type,size_bytes,storage_key,encryption_version,crypto_iv,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,0,0)",
      documentId, vaultId, categoryId, "National card", "card.txt", "text/plain", 3, storageKey,
      sealed.metadata.encryption_version, sealed.metadata.crypto_iv, owner.id);
    await run(db, "UPDATE settings SET value='DOWNLOADS' WHERE key='pin_policy'");
    const sent: Record<string, unknown>[] = [];
    let documentsSent = 0;
    vi.stubGlobal("fetch", vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      const method = String(url).split("/").at(-1);
      if (method === "sendMessage" || method === "editMessageText")
        sent.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      if (method === "sendDocument") {
        const body = await new Response(init?.body).text();
        expect(body).toContain('filename="card.txt"');
        expect(body).toContain('name="protect_content"\r\n\r\ntrue');
        documentsSent++;
      }
      return Response.json({ ok: true, result: { message_id: 500, chat: { id: 10015, type: "private" } } });
    }));
    const callback = (updateId: number) => handleUpdate(e, { update_id: updateId, callback_query: {
      id: `viewer-${updateId}`, from: { id: 10015, first_name: "Viewer" },
      data: `d:${documentId}`, message: { message_id: 400, chat: { id: 10015, type: "private" } },
    } });
    await callback(95001);
    expect(documentsSent).toBe(0);
    expect(sent.map((body) => body.text)).toContain("رمز عددی خود را وارد کنید.");
    expect(sent.some((body) => String(body.text).includes("National card"))).toBe(false);
    await handleUpdate(e, { update_id: 95002, message: {
      message_id: 401, chat: { id: 10015, type: "private" },
      from: { id: 10015, first_name: "Viewer" }, text: "123456",
    } });
    expect(documentsSent).toBe(1);
    await run(db, "DELETE FROM vault_permissions WHERE user_id=? AND vault_id=?", memberId, vaultId);
    await callback(95003);
    expect(documentsSent).toBe(1);
    await run(db, "UPDATE settings SET value='OFF' WHERE key='pin_policy'");
    vi.unstubAllGlobals();
  });
  it("rechecks access before a confirmed destructive operation", async () => {
    const e = testEnv();
    const owner = (await one<User>(
      e.VAULTGRAM_DB,
      "SELECT * FROM users WHERE role='OWNER'",
    ))!;
    const member = (await one<User>(
      e.VAULTGRAM_DB,
      "SELECT * FROM users WHERE telegram_id='10003'",
    ))!;
    const vaultId = crypto.randomUUID(),
      categoryId = crypto.randomUUID(),
      docId = crypto.randomUUID();
    await run(
      e.VAULTGRAM_DB,
      "INSERT INTO vaults(id,name,created_at) VALUES(?,?,0)",
      vaultId,
      "Review",
    );
    await run(
      e.VAULTGRAM_DB,
      "INSERT INTO categories(id,vault_id,name,created_at) VALUES(?,?,?,0)",
      categoryId,
      vaultId,
      "C",
    );
    await run(
      e.VAULTGRAM_DB,
      "INSERT INTO documents(id,vault_id,category_id,title,original_filename,mime_type,size_bytes,storage_key,encryption_version,crypto_iv,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,0,0)",
      docId,
      vaultId,
      categoryId,
      "D",
      "D.pdf",
      "application/pdf",
      1,
      `documents/${crypto.randomUUID()}`,
      1,
      randomToken(8),
      owner.id,
    );
    await run(
      e.VAULTGRAM_DB,
      "INSERT INTO vault_permissions(user_id,vault_id,level) VALUES(?,?,'MANAGE')",
      member.id,
      vaultId,
    );
    const pending = await createPending(
      e.VAULTGRAM_DB,
      member.id,
      "delete_doc",
      { id: docId },
    );
    await run(
      e.VAULTGRAM_DB,
      "DELETE FROM vault_permissions WHERE user_id=? AND vault_id=?",
      member.id,
      vaultId,
    );
    await expect(
      executePending(e, member, member.telegram_id, pending),
    ).rejects.toBeInstanceOf(Forbidden);
    expect(
      await one(e.VAULTGRAM_DB, "SELECT id FROM documents WHERE id=?", docId),
    ).not.toBeNull();
  });
  it("rate limits PIN attempts and creates unlock session", async () => {
    const e = testEnv();
    const u = (await one<User>(
      e.VAULTGRAM_DB,
      "SELECT * FROM users WHERE role='OWNER'",
    ))!;
    await setPin(e, u, "123456");
    let current = (await one<User>(
      e.VAULTGRAM_DB,
      "SELECT * FROM users WHERE id=?",
      u.id,
    ))!;
    for (let i = 0; i < 5; i++) {
      expect(await verifyPin(e, current, "999999")).toBe(false);
      current = (await one<User>(
        e.VAULTGRAM_DB,
        "SELECT * FROM users WHERE id=?",
        u.id,
      ))!;
    }
    expect(current.pin_locked_until).toBeGreaterThan(0);
    expect(await verifyPin(e, current, "123456")).toBe(false);
    await run(
      e.VAULTGRAM_DB,
      "UPDATE users SET pin_locked_until=0 WHERE id=?",
      u.id,
    );
    current = (await one<User>(
      e.VAULTGRAM_DB,
      "SELECT * FROM users WHERE id=?",
      u.id,
    ))!;
    expect(await verifyPin(e, current, "123456")).toBe(true);
    await run(
      e.VAULTGRAM_DB,
      "UPDATE settings SET value='ALWAYS' WHERE key='pin_policy'",
    );
    expect(
      await pinRequired(
        e,
        current,
        { id: "v", name: "v", requires_pin: 0, archived_at: null },
        "download",
      ),
    ).toBe(false);
  });
  it("keeps secure values encrypted and enforces vault access on reveal", async () => {
    const e=testEnv(), db=e.VAULTGRAM_DB;
    const owner=(await one<User>(db,"SELECT * FROM users WHERE role='OWNER'"))!;
    const member=(await one<User>(db,"SELECT * FROM users WHERE telegram_id='10003'"))!;
    const vaultId=crypto.randomUUID();
    await run(db,"INSERT INTO vaults(id,name,created_at) VALUES(?,?,0)",vaultId,"Secrets");
    await run(db,"UPDATE settings SET value='OFF' WHERE key='pin_policy'");
    const valueId=await createSecureValue(e,owner,vaultId,"Bank password","private-example");
    const row=(await one<SecureValue>(db,"SELECT * FROM secure_values WHERE id=?",valueId))!;
    expect(row.ciphertext).not.toContain("private-example");
    await expect(getSecureValue(e,member,valueId)).rejects.toBeInstanceOf(Forbidden);
    await run(db,"INSERT INTO vault_permissions(user_id,vault_id,level) VALUES(?,?,'VIEW')",member.id,vaultId);
    expect((await getSecureValue(e,member,valueId)).value).toBe("private-example");
    await expect(updateSecureValue(e,member,valueId,"changed")).rejects.toBeInstanceOf(Forbidden);
    await run(db,"DELETE FROM vault_permissions WHERE user_id=? AND vault_id=?",member.id,vaultId);
    await expect(getSecureValue(e,member,valueId)).rejects.toBeInstanceOf(Forbidden);
  });
  it("rejects bad webhook secrets and duplicate update IDs", async () => {
    const e = testEnv();
    const update = {
      update_id: 90001,
      message: {
        message_id: 1,
        chat: { id: 10001, type: "private" },
        from: { id: 10001, first_name: "Owner" },
        text: "/menu",
      },
    };
    const body = JSON.stringify(update);
    const bad = await worker.fetch(
      new Request("https://example.test/telegram/webhook", {
        method: "POST",
        headers: { "X-Telegram-Bot-Api-Secret-Token": "bad" },
        body,
      }),
      e,
    );
    expect(bad.status).toBe(403);
    expect((await worker.fetch(new Request("https://example.test/telegram/webhook",{method:"POST",body}),{...e,TELEGRAM_WEBHOOK_SECRET:""})).status).toBe(403);
    const mocked = vi.fn(
      async (input: RequestInfo | URL) => {
        expect(["sendMessage", "deleteMessage"]).toContain(String(input).split("/").at(-1));
        return new Response(
          JSON.stringify({
            ok: true,
            result: { message_id: 2, chat: update.message.chat },
          }),
          { status: 200 },
        );
      },
    );
    vi.stubGlobal("fetch", mocked);
    const req = () =>
      new Request("https://example.test/telegram/webhook", {
        method: "POST",
        headers: {
          "X-Telegram-Bot-Api-Secret-Token": e.TELEGRAM_WEBHOOK_SECRET,
        },
        body,
      });
    expect((await worker.fetch(req(), e)).status).toBe(200);
    expect((await worker.fetch(req(), e)).status).toBe(200);
    expect(mocked.mock.calls.filter(([url])=>String(url).endsWith("/sendMessage"))).toHaveLength(1);
    vi.unstubAllGlobals();
  });
  it("places Owner security in Settings and offers a direct Home route from documents", async () => {
    const e=testEnv();
    const sent:Record<string,unknown>[]=[];
    vi.stubGlobal("fetch",vi.fn(async (url:RequestInfo|URL,init?:RequestInit)=>{
      if(String(url).endsWith("/sendMessage")||String(url).endsWith("/editMessageText")) sent.push(JSON.parse(String(init?.body)) as Record<string,unknown>);
      return Response.json({ok:true,result:{message_id:111,chat:{id:10001,type:"private"}}});
    }));
    await handleUpdate(e,{update_id:91001,message:{message_id:110,chat:{id:10001,type:"private"},from:{id:10001,first_name:"Owner"},text:"/menu"}});
    const home=sent.at(-1) as {reply_markup?:{inline_keyboard?:{callback_data?:string}[][]}};
    expect(home.reply_markup?.inline_keyboard?.flat().map(x=>x.callback_data)).toContain("settings");
    expect(home.reply_markup?.inline_keyboard?.flat().map(x=>x.callback_data)).not.toContain("security");
    await handleUpdate(e,{update_id:91002,callback_query:{id:"q",from:{id:10001,first_name:"Owner"},data:"settings",message:{message_id:111,chat:{id:10001,type:"private"}}}});
    const settings=sent.at(-1) as {reply_markup?:{inline_keyboard?:{callback_data?:string}[][]}};
    expect(settings.reply_markup?.inline_keyboard?.flat().map(x=>x.callback_data)).toContain("security");
    await handleUpdate(e,{update_id:91003,callback_query:{id:"q2",from:{id:10001,first_name:"Owner"},data:"security",message:{message_id:111,chat:{id:10001,type:"private"}}}});
    const security=sent.at(-1) as {reply_markup?:{inline_keyboard?:{callback_data?:string}[][]}};
    expect(security.reply_markup?.inline_keyboard?.flat().map(x=>x.callback_data)).toContain("setpin");
    expect(security.reply_markup?.inline_keyboard?.flat().map(x=>x.callback_data)).toContain("settings");
    expect(security.reply_markup?.inline_keyboard?.flat().some(x=>x.callback_data?.startsWith("userlang"))).toBe(false);
    const owner=(await one<User>(e.VAULTGRAM_DB,"SELECT * FROM users WHERE role='OWNER'"))!;
    const vaultId=crypto.randomUUID(),categoryId=crypto.randomUUID(),documentId=crypto.randomUUID();
    await run(e.VAULTGRAM_DB,"UPDATE settings SET value='OFF' WHERE key='pin_policy'");
    await run(e.VAULTGRAM_DB,"INSERT INTO vaults(id,name,created_at) VALUES(?,?,0)",vaultId,"Navigation");
    await run(e.VAULTGRAM_DB,"INSERT INTO categories(id,vault_id,name,created_at) VALUES(?,?,?,0)",categoryId,vaultId,"Test");
    await run(e.VAULTGRAM_DB,"INSERT INTO documents(id,vault_id,category_id,title,original_filename,mime_type,size_bytes,storage_key,encryption_version,crypto_iv,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,0,0)",documentId,vaultId,categoryId,"Test","test.txt","text/plain",1,`documents/${crypto.randomUUID()}`,1,randomToken(8),owner.id);
    await handleUpdate(e,{update_id:91004,callback_query:{id:"q3",from:{id:10001,first_name:"Owner"},data:`d:${documentId}`,message:{message_id:111,chat:{id:10001,type:"private"}}}});
    const documentMenu=sent.at(-1) as {reply_markup?:{inline_keyboard?:{callback_data?:string}[][]}};
    expect(documentMenu.reply_markup?.inline_keyboard?.flat().map(x=>x.callback_data)).toContain("home");
    vi.unstubAllGlobals();
  });
  it("keeps the Owner menu while sending a forwardable invite link", async () => {
    const e = testEnv();
    const owner = (await one<User>(e.VAULTGRAM_DB, "SELECT * FROM users WHERE role='OWNER'"))
      ?? (await bootstrap(e, "10001", "Owner"))!;
    await run(
      e.VAULTGRAM_DB,
      "INSERT INTO user_sessions(user_id,menu_message_id) VALUES(?,777) ON CONFLICT(user_id) DO UPDATE SET menu_message_id=777",
      owner.id,
    );
    const calls: { method: string; body: Record<string, unknown> }[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      const method = String(url).split("/").at(-1)!;
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      calls.push({ method, body });
      const result = method === "getMe"
        ? { username: "vaultgram_test_bot" }
        : { message_id: 888, chat: { id: 10001, type: "private" } };
      return Response.json({ ok: true, result });
    }));
    await handleUpdate(e, {
      update_id: 93001,
      callback_query: {
        id: "invite-test",
        from: { id: 10001, first_name: "Owner" },
        data: "invite",
        message: { message_id: 777, chat: { id: 10001, type: "private" } },
      },
    });
    const invite = calls.find(({ method }) => method === "sendMessage")!.body;
    const text = String(invite.text);
    const url = text.match(/https:\/\/t\.me\/vaultgram_test_bot\?start=[A-Za-z0-9_-]+/)?.[0];
    expect(url).toBeTruthy();
    expect(invite.entities).toEqual([{ type: "url", offset: text.indexOf(url!), length: url!.length }]);
    expect(invite.reply_markup).toMatchObject({
      inline_keyboard: [
        [{ url }],
        [{ copy_text: { text: url } }],
      ],
    });
    expect(calls.some(({ method, body }) => method === "deleteMessage" && body.message_id === 777)).toBe(false);
    expect((await one<{ menu_message_id: number }>(e.VAULTGRAM_DB, "SELECT menu_message_id FROM user_sessions WHERE user_id=?", owner.id))?.menu_message_id).toBe(777);
    vi.unstubAllGlobals();
  });
  it("removes an answered prompt, the submitted text, and the previous menu", async () => {
    const e=testEnv();
    await run(e.VAULTGRAM_DB,"UPDATE settings SET value='OFF' WHERE key='pin_policy'");
    let nextId=200;
    const sent:number[]=[],deleted:number[]=[];
    vi.stubGlobal("fetch",vi.fn(async (url:RequestInfo|URL,init?:RequestInit)=>{
      const method=String(url).split("/").at(-1);
      const body=JSON.parse(String(init?.body)) as {message_id?:number};
      if(method==="deleteMessage") deleted.push(body.message_id!);
      if(method==="sendMessage") {const id=nextId++;sent.push(id);return Response.json({ok:true,result:{message_id:id,chat:{id:10001,type:"private"}}})}
      return Response.json({ok:true,result:true});
    }));
    await handleUpdate(e,{update_id:92001,message:{message_id:500,chat:{id:10001,type:"private"},from:{id:10001,first_name:"Owner"},text:"/menu"}});
    await handleUpdate(e,{update_id:92002,callback_query:{id:"q",from:{id:10001,first_name:"Owner"},data:"newvault",message:{message_id:sent[0]!,chat:{id:10001,type:"private"}}}});
    await handleUpdate(e,{update_id:92003,message:{message_id:501,chat:{id:10001,type:"private"},from:{id:10001,first_name:"Owner"},text:"Temporary navigation"}});
    expect(sent).toHaveLength(3);
    expect(deleted).toEqual(expect.arrayContaining([500,501,sent[0],sent[1]]));
    expect(deleted).not.toContain(sent[2]);
    vi.unstubAllGlobals();
  });
  it("persists an upload and ignores a retried source message", async () => {
    const e = testEnv(),
      db = e.VAULTGRAM_DB;
    const owner = (await one<User>(
      db,
      "SELECT * FROM users WHERE role='OWNER'",
    ))!;
    const vaultId = crypto.randomUUID(),
      categoryId = crypto.randomUUID();
    await run(db, "UPDATE settings SET value='OFF' WHERE key='pin_policy'");
    await run(
      db,
      "INSERT INTO vaults(id,name,created_at) VALUES(?,?,0)",
      vaultId,
      "Uploads",
    );
    await run(
      db,
      "INSERT INTO categories(id,vault_id,name,created_at) VALUES(?,?,?,0)",
      categoryId,
      vaultId,
      "Files",
    );
    const state = () =>
      run(
        db,
        "INSERT INTO user_sessions(user_id,state,payload,expires_at) VALUES(?,'upload',?,?) ON CONFLICT(user_id) DO UPDATE SET state=excluded.state,payload=excluded.payload,expires_at=excluded.expires_at",
        owner.id,
        JSON.stringify({ categoryId }),
        Math.floor(Date.now() / 1000) + 600,
      );
    await state();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url=String(input);
        if(url.endsWith("/getFile")) return Response.json({ok:true,result:{file_path:"documents/a",file_size:3}});
        if(url.includes("api.telegram.org/file/")) return new Response("abc",{headers:{"content-length":"3"}});
        return Response.json({ok:true,result:{message_id:55,chat:{id:10001,type:"private"}}});
      }),
    );
    const update = {
      update_id: 90100,
      message: {
        message_id: 42,
        chat: { id: 10001, type: "private" },
        from: { id: 10001, first_name: "Owner" },
        document: {
          file_id: "f1",
          file_unique_id: "u1",
          file_size: 3,
          file_name: "document.pdf",
          mime_type: "application/pdf",
        },
      },
    };
    await handleUpdate(e, update);

    expect(
      (
        await one<{ n: number }>(
          db,
          "SELECT COUNT(*) AS n FROM documents WHERE category_id=?",
          categoryId,
        )
      )?.n,
    ).toBe(1);
    expect(
      (
        await one<{ n: number }>(
          db,
          "SELECT COUNT(*) AS n FROM upload_receipts WHERE chat_id=? AND message_id=?",
          owner.telegram_id,
          42,
        )
      )?.n,
    ).toBe(1);
    const stored=(await one<Document>(db,"SELECT * FROM documents WHERE category_id=?",categoryId))!;
    const ciphertext=await e.DOCUMENTS.get(stored.storage_key,"arrayBuffer");
    expect(ciphertext).not.toBeNull();
    expect(new TextDecoder().decode(ciphertext!)).not.toContain("abc");
    const read=await readDocument(e,owner,stored.id);
    expect(await new Response(read.stream).text()).toBe("abc");
    await state();
    await handleUpdate(e, update);
    expect((await one<{n:number}>(db,"SELECT COUNT(*) AS n FROM documents WHERE category_id=?",categoryId))?.n).toBe(1);
    vi.unstubAllGlobals();
  });
  it("resets a member PIN only through a confirmed owner action", async () => {
    const e = testEnv();
    const owner = (await one<User>(
      e.VAULTGRAM_DB,
      "SELECT * FROM users WHERE role='OWNER'",
    ))!;
    const member = (await one<User>(
      e.VAULTGRAM_DB,
      "SELECT * FROM users WHERE telegram_id='10003'",
    ))!;
    await setPin(e, member, "123456");
    await run(
      e.VAULTGRAM_DB,
      "INSERT INTO user_sessions(user_id,pin_unlocked_until) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET pin_unlocked_until=excluded.pin_unlocked_until",
      member.id,
      Math.floor(Date.now() / 1000) + 600,
    );
    const pending = await createPending(e.VAULTGRAM_DB, owner.id, "reset_pin", {
      id: member.id,
    });
    await expect(
      executePending(e, member, member.telegram_id, pending),
    ).rejects.toBeInstanceOf(Forbidden);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({
          ok: true,
          result: { message_id: 76, chat: { id: 10001, type: "private" } },
        }),
      ),
    );
    await executePending(e, owner, owner.telegram_id, pending);
    const after = await one<{
      pin_hash: string | null;
      pin_unlocked_until: number;
    }>(
      e.VAULTGRAM_DB,
      "SELECT u.pin_hash,s.pin_unlocked_until FROM users u JOIN user_sessions s ON s.user_id=u.id WHERE u.id=?",
      member.id,
    );
    expect(after?.pin_hash).toBeNull();
    expect(after?.pin_unlocked_until).toBe(0);
    await expect(
      executePending(e, owner, owner.telegram_id, pending),
    ).rejects.toBeInstanceOf(Forbidden);
    vi.unstubAllGlobals();
  });
  it("acknowledges revoked callbacks without retrying the webhook", async () => {
    const e = testEnv();
    const member = (await one<User>(
      e.VAULTGRAM_DB,
      "SELECT * FROM users WHERE telegram_id='10003'",
    ))!;
    await setPin(e, member, "123456");
    const vaultId = crypto.randomUUID();
    await run(
      e.VAULTGRAM_DB,
      "INSERT INTO vaults(id,name,created_at) VALUES(?,?,0)",
      vaultId,
      "Revoked",
    );
    const telegram = vi.fn(async () =>
      Response.json({ ok: true, result: true }),
    );
    vi.stubGlobal("fetch", telegram);
    await handleUpdate(e, {
      update_id: 90999,
      callback_query: {
        id: "callback",
        from: { id: Number(member.telegram_id), first_name: "Member" },
        data: `v:${vaultId}`,
        message: {
          message_id: 77,
          chat: { id: Number(member.telegram_id), type: "private" },
        },
      },
    });
    expect(telegram).toHaveBeenCalledTimes(1);
    vi.unstubAllGlobals();
  });
});
