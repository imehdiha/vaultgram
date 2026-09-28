import type { Env, Update, DeleteJob } from "./types";
import { equal, now } from "./security/crypto";
import { run } from "./db/repo";
import { handleUpdate } from "./app/bot";
import { deleteMessage } from "./telegram/api";

function log(event: string, requestId: string, error: unknown): void {
  console.error(
    JSON.stringify({
      event,
      requestId,
      error: error instanceof Error ? error.name : "UNKNOWN",
    }),
  );
}
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const requestId = crypto.randomUUID();
    try {
      if (url.pathname === "/health" && request.method === "GET")
        return new Response("ok", { headers: { "cache-control": "no-store" } });
      if (url.pathname === "/telegram/webhook" && request.method === "POST") {
        const supplied =
          request.headers.get("X-Telegram-Bot-Api-Secret-Token") ?? "";
        if (!supplied || !env.TELEGRAM_WEBHOOK_SECRET || !equal(supplied, env.TELEGRAM_WEBHOOK_SECRET))
          return new Response("Forbidden", { status: 403 });
        const update = await request.json<Update>();
        if (!Number.isSafeInteger(update.update_id))
          return new Response("Bad update", { status: 400 });
        const inserted = await run(
          env.VAULTGRAM_DB,
          "INSERT OR IGNORE INTO processed_telegram_updates(update_id,created_at) VALUES(?,?)",
          update.update_id,
          now(),
        );
        if (inserted.meta.changes === 0) return new Response("ok");
        try {
          await handleUpdate(env, update);
          return new Response("ok");
        } catch (e) {
          log("update_failed", requestId, e);
          await run(
            env.VAULTGRAM_DB,
            "DELETE FROM processed_telegram_updates WHERE update_id=?",
            update.update_id,
          );
          return new Response("Retry later", { status: 503 });
        }
      }
      return new Response("Not found", { status: 404 });
    } catch (e) {
      log("request_failed", requestId, e);
      return new Response("Internal error", { status: 500 });
    }
  },
  async queue(batch: MessageBatch<DeleteJob>, env: Env): Promise<void> {
    for (const message of batch.messages) {
      try {
        const { chat_id, message_id } = message.body;
        if (!/^\d+$/.test(chat_id) || !Number.isSafeInteger(message_id)) {
          message.ack();
          continue;
        }
        await deleteMessage(env, { chat_id, message_id });
        message.ack();
      } catch (e) {
        const messageText = e instanceof Error ? e.message : "";
        if (
          messageText.includes("message to delete not found") ||
          messageText.includes("message can't be deleted")
        ) {
          message.ack();
          continue;
        }
        message.retry();
      }
    }
  },
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    const db = env.VAULTGRAM_DB;
    await run(
      db,
      "DELETE FROM processed_telegram_updates WHERE created_at<?",
      now() - 30 * 86400,
    );
    await run(
      db,
      "DELETE FROM upload_receipts WHERE created_at<?",
      now() - 30 * 86400,
    );
    await run(
      db,
      "DELETE FROM pending_actions WHERE expires_at<?",
      now() - 86400,
    );
    await run(
      db,
      "DELETE FROM invite_permissions WHERE invite_id IN (SELECT id FROM invites WHERE (used_at IS NOT NULL OR revoked_at IS NOT NULL OR expires_at<?) AND created_at<?)",
      now() - 30 * 86400,
      now() - 30 * 86400,
    );
    await run(
      db,
      "DELETE FROM invites WHERE (used_at IS NOT NULL OR revoked_at IS NOT NULL OR expires_at<?) AND created_at<?",
      now() - 30 * 86400,
      now() - 30 * 86400,
    );
  },
} satisfies ExportedHandler<Env, DeleteJob>;
