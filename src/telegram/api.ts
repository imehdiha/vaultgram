import type { Env, Message, DeleteJob } from "../types";
import { randomToken, safeName } from "../security/crypto";
export type Button = { text: string; callback_data?: string; url?: string };
export type Keyboard = Button[][];
export function assertKeyboard(keyboard?: Keyboard): void {
  if (!keyboard) return;
  for (const row of keyboard)
    for (const button of row)
      if (button.callback_data) {
        const bytes = new TextEncoder().encode(button.callback_data).length;
        if (bytes < 1 || bytes > 64)
          throw new Error("Telegram callback_data exceeds 64 bytes");
      }
}
export async function telegram<T>(
  env: Env,
  method: string,
  body: Record<string, unknown>,
): Promise<T> {
  const res = await fetch(
    `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/${method}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    },
  );
  const data = await res.json<{
    ok: boolean;
    result: T;
    description?: string;
  }>();
  if (!res.ok || !data.ok)
    throw new Error(
      `Telegram ${method} HTTP ${res.status}: ${data.description ?? "failed"}`,
    );
  return data.result;
}
export async function send(
  env: Env,
  chat: string,
  text: string,
  keyboard?: Keyboard,
): Promise<Message> {
  assertKeyboard(keyboard);
  return telegram<Message>(env, "sendMessage", {
    chat_id: chat,
    text,
    reply_markup: keyboard ? { inline_keyboard: keyboard } : undefined,
    disable_web_page_preview: true,
  });
}
export async function sendInvite(
  env: Env,
  chat: string,
  text: string,
  url: string,
  openLabel: string,
  copyLabel: string,
): Promise<Message> {
  const offset = text.indexOf(url);
  if (offset < 0) throw new Error("Invite URL is missing from message");
  return telegram<Message>(env, "sendMessage", {
    chat_id: chat,
    text,
    entities: [{ type: "url", offset, length: url.length }],
    reply_markup: {
      inline_keyboard: [
        [{ text: openLabel, url }],
        [{ text: copyLabel, copy_text: { text: url } }],
      ],
    },
    disable_web_page_preview: true,
  });
}
export async function sendProtectedText(
  env: Env,
  chat: string,
  text: string,
  protect: boolean,
): Promise<Message> {
  return telegram<Message>(env, "sendMessage", {
    chat_id: chat,
    text,
    protect_content: protect,
    disable_web_page_preview: true,
  });
}
export async function edit(
  env: Env,
  chat: string,
  messageId: number,
  text: string,
  keyboard?: Keyboard,
): Promise<void> {
  assertKeyboard(keyboard);
  try {
    await telegram(env, "editMessageText", {
      chat_id: chat,
      message_id: messageId,
      text,
      reply_markup: keyboard ? { inline_keyboard: keyboard } : undefined,
      disable_web_page_preview: true,
    });
  } catch (e) {
    if (!String(e).includes("message is not modified")) throw e;
  }
}
export async function answer(
  env: Env,
  id: string,
  text?: string,
): Promise<void> {
  await telegram(env, "answerCallbackQuery", { callback_query_id: id, text });
}
export async function deleteMessage(env: Env, job: DeleteJob): Promise<void> {
  await telegram(env, "deleteMessage", {
    chat_id: job.chat_id,
    message_id: job.message_id,
  });
}
export async function scheduleDelete(
  env: Env,
  job: DeleteJob,
  seconds: number,
): Promise<void> {
  if (seconds > 0) await env.DELETE_QUEUE.send(job, { delaySeconds: seconds });
}
export async function file(
  env: Env,
  fileId: string,
): Promise<{ file_path: string; file_size?: number }> {
  return telegram(env, "getFile", { file_id: fileId });
}
export async function sendDocumentStream(
  env: Env,
  chat: string,
  stream: ReadableStream<Uint8Array>,
  filename: string,
  caption: string,
  protect: boolean,
  size: number,
): Promise<Message> {
  if (!Number.isSafeInteger(size) || size < 0 || size > 50_000_000)
    throw new Error("Telegram send size limit exceeded");
  const boundary = `vaultgram-${randomToken(18)}`;
  const quoted = safeName(filename).replace(/["\\]/g, "_");
  const field = (name: string, value: string) =>
    `--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`;
  const encoder = new TextEncoder();
  const prefix = encoder.encode(
    field("chat_id", chat) +
      field("caption", caption) +
      field("protect_content", String(protect)) +
      `--${boundary}\r\nContent-Disposition: form-data; name="document"; filename="${quoted}"\r\nContent-Type: application/octet-stream\r\n\r\n`,
  );
  const suffix = encoder.encode(`\r\n--${boundary}--\r\n`);
  const reader = stream.getReader();
  let stage = 0;
  const multipart = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (stage === 0) {
        stage = 1;
        controller.enqueue(prefix);
        return;
      }
      if (stage === 1) {
        const next = await reader.read();
        if (!next.done) {
          controller.enqueue(next.value);
          return;
        }
        stage = 2;
      }
      if (stage === 2) {
        stage = 3;
        controller.enqueue(suffix);
        return;
      }
      controller.close();
    },
    cancel(reason) {
      return reader.cancel(reason);
    },
  });
  const fixed = new FixedLengthStream(
    prefix.byteLength + size + suffix.byteLength,
  );
  const [res] = await Promise.all([
    fetch(
      `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendDocument`,
      {
        method: "POST",
        headers: {
          "Content-Type": `multipart/form-data; boundary=${boundary}`,
        },
        body: fixed.readable,
      },
    ),
    multipart.pipeTo(fixed.writable),
  ]);
  const data = await res.json<{ ok: boolean; result: Message }>();
  if (!res.ok || !data.ok)
    throw new Error(`Telegram sendDocument HTTP ${res.status}`);
  return data.result;
}
