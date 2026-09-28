import process from "node:process";

function hiddenToken() {
  if (!process.stdin.isTTY) throw new Error("Run this command in an interactive terminal.");
  process.stdout.write("Telegram bot token (hidden): ");
  return new Promise((resolve, reject) => {
    let token = "";
    const wasRaw = process.stdin.isRaw;
    process.stdin.setRawMode(true);
    process.stdin.resume();
    const finish = (error) => {
      process.stdin.off("data", onData);
      process.stdin.setRawMode(wasRaw);
      process.stdin.pause();
      process.stdout.write("\n");
      if (error) reject(error);
      else resolve(token.trim());
    };
    const onData = (chunk) => {
      for (const char of chunk.toString("utf8")) {
        if (char === "\r" || char === "\n") return finish();
        if (char === "\u0003") return finish(new Error("Cancelled."));
        if (char === "\u007f" || char === "\b") token = token.slice(0, -1);
        else token += char;
      }
    };
    process.stdin.on("data", onData);
  });
}

const token = process.env.TELEGRAM_BOT_TOKEN || (await hiddenToken());
if (!token) throw new Error("A bot token is required.");

async function call(method, body = {}) {
  const response = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok || !data.ok)
    throw new Error(`Telegram ${method} failed (HTTP ${response.status}).`);
  return data.result;
}

await call("setMyCommands", {
  commands: [
    { command: "menu", description: "Open the main menu" },
    { command: "cancel", description: "Cancel the current action" },
  ],
});
await call("setMyCommands", {
  commands: [
    { command: "menu", description: "بازکردن منوی اصلی" },
    { command: "cancel", description: "لغو کار فعلی" },
  ],
  language_code: "fa",
});
await call("setChatMenuButton", { menu_button: { type: "commands" } });

const [commands, button] = await Promise.all([
  call("getMyCommands"),
  call("getChatMenuButton"),
]);
if (button.type !== "commands" || !commands.some(({ command }) => command === "menu"))
  throw new Error("Telegram did not retain the command menu.");
console.log("Telegram command menu configured and verified.");
