import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";
import process from "node:process";
import { setTimeout as wait } from "node:timers/promises";
import { assertFreshWorker, deploymentUrl, installationName, privateWranglerConfig } from "./install-core.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const localDir = join(root, ".vaultgram");
const localConfig = join(localDir, "wrangler.jsonc");
const statePath = join(localDir, "install-state.json");
const secretNames = [
  "TELEGRAM_BOT_TOKEN",
  "TELEGRAM_WEBHOOK_SECRET",
  "BOOTSTRAP_SECRET",
  "VAULT_ENCRYPTION_KEY",
  "PIN_PEPPER",
];

function fail(message) {
  throw new Error(message);
}

async function question(prompt) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try { return (await rl.question(prompt)).trim(); }
  finally { rl.close(); }
}

async function hiddenToken() {
  if (!process.stdin.isTTY || !process.stdin.setRawMode)
    fail("Run setup in an interactive terminal to enter the bot token securely.");
  process.stdout.write("BotFather token (hidden): ");
  return new Promise((resolveToken, rejectToken) => {
    let value = "";
    const wasRaw = process.stdin.isRaw;
    process.stdin.setRawMode(true);
    process.stdin.resume();
    const finish = (error) => {
      process.stdin.off("data", onData);
      process.stdin.setRawMode(wasRaw);
      process.stdin.pause();
      process.stdout.write("\n");
      if (error) rejectToken(error);
      else resolveToken(value.trim());
    };
    const onData = (chunk) => {
      for (const char of chunk.toString("utf8")) {
        if (char === "\r" || char === "\n") return finish();
        if (char === "\u0003") return finish(new Error("Setup cancelled."));
        if (char === "\u007f" || char === "\b") value = value.slice(0, -1);
        else value += char;
      }
    };
    process.stdin.on("data", onData);
  });
}

function command(bin, args, { input, env = {}, show = false } = {}) {
  return new Promise((resolveCommand, rejectCommand) => {
    const child = spawn(bin, args, {
      cwd: root,
      env: { ...process.env, ...env },
      stdio: [input === undefined ? "inherit" : "pipe", "pipe", "pipe"],
    });
    let stdout = "", stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout = (stdout + chunk.toString("utf8")).slice(-1_000_000);
      if (show) process.stdout.write(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr = (stderr + chunk.toString("utf8")).slice(-1_000_000);
      if (show) process.stderr.write(chunk);
    });
    child.on("error", rejectCommand);
    child.on("close", (code) => resolveCommand({ code, stdout, stderr, output: stdout + stderr }));
    if (input !== undefined) child.stdin.end(`${input}\n`);
  });
}

const wranglerBin = join(root, "node_modules", ".bin", process.platform === "win32" ? "wrangler.cmd" : "wrangler");
async function wrangler(args, options) {
  if (!existsSync(wranglerBin)) fail("Wrangler is missing. Run npm ci and retry.");
  return command(wranglerBin, args, options);
}
async function checkedWrangler(args, options) {
  const result = await wrangler(args, options);
  if (result.code !== 0) fail(`Wrangler failed: ${args.slice(0, 2).join(" ")}. Review its error above and rerun setup.`);
  return result.stdout;
}

async function telegram(token, method, body = {}) {
  const response = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok || !data.ok)
    fail(`Telegram ${method} failed (HTTP ${response.status}). Check the token or service status.`);
  return data.result;
}

async function savePrivate(path, value) {
  const temp = `${path}.tmp-${randomBytes(6).toString("hex")}`;
  await writeFile(temp, value, { mode: 0o600, flag: "wx" });
  await rename(temp, path);
}

async function saveState(state) {
  await savePrivate(statePath, `${JSON.stringify(state, null, 2)}\n`);
}

function validateRecovery(recovery) {
  for (const name of secretNames)
    if (typeof recovery[name] !== "string" || !recovery[name])
      fail("Recovery file is incomplete; no secrets were changed.");
  return recovery;
}

async function ensureHealthy(url) {
  for (let attempt = 0; attempt < 10; attempt++) {
    try {
      const response = await fetch(`${url}/health`);
      if (response.ok && (await response.text()).trim() === "ok") return;
    } catch { /* deployment may still be propagating */ }
    await wait(2000);
  }
  fail("Worker health check did not return ok. The webhook was not changed; rerun setup after checking Cloudflare.");
}

async function run() {
  if (Number(process.versions.node.split(".")[0]) < 20)
    fail("Node.js 20 or newer is required.");
  if (process.argv.includes("--dry-run")) {
    console.log("Fresh install: Cloudflare login → existing Worker check → bot check → one private recovery file → deploy → five Worker Secrets → D1 migrations → health → Telegram commands and webhook.");
    console.log("This mode changed nothing.");
    return;
  }
  if (!process.stdin.isTTY) fail("Run npm run setup in your own interactive terminal.");
  console.log("Vaultgram fresh-install wizard. Existing installations are protected and cannot be reset here.");
  if (!existsSync(wranglerBin)) {
    console.log("Installing project dependencies...");
    const npmBin = process.platform === "win32" ? "npm.cmd" : "npm";
    const result = await command(npmBin, ["ci"], { show: true });
    if (result.code !== 0) fail("npm ci failed. Fix the error and rerun setup.");
  }
  let identity = await wrangler(["whoami", "--json"]);
  if (identity.code !== 0) {
    console.log("Sign in to Cloudflare using the link shown by Wrangler.");
    await checkedWrangler(["login", "--device"], { show: true });
    identity = await wrangler(["whoami", "--json"]);
  }
  if (identity.code !== 0) fail("Cloudflare login was not completed.");
  const who = JSON.parse(identity.stdout);
  if (!who.loggedIn || !Array.isArray(who.accounts) || who.accounts.length < 1)
    fail("No Cloudflare account is available.");
  let account = who.accounts[0];
  if (who.accounts.length > 1) {
    who.accounts.forEach((item, index) => console.log(`${index + 1}. ${item.name}`));
    const selected = Number(await question("Choose the Cloudflare account number: "));
    account = who.accounts[selected - 1];
    if (!account) fail("Invalid account selection.");
  }
  const accountEnv = { CLOUDFLARE_ACCOUNT_ID: account.id };

  await mkdir(localDir, { recursive: true, mode: 0o700 });
  let state = existsSync(statePath) ? JSON.parse(await readFile(statePath, "utf8")) : null;
  if (state) {
    if (state.accountId !== account.id || !/^vaultgram-[a-z0-9-]+-[a-f0-9]{6}$/.test(state.workerName) || state.version !== 1)
      fail("This setup state belongs to another Cloudflare account or installer version.");
    if (state.completed) {
      console.log(`Installation already completed at ${state.workerUrl}. No secrets were changed.`);
      return;
    }
    console.log("Resuming the previous installation with its original secrets.");
  } else {
    if (existsSync(localConfig))
      fail("A local Wrangler config exists without setup state. No changes were made.");
    const token = await hiddenToken();
    if (!token) fail("BotFather token is required.");
    const bot = await telegram(token, "getMe");
    if (!bot?.is_bot || !bot?.username) fail("The supplied token does not identify a Telegram bot.");
    const webhook = await telegram(token, "getWebhookInfo");
    if (webhook.url) fail("This Telegram bot already has a webhook. Use a new bot for a fresh installation.");
    const workerName = installationName(bot.username, randomBytes(3).toString("hex"));
    const existing = await wrangler(["deployments", "list", "--name", workerName, "--json"], { env: accountEnv });
    assertFreshWorker(existing);

    const recovery = validateRecovery({
      TELEGRAM_BOT_TOKEN: token,
      TELEGRAM_WEBHOOK_SECRET: randomBytes(32).toString("base64url"),
      BOOTSTRAP_SECRET: randomBytes(32).toString("base64url"),
      VAULT_ENCRYPTION_KEY: randomBytes(32).toString("base64url"),
      PIN_PEPPER: randomBytes(32).toString("base64url"),
    });
    const recoveryDir = join(homedir(), ".vaultgram", "recovery");
    await mkdir(recoveryDir, { recursive: true, mode: 0o700 });
    const recoveryPath = join(recoveryDir, `${Date.now()}-${bot.username}.json`);
    await writeFile(recoveryPath, `${JSON.stringify(recovery, null, 2)}\n`, { mode: 0o600, flag: "wx" });
    state = { version: 1, accountId: account.id, workerName, botUsername: bot.username, recoveryPath, workerUrl: null, backupConfirmed: false, completed: false };
    await saveState(state);
    console.log(`Recovery file created outside the repository: ${recoveryPath}`);
  }

  const recovery = validateRecovery(JSON.parse(await readFile(state.recoveryPath, "utf8")));
  const bot = await telegram(recovery.TELEGRAM_BOT_TOKEN, "getMe");
  if (bot.username !== state.botUsername) fail("The recovery file belongs to a different Telegram bot.");
  if (!state.backupConfirmed) {
    const confirmation = await question("Back up the recovery file in your password manager, then type SAVED: ");
    if (confirmation !== "SAVED") fail("Setup paused. Save the recovery file, then rerun npm run setup.");
    state.backupConfirmed = true;
    await saveState(state);
  }

  if (!existsSync(localConfig)) {
    const base = await readFile(join(root, "wrangler.jsonc"), "utf8");
    await savePrivate(localConfig, privateWranglerConfig(base, state.workerName));
  } else {
    const savedConfig = JSON.parse(await readFile(localConfig, "utf8"));
    if (savedConfig.name !== state.workerName)
      fail("Local Wrangler config belongs to another installation. No changes were made.");
  }
  const configArgs = ["--config", localConfig];
  if (!state.workerUrl) {
    console.log("Deploying the Worker and provisioning Cloudflare resources...");
    const tempDir = await mkdtemp(join(tmpdir(), "vaultgram-deploy-"));
    const outputFile = join(tempDir, "wrangler.ndjson");
    try {
      await checkedWrangler(["deploy", ...configArgs], {
        env: { ...accountEnv, WRANGLER_OUTPUT_FILE_PATH: outputFile }, show: true,
      });
      state.workerUrl = deploymentUrl((await readFile(outputFile, "utf8")).split("\n").filter(Boolean));
      await saveState(state);
    } finally { await rm(tempDir, { recursive: true, force: true }); }
  }

  console.log("Configuring Worker Secrets without printing their values...");
  const installed = await checkedWrangler(["secret", "list", ...configArgs, "--format", "json"], { env: accountEnv });
  const present = new Set(JSON.parse(installed).map((item) => item.name));
  for (const name of secretNames) {
    if (present.has(name)) continue;
    await checkedWrangler(["secret", "put", name, ...configArgs], {
      env: accountEnv, input: recovery[name], show: true,
    });
  }
  console.log("Applying D1 migrations...");
  await checkedWrangler(["d1", "migrations", "apply", "VAULTGRAM_DB", "--remote", ...configArgs], {
    env: accountEnv, show: true,
  });
  await ensureHealthy(state.workerUrl);

  const currentWebhook = await telegram(recovery.TELEGRAM_BOT_TOKEN, "getWebhookInfo");
  const webhookUrl = `${state.workerUrl}/telegram/webhook`;
  if (currentWebhook.url && currentWebhook.url !== webhookUrl)
    fail("This bot's webhook now points elsewhere. Setup stopped without replacing it.");
  console.log("Configuring Telegram commands and webhook...");
  await telegram(recovery.TELEGRAM_BOT_TOKEN, "setMyCommands", { commands: [
    { command: "menu", description: "Open the main menu" },
    { command: "cancel", description: "Cancel the current action" },
  ] });
  await telegram(recovery.TELEGRAM_BOT_TOKEN, "setMyCommands", { language_code: "fa", commands: [
    { command: "menu", description: "بازکردن منوی اصلی" },
    { command: "cancel", description: "لغو کار فعلی" },
  ] });
  await telegram(recovery.TELEGRAM_BOT_TOKEN, "setChatMenuButton", { menu_button: { type: "commands" } });
  const [commands, menuButton] = await Promise.all([
    telegram(recovery.TELEGRAM_BOT_TOKEN, "getMyCommands"),
    telegram(recovery.TELEGRAM_BOT_TOKEN, "getChatMenuButton"),
  ]);
  if (!commands.some(({ command }) => command === "menu") || menuButton.type !== "commands")
    fail("Telegram did not retain the command menu. The webhook was not changed; rerun setup.");
  await telegram(recovery.TELEGRAM_BOT_TOKEN, "setWebhook", {
    url: webhookUrl,
    secret_token: recovery.TELEGRAM_WEBHOOK_SECRET,
    allowed_updates: ["message", "callback_query"],
    drop_pending_updates: false,
  });
  const finalWebhook = await telegram(recovery.TELEGRAM_BOT_TOKEN, "getWebhookInfo");
  if (finalWebhook.url !== webhookUrl) fail("Telegram did not retain the webhook. Rerun setup.");
  state.completed = true;
  await saveState(state);
  console.log(`Ready: ${state.workerUrl}`);
  console.log(`Open @${state.botUsername} and send /claim followed by BOOTSTRAP_SECRET from your recovery file.`);
  console.log(`Keep the recovery file safe: ${state.recoveryPath}`);
}

run().catch((error) => {
  console.error(`Setup stopped: ${error.message}`);
  process.exitCode = 1;
});
