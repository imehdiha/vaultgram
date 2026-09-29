import { randomBytes } from "node:crypto";
import { Buffer } from "node:buffer";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
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
    fail("برای واردکردن امن توکن، نصب را در ترمینال تعاملی اجرا کنید.");
  process.stdout.write("توکن روبات از بات‌فادر (ورودی دیده نمی‌شود): ");
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
        if (char === "\u0003") return finish(new Error("نصب لغو شد."));
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

const wranglerCli = join(root, "node_modules", "wrangler", "bin", "wrangler.js");
const npmCli = [
  process.env.npm_execpath,
  join(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js"),
].find((path) => path && existsSync(path));

async function npm(args, options) {
  if (npmCli) return command(process.execPath, [npmCli, ...args], options);
  if (process.platform === "win32")
    fail("فایل اجرایی ان‌پی‌ام پیدا نشد. نصب را با دستور npm.cmd run setup در پاورشل اجرا کنید.");
  return command("npm", args, options);
}

async function wrangler(args, options) {
  if (!existsSync(wranglerCli)) fail("ابزار کلادفلر نصب نیست. دستور زیر را اجرا کنید و دوباره تلاش کنید:\nnpm ci");
  return command(process.execPath, [wranglerCli, ...args], options);
}
async function checkedWrangler(args, options) {
  const result = await wrangler(args, options);
  if (result.code !== 0) fail(`ابزار کلادفلر در مرحلهٔ «${args.slice(0, 2).join(" ")}» خطا داد. خطای بالا را بررسی کنید و نصب را دوباره اجرا کنید.`);
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
    fail(`ارتباط با تلگرام در مرحلهٔ «${method}» ناموفق بود (وضعیت ${response.status}). توکن روبات و دسترسی به تلگرام را بررسی کنید.`);
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
      fail("فایل بازیابی ناقص است؛ هیچ رمزی تغییر نکرد.");
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
  fail("بررسی سلامت برنامه موفق نبود. اتصال تلگرام تغییر نکرد؛ پس از بررسی کلادفلر نصب را دوباره اجرا کنید.");
}

async function startClaimQr(secret) {
  const { default: QRCode } = await import("qrcode");
  const png = await QRCode.toBuffer(`/claim ${secret}`, {
    type: "png", width: 420, margin: 2, errorCorrectionLevel: "M",
  });
  const route = `/qr-${randomBytes(16).toString("hex")}`;
  const server = createServer((request, response) => {
    if (request.url !== route) {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, {
      "content-type": "image/png",
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
    }).end(png);
  });
  await new Promise((resolveServer, rejectServer) => {
    server.once("error", rejectServer);
    server.listen(0, "127.0.0.1", resolveServer);
  });
  return { server, url: `http://127.0.0.1:${server.address().port}${route}` };
}

async function offerClaimQr(state) {
  const choice = await question("برای نمایش کد QR رمز مالک روی همین رایانه، کلید ورود را بزنید؛ برای ردکردن «خیر» بنویسید: ");
  if (["خیر", "no", "n"].includes(choice.toLowerCase())) return;

  let server;
  try {
    const recovery = validateRecovery(JSON.parse(await readFile(state.recoveryPath, "utf8")));
    const qr = await startClaimQr(recovery.BOOTSTRAP_SECRET);
    server = qr.server;
    const qrUrl = qr.url;
    const opener = process.platform === "win32"
      ? ["rundll32.exe", ["url.dll,FileProtocolHandler", qrUrl]]
      : process.platform === "darwin"
        ? ["open", [qrUrl]]
        : ["xdg-open", [qrUrl]];
    try { await command(opener[0], opener[1]); }
    catch { /* the local page can still be opened using the URL below */ }
    console.log("تصویر QR روی همین رایانه آماده است. اگر خودکار باز نشد، این نشانی محلی را در مرورگر باز کنید:");
    console.log(qrUrl);
    console.log("آن را با دوربین موبایل اسکن کنید؛ متن به‌دست‌آمده را فقط در گفت‌وگوی خصوصی روبات بفرستید.");
    await question("بعد از اسکن، برگهٔ مرورگر را ببندید و اینجا کلید ورود را بزنید: ");
  } catch (error) {
    console.log(`نمایش QR ممکن نشد: ${error.message}`);
    console.log("رمز مالک در فایل بازیابی باقی مانده است:");
    console.log(state.recoveryPath);
  } finally {
    if (server?.listening)
      await new Promise((resolveServer) => server.close(resolveServer));
  }
}

async function run() {
  if (Number(process.versions.node.split(".")[0]) < 20)
    fail("نود جی‌اس نسخهٔ ۲۰ یا بالاتر لازم است.");
  if (process.argv.includes("--dry-run")) {
    console.log("مراحل نصب تازه: ورود به کلادفلر، بررسی روبات، ساخت فایل بازیابی، استقرار، ثبت رمزها، آماده‌سازی پایگاه داده و اتصال تلگرام.");
    console.log("در این حالت هیچ چیزی تغییر نکرد.");
    return;
  }
  if (process.argv.includes("--check-local-tools")) {
    if (!existsSync(wranglerCli)) {
      const installed = await npm(["ci", "--no-audit", "--no-fund"], { show: true });
      if (installed.code !== 0) fail("نصب ابزارهای پروژه ناموفق بود.");
    }
    await checkedWrangler(["--version"]);
    const qr = await startClaimQr("test-secret-only");
    try {
      const response = await fetch(qr.url);
      const png = Buffer.from(await response.arrayBuffer());
      if (!response.ok || png.subarray(0, 8).toString("hex") !== "89504e470d0a1a0a")
        fail("بررسی محلی QR موفق نبود.");
      const denied = await fetch(new URL("/not-a-qr", qr.url));
      if (denied.status !== 404) fail("دسترسی به QR محدود نشده است.");
    } finally {
      await new Promise((resolveServer) => qr.server.close(resolveServer));
    }
    console.log("ابزارهای محلی آماده‌اند.");
    return;
  }
  if (!process.stdin.isTTY) fail("نصب را در ترمینال تعاملی خودتان اجرا کنید:\nnpm run setup");
  if (process.platform === "win32")
    console.log("Windows: if Persian appears as squares, use Windows Terminal, run chcp 65001, and see docs/INSTALL.fa.md.");
  console.log("نصب تازهٔ والتگرام شروع شد. نصب‌های قبلی با این دستور بازنشانی نمی‌شوند.");
  if (!existsSync(wranglerCli)) {
    console.log("در حال نصب ابزارهای موردنیاز پروژه...");
    const result = await npm(["ci", "--no-audit", "--no-fund"], { show: true });
    if (result.code !== 0) fail("نصب ابزارهای پروژه ناموفق بود. خطای بالا را برطرف کنید و دوباره این دستور را اجرا کنید:\nnpm run setup");
  }
  let identity = await wrangler(["whoami", "--json"]);
  if (identity.code !== 0) {
    console.log("نشانی نمایش‌داده‌شده را در مرورگر باز کنید و ورود به کلادفلر را تأیید کنید.");
    await checkedWrangler(["login", "--device"], { show: true });
    identity = await wrangler(["whoami", "--json"]);
  }
  if (identity.code !== 0) fail("ورود به کلادفلر کامل نشد.");
  const who = JSON.parse(identity.stdout);
  if (!who.loggedIn || !Array.isArray(who.accounts) || who.accounts.length < 1)
    fail("هیچ حساب کلادفلری در دسترس نیست.");
  let account = who.accounts[0];
  if (who.accounts.length > 1) {
    who.accounts.forEach((item, index) => console.log(`${index + 1}. ${item.name}`));
    const selected = Number(await question("شمارهٔ حساب کلادفلر موردنظر را وارد کنید: "));
    account = who.accounts[selected - 1];
    if (!account) fail("شمارهٔ حساب معتبر نیست.");
  }
  const accountEnv = { CLOUDFLARE_ACCOUNT_ID: account.id };

  await mkdir(localDir, { recursive: true, mode: 0o700 });
  let state = existsSync(statePath) ? JSON.parse(await readFile(statePath, "utf8")) : null;
  if (state) {
    if (state.accountId !== account.id || !/^vaultgram-[a-z0-9-]+-[a-f0-9]{6}$/.test(state.workerName) || state.version !== 1)
      fail("اطلاعات نصب قبلی مربوط به حساب کلادفلر یا نسخهٔ دیگری از نصب‌کننده است.");
    if (state.completed) {
      console.log("این نصب قبلاً کامل شده است. نشانی برنامه:");
      console.log(state.workerUrl);
      console.log("هیچ رمزی تغییر نکرد.");
      await offerClaimQr(state);
      return;
    }
    console.log("ادامهٔ نصب قبلی با همان رمزهای اولیه انجام می‌شود.");
  } else {
    if (existsSync(localConfig))
      fail("فایل تنظیمات محلی وجود دارد، اما اطلاعات ادامهٔ نصب پیدا نشد. چیزی تغییر نکرد.");
    const token = await hiddenToken();
    if (!token) fail("توکن روبات از بات‌فادر لازم است.");
    const bot = await telegram(token, "getMe");
    if (!bot?.is_bot || !bot?.username) fail("این توکن متعلق به یک روبات تلگرام نیست.");
    const webhook = await telegram(token, "getWebhookInfo");
    if (webhook.url) fail("این روبات از قبل به سرویس دیگری وصل است. برای نصب تازه، روبات جدیدی بسازید.");
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
    console.log("فایل بازیابی بیرون از پوشهٔ پروژه ساخته شد. نشانی آن:");
    console.log(recoveryPath);
  }

  const recovery = validateRecovery(JSON.parse(await readFile(state.recoveryPath, "utf8")));
  const bot = await telegram(recovery.TELEGRAM_BOT_TOKEN, "getMe");
  if (bot.username !== state.botUsername) fail("فایل بازیابی متعلق به روبات دیگری است.");
  if (!state.backupConfirmed) {
    console.log("همهٔ محتوای فایل بازیابی را در مدیر رمز عبور خود ذخیره کنید. پس از اطمینان، عبارت «ذخیره شد» را بنویسید.");
    const confirmation = await question("تأیید پشتیبان‌گیری: ");
    if (confirmation !== "ذخیره شد" && confirmation !== "SAVED")
      fail("نصب متوقف شد. فایل بازیابی را ذخیره کنید و دوباره این دستور را اجرا کنید:\nnpm run setup");
    state.backupConfirmed = true;
    await saveState(state);
  }

  if (!existsSync(localConfig)) {
    const base = await readFile(join(root, "wrangler.jsonc"), "utf8");
    await savePrivate(localConfig, privateWranglerConfig(base, state.workerName));
  } else {
    const savedConfig = JSON.parse(await readFile(localConfig, "utf8"));
    if (savedConfig.name !== state.workerName)
      fail("تنظیمات محلی متعلق به نصب دیگری است. چیزی تغییر نکرد.");
  }
  const configArgs = ["--config", localConfig];
  if (!state.workerUrl) {
    console.log("در حال استقرار برنامه و ساخت منابع کلادفلر...");
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

  console.log("در حال ثبت امن رمزها، بدون نمایش مقدار آن‌ها...");
  const installed = await checkedWrangler(["secret", "list", ...configArgs, "--format", "json"], { env: accountEnv });
  const present = new Set(JSON.parse(installed).map((item) => item.name));
  for (const name of secretNames) {
    if (present.has(name)) continue;
    await checkedWrangler(["secret", "put", name, ...configArgs], {
      env: accountEnv, input: recovery[name], show: true,
    });
  }
  console.log("در حال آماده‌سازی پایگاه داده...");
  await checkedWrangler(["d1", "migrations", "apply", "VAULTGRAM_DB", "--remote", ...configArgs], {
    env: accountEnv, show: true,
  });
  await ensureHealthy(state.workerUrl);

  const currentWebhook = await telegram(recovery.TELEGRAM_BOT_TOKEN, "getWebhookInfo");
  const webhookUrl = `${state.workerUrl}/telegram/webhook`;
  if (currentWebhook.url && currentWebhook.url !== webhookUrl)
    fail("اتصال این روبات اکنون به نشانی دیگری اشاره می‌کند. نصب بدون جایگزینی آن متوقف شد.");
  console.log("در حال تنظیم منو و اتصال تلگرام...");
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
    fail("تلگرام منوی فرمان‌ها را ثبت نکرد. اتصال روبات تغییر نکرد؛ نصب را دوباره اجرا کنید.");
  await telegram(recovery.TELEGRAM_BOT_TOKEN, "setWebhook", {
    url: webhookUrl,
    secret_token: recovery.TELEGRAM_WEBHOOK_SECRET,
    allowed_updates: ["message", "callback_query"],
    drop_pending_updates: false,
  });
  const finalWebhook = await telegram(recovery.TELEGRAM_BOT_TOKEN, "getWebhookInfo");
  if (finalWebhook.url !== webhookUrl) fail("تلگرام اتصال روبات را ثبت نکرد. نصب را دوباره اجرا کنید.");
  state.completed = true;
  await saveState(state);
  console.log("نصب کامل شد. نشانی برنامه:");
  console.log(state.workerUrl);
  console.log("روبات خود را در گفت‌وگوی خصوصی تلگرام باز کنید:");
  console.log(`@${state.botUsername}`);
  console.log("برای ساخت حساب مالک، این نمونه را با مقدار رمز مالک از فایل بازیابی تکمیل کنید:");
  console.log("/claim abc123");
  console.log("به جای abc123 مقدار واقعی را بنویسید.");
  console.log("نشانی فایل بازیابی؛ آن را امن نگه دارید:");
  console.log(state.recoveryPath);
  await offerClaimQr(state);
}

run().catch((error) => {
  console.error(`نصب متوقف شد: ${error.message}`);
  process.exitCode = 1;
});
