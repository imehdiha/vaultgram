export function assertFreshWorker(result) {
  if (result.code === 0)
    throw new Error("برنامه‌ای با این نام از قبل وجود دارد. نصب تازه پیش از ساخت یا جایگزینی رمزها متوقف شد.");
  if (!/code:\s*10007/.test(result.output))
    throw new Error("وجود برنامهٔ قبلی به‌طور امن مشخص نشد. چیزی تغییر نکرد.");
}

export function installationName(username, suffix) {
  const slug = username.toLowerCase().replace(/[^a-z0-9-]/g, "-");
  if (!slug || !/^[a-f0-9]{6}$/.test(suffix))
    throw new Error("نام روبات یا شناسهٔ نصب معتبر نیست.");
  return `vaultgram-${slug}-${suffix}`;
}

export function privateWranglerConfig(source, workerName) {
  const config = JSON.parse(source);
  delete config.$schema;
  config.name = workerName;
  config.main = "../src/index.ts";
  config.d1_databases = config.d1_databases.map((item) => ({
    ...item,
    database_name: workerName,
    migrations_dir: "../migrations",
  }));
  config.queues.producers = config.queues.producers.map((item) => ({
    ...item,
    queue: `${workerName}-delete`,
  }));
  config.queues.consumers = config.queues.consumers.map((item) => ({
    ...item,
    queue: `${workerName}-delete`,
  }));
  return `${JSON.stringify(config, null, 2)}\n`;
}

export function deploymentUrl(lines) {
  const deploy = lines.map((line) => {
    try { return JSON.parse(line); } catch { return null; }
  }).findLast((item) => item?.type === "deploy");
  const candidate = deploy?.targets?.find((target) => {
    try { return new URL(target).protocol === "https:"; } catch { return false; }
  });
  if (!candidate)
    throw new Error("استقرار انجام شد، اما نشانی امن برنامه برنگشت. کلادفلر را بررسی کنید و نصب را دوباره اجرا کنید.");
  return new URL(candidate).origin;
}
