export function assertFreshWorker(result) {
  if (result.code === 0)
    throw new Error("An existing Worker with this installation name was found. Fresh setup stopped before generating or replacing any secrets.");
  if (!/code:\s*10007/.test(result.output))
    throw new Error("Could not safely determine whether a vaultgram Worker exists. No changes were made.");
}

export function installationName(username, suffix) {
  const slug = username.toLowerCase().replace(/[^a-z0-9-]/g, "-");
  if (!slug || !/^[a-f0-9]{6}$/.test(suffix))
    throw new Error("Invalid bot username or installation suffix.");
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
    throw new Error("Deployment succeeded but no HTTPS Worker URL was returned. Check Cloudflare and rerun setup.");
  return new URL(candidate).origin;
}
