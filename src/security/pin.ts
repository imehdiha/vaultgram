import type { Env, User, Vault } from "../types";
import { equal, hmac, now, randomToken } from "./crypto";
import { audit, one, run, setting } from "../db/repo";
export class PinRequired extends Error {
  constructor() { super("PIN required"); }
}
export async function setPin(env: Env, user: User, pin: string): Promise<void> {
  if (!/^\d{6,12}$/.test(pin)) throw new Error("PIN must be 6–12 digits");
  const salt = randomToken(16);
  const hash = await hmac(env.PIN_PEPPER, `${user.id}:${salt}:${pin}`);
  await env.VAULTGRAM_DB.batch([
    env.VAULTGRAM_DB.prepare(
      "UPDATE users SET pin_salt=?,pin_hash=?,pin_failures=0,pin_locked_until=0 WHERE id=?",
    ).bind(salt, hash, user.id),
    env.VAULTGRAM_DB.prepare(
      "UPDATE user_sessions SET pin_unlocked_until=0 WHERE user_id=?",
    ).bind(user.id),
  ]);
  await audit(env.VAULTGRAM_DB, user.id, "PIN_SET", user.id);
}
export async function verifyPin(
  env: Env,
  user: User,
  pin: string,
): Promise<boolean> {
  const current = await one<User>(
    env.VAULTGRAM_DB,
    "SELECT * FROM users WHERE id=? AND disabled=0 AND removed=0",
    user.id,
  );
  if (!current || current.pin_locked_until > now()) return false;
  const hash = await hmac(
    env.PIN_PEPPER,
    `${current.id}:${current.pin_salt ?? ""}:${pin}`,
  );
  const ok = !!current.pin_hash && equal(hash, current.pin_hash);
  if (ok) {
    const duration = Number(
      await setting(env.VAULTGRAM_DB, "pin_session_seconds"),
    );
    await run(
      env.VAULTGRAM_DB,
      "INSERT INTO user_sessions(user_id,pin_unlocked_until) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET pin_unlocked_until=excluded.pin_unlocked_until",
      user.id,
      now() + duration,
    );
    await run(
      env.VAULTGRAM_DB,
      "UPDATE users SET pin_failures=0,pin_locked_until=0 WHERE id=?",
      user.id,
    );
    return true;
  }
  await run(
    env.VAULTGRAM_DB,
    "UPDATE users SET pin_failures=pin_failures+1,pin_locked_until=CASE WHEN pin_failures+1>=5 THEN ? ELSE 0 END WHERE id=? AND pin_locked_until<=?",
    now() + 900,
    user.id,
    now(),
  );
  const after = await one<{ pin_locked_until: number }>(
    env.VAULTGRAM_DB,
    "SELECT pin_locked_until FROM users WHERE id=?",
    user.id,
  );
  await audit(
    env.VAULTGRAM_DB,
    user.id,
    after?.pin_locked_until ? "PIN_LOCKOUT" : "PIN_FAILURE",
    user.id,
  );
  return false;
}
export async function pinRequired(
  env: Env,
  user: User,
  vault: Vault,
  action: "browse" | "download" | "edit",
): Promise<boolean> {
  const policy = await setting(env.VAULTGRAM_DB, "pin_policy");
  const required =
    policy === "ALWAYS" ||
    (policy === "DOWNLOADS" && action === "download") ||
    (policy === "SENSITIVE_VAULTS" && !!vault.requires_pin);
  if (!required) return false;
  const session = await one<{ pin_unlocked_until: number }>(
    env.VAULTGRAM_DB,
    "SELECT pin_unlocked_until FROM user_sessions WHERE user_id=?",
    user.id,
  );
  return !session || session.pin_unlocked_until <= now();
}
