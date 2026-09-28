const encoder = new TextEncoder();
export const now = () => Math.floor(Date.now() / 1000);
export const id = () => crypto.randomUUID();
export function randomToken(bytes = 32): string {
  const raw = crypto.getRandomValues(new Uint8Array(bytes));
  return base64url(raw);
}
export function base64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
export function unbase64url(value: string): Uint8Array<ArrayBuffer> {
  const s = atob(value.replaceAll("-", "+").replaceAll("_", "/"));
  const out = new Uint8Array(new ArrayBuffer(s.length));
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
export async function sha256(value: string): Promise<string> {
  return base64url(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", encoder.encode(value)),
    ),
  );
}
export async function hmac(secret: string, value: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return base64url(
    new Uint8Array(
      await crypto.subtle.sign("HMAC", key, encoder.encode(value)),
    ),
  );
}
export function equal(a: string, b: string): boolean {
  const x = encoder.encode(a),
    y = encoder.encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++)
    diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}
export function safeName(raw: string): string {
  const name = raw
    .trim()
    .replace(/[\u0000-\u001f\u007f\/\\]/g, "_")
    .replace(/^\.+/, "")
    .slice(0, 160);
  if (!name || name === "." || name === "..")
    throw new Error("Invalid file name");
  return name;
}
export function extension(name: string, mime: string): string {
  const ext = name.match(/\.([a-zA-Z0-9]{1,12})$/)?.[1]?.toLowerCase();
  const known: Record<string, string> = {
    "application/pdf": "pdf",
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
  };
  return known[mime] ?? ext ?? "bin";
}
