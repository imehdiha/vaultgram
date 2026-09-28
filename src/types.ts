export interface Env extends Cloudflare.Env {
  DELETE_QUEUE: Queue<DeleteJob>;
  DOCUMENTS: KVNamespace;
  TELEGRAM_BOT_TOKEN: string;
  TELEGRAM_WEBHOOK_SECRET: string;
  BOOTSTRAP_SECRET: string;
  VAULT_ENCRYPTION_KEY: string;
  PIN_PEPPER: string;
}
export interface DeleteJob {
  chat_id: string;
  message_id: number;
}
export interface User {
  id: string;
  telegram_id: string;
  display_name: string;
  role: "OWNER" | "MEMBER";
  disabled: number;
  removed: number;
  locale: "en" | "fa" | null;
  pin_salt: string | null;
  pin_hash: string | null;
  pin_failures: number;
  pin_locked_until: number;
}
export interface Vault {
  id: string;
  name: string;
  requires_pin: number;
  archived_at: number | null;
}
export interface Category {
  id: string;
  vault_id: string;
  name: string;
}
export interface Document {
  id: string;
  vault_id: string;
  category_id: string;
  title: string;
  original_filename: string;
  mime_type: string;
  size_bytes: number;
  storage_key: string;
  encryption_version: number;
  crypto_iv: string;
  status: "ACTIVE" | "ARCHIVED" | "MISSING" | "DELETING";
  created_by: string;
  created_at: number;
  updated_at: number;
  last_checked_at: number;
}
export interface SecureValue {
  id: string;
  vault_id: string;
  category_id: string | null;
  label: string;
  kind: string;
  ciphertext: string;
  crypto_iv: string;
  crypto_revision: string;
  encryption_version: number;
  created_by: string;
  created_at: number;
  updated_at: number;
  archived_at: number | null;
}
export interface Message {
  message_id: number;
  chat: { id: number; type: string };
  from?: {
    id: number;
    first_name: string;
    username?: string;
    language_code?: string;
  };
  text?: string;
  document?: {
    file_id: string;
    file_unique_id: string;
    file_size?: number;
    file_name?: string;
    mime_type?: string;
  };
  photo?: { file_id: string; file_unique_id: string; file_size?: number }[];
}
export interface Callback {
  id: string;
  from: { id: number; first_name: string };
  message?: Message;
  data?: string;
}
export interface Update {
  update_id: number;
  message?: Message;
  callback_query?: Callback;
}
export type Level = "VIEW" | "EDIT" | "MANAGE";
