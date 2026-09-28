-- Pre-production cutover: the deployed database was verified to contain no users or documents.
-- Existing OneDrive document rows are intentionally not migrated.
DROP TABLE documents;
DROP TABLE cleanup_jobs;
DROP TABLE oauth_states;
DROP TABLE oauth_connections;

CREATE TABLE documents (
  id TEXT PRIMARY KEY,
  vault_id TEXT NOT NULL REFERENCES vaults(id),
  category_id TEXT NOT NULL REFERENCES categories(id),
  title TEXT NOT NULL,
  original_filename TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
  storage_key TEXT NOT NULL UNIQUE,
  encryption_version INTEGER NOT NULL CHECK(encryption_version = 1),
  crypto_iv TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','ARCHIVED','MISSING','DELETING')),
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_checked_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX documents_category_idx ON documents(category_id,status,created_at);
CREATE INDEX documents_reconcile_idx ON documents(status,last_checked_at);

CREATE TABLE kv_cleanup_jobs (
  id TEXT PRIMARY KEY,
  storage_key TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  completed_at INTEGER
);
CREATE INDEX kv_cleanup_pending_idx ON kv_cleanup_jobs(completed_at,created_at);

CREATE TABLE secure_values (
  id TEXT PRIMARY KEY,
  vault_id TEXT NOT NULL REFERENCES vaults(id),
  category_id TEXT REFERENCES categories(id),
  label TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'TEXT',
  ciphertext TEXT NOT NULL,
  crypto_iv TEXT NOT NULL,
  crypto_revision TEXT NOT NULL,
  encryption_version INTEGER NOT NULL CHECK(encryption_version = 1),
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  archived_at INTEGER
);
CREATE INDEX secure_values_vault_idx ON secure_values(vault_id,archived_at,label);
CREATE INDEX secure_values_category_idx ON secure_values(category_id,archived_at);
