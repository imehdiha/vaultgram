# Contributing

Vaultgram is a focused Cloudflare Worker and Telegram bot. Keep document bytes encrypted in KV, Secure Value plaintext out of D1 and logs, and all object access behind current Vault ACL checks. The bot should remain useful through buttons without AI or an external storage account.

Run `npm ci` and `npm run verify` before proposing a change. Add focused tests when changing encryption, authorization, PIN, invitations, upload/replacement, cleanup, Telegram deletion, or the installer. Use D1 migrations for schema changes; never edit an already deployed migration. Do not include real tokens, document contents, personal IDs, or deployment-specific credentials in commits or issue reports.
