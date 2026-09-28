# Manual installation and existing deployments

Use this route when you already have a Vaultgram Worker or need to control each step. **Do not run the fresh-install wizard against an existing bot.** Preserve the existing `VAULT_ENCRYPTION_KEY` and `PIN_PEPPER`; replacing them breaks access to existing encrypted data and PINs.

1. Run `npm ci` and `npx wrangler login` if needed.
2. Run `npm run deploy`. Wrangler can provision D1, KV, and Queue bindings declared in `wrangler.jsonc`. Record the HTTPS Worker URL.
3. For a new installation only, run `npm run secrets:generate` once and store the generated values in a password manager. Add the BotFather token there too. For an existing installation, reuse the original values.
4. Configure the five Worker Secrets with `npx wrangler secret put NAME`: `TELEGRAM_BOT_TOKEN`, `TELEGRAM_WEBHOOK_SECRET`, `BOOTSTRAP_SECRET`, `VAULT_ENCRYPTION_KEY`, and `PIN_PEPPER`. Enter each at Wrangler's hidden prompt. Never put values in Git, `wrangler.jsonc`, or shell history.
5. Run `npm run db:migrate:remote`. Check `https://YOUR-WORKER-ORIGIN/health` for `ok`.
6. Set `TELEGRAM_BOT_TOKEN`, `TELEGRAM_WEBHOOK_SECRET`, and `PUBLIC_BASE_URL` in a secure local shell environment. Run `npm run setup:webhook` and `npm run webhook:status`. Run `npm run setup:bot-menu` to register the `/menu` and `/cancel` commands and Telegram's menu button.
7. For a new installation, send `/claim YOUR_BOOTSTRAP_SECRET` privately to the bot. The first successful claim creates the Owner.

For a fresh wizard installation, use its ignored `.vaultgram/wrangler.jsonc` for future Wrangler commands. Redeploy with `npx wrangler deploy --config .vaultgram/wrangler.jsonc`; apply new migrations with `npx wrangler d1 migrations apply VAULTGRAM_DB --remote --config .vaultgram/wrangler.jsonc`. The ignored `.vaultgram/install-state.json` is used only to resume setup and does not contain Secret values.

For local development, copy `.dev.vars.example` to `.dev.vars`, fill local secrets, run `npm run db:migrate:local` and `npm run dev`. `.dev.vars` is ignored by Git. A public HTTPS tunnel is needed to receive real Telegram webhooks locally.
