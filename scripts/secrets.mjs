import { randomBytes } from 'node:crypto';
for (const name of ['TELEGRAM_WEBHOOK_SECRET','BOOTSTRAP_SECRET','VAULT_ENCRYPTION_KEY','PIN_PEPPER']) console.log(`${name}=${randomBytes(32).toString('base64url')}`);
