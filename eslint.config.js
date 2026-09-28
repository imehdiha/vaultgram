import js from '@eslint/js';
import tseslint from 'typescript-eslint';
export default tseslint.config(
  { ignores: ['node_modules/**', '.wrangler/**', 'worker-configuration.d.ts'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  { languageOptions: { globals: { crypto: 'readonly', fetch: 'readonly', FormData: 'readonly', Blob: 'readonly', Response: 'readonly', Request: 'readonly', URL: 'readonly', TextEncoder: 'readonly', console: 'readonly' } }, rules: { 'no-control-regex': 'off', 'no-useless-escape': 'off' } }
);
