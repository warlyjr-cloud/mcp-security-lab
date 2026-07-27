import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import eslintConfigPrettier from 'eslint-config-prettier';

export default tseslint.config(
  // The root config type-lints only the CLI under src/ (see tsconfig.json).
  // backend/ and frontend/ have their own tooling and tsconfigs.
  { ignores: ['dist/', 'node_modules/', 'coverage/', 'backend/', 'frontend/'] },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  eslintConfigPrettier,
  {
    rules: {
      '@typescript-eslint/explicit-function-return-type': 'warn',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
    languageOptions: {
      parserOptions: {
        project: './tsconfig.json',
      },
    },
    ignores: ['dist/', 'node_modules/', 'coverage/'],
  },
);
