import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';

export default [
  {
    files: ['src/**/*.ts', 'test/**/*.ts'],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
    },
    rules: {
      // Google TypeScript style
      '@typescript-eslint/explicit-function-return-type': ['error', {
        allowExpressions: true,
        allowTypedFunctionExpressions: true,
      }],
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unused-vars': ['error', {
        argsIgnorePattern: '^_',
      }],
      '@typescript-eslint/consistent-type-imports': 'error',

      // Readability and DRY
      'no-duplicate-imports': 'error',
      'no-constant-condition': 'error',
      'no-unreachable': 'error',
      'prefer-const': 'error',
      'no-var': 'error',
      'eqeqeq': ['error', 'always'],
      'curly': ['error', 'all'],
      'no-throw-literal': 'error',

      // Complexity limits — keep functions small and simple (errors, not warnings)
      'max-lines-per-function': ['error', { max: 40, skipBlankLines: true, skipComments: true }],
      'max-depth': ['error', 3],
      'complexity': ['error', 10],
    },
  },
  {
    ignores: ['dist/', 'out/', 'node_modules/', '*.mjs'],
  },
];
