import { defineConfig } from '@vscode/test-cli';

export default defineConfig({
  files: 'out/test/integration/**/*.test.js',
  workspaceFolder: './test/fixtures',
  mocha: {
    timeout: 30_000,
  },
});
