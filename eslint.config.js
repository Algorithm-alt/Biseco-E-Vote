const globals = require('globals');
const pluginJs = require('@eslint/js');

module.exports = [
  { ignores: ['node_modules/', 'public/uploads/'] },
  pluginJs.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'commonjs',
      globals: {
        ...globals.node,
        ...globals.browser,
        ...globals.jest,
      },
    },
    rules: {
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
      'no-console': 'off',
    },
  },
];
