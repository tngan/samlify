const { resolve } = require('path');

// @ts-check
const config = {
	overrides: [
		{
			files: ['*.{js,ts}'],
			extends: ['./eslint-config/base'],
		},
		{
			files: ['*.js'],
			extends: ['./eslint-config/javascript', './eslint-config/node', './eslint-config/prettier'],
		},
		{
			files: ['src/**/*.ts'],
			extends: ['./eslint-config/typescript', './eslint-config/node', './eslint-config/prettier'],
			parserOptions: { project: resolve(__dirname, '../tsconfig.json') },
		},
		{
			files: ['test/**/*.ts'],
			extends: ['./eslint-config/typescript', './eslint-config/node', './eslint-config/prettier'],
			parserOptions: { project: resolve(__dirname, '../test/tsconfig.json') },
		},
	],
};

module.exports = config;
