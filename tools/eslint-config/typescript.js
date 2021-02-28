// @ts-check
const config = {
	parser: '@typescript-eslint/parser',
	plugins: ['@typescript-eslint'],
	extends: [
		'plugin:@typescript-eslint/eslint-recommended',
		'plugin:@typescript-eslint/recommended',
		'plugin:@typescript-eslint/recommended-requiring-type-checking',
	],
	rules: {
		'@typescript-eslint/no-unused-vars': [
			'warn',
			{
				argsIgnorePattern: '^_|^[iI]gnore',
				caughtErrorsIgnorePattern: '^_|^[iI]gnore',
				varsIgnorePattern: '^_|^[iI]gnore|^React$|^jsx$|^css$',
			},
		],
		'@typescript-eslint/explicit-function-return-type': 'off',
		'@typescript-eslint/no-use-before-define': 'off',
		'@typescript-eslint/no-explicit-any': 'off',
		'@typescript-eslint/no-unsafe-assignment': 'off',
		// '@typescript-eslint/no-unsafe-call': 'off',
		'@typescript-eslint/no-unsafe-member-access': 'off',
		// '@typescript-eslint/no-unsafe-return': 'off',
		'@typescript-eslint/explicit-module-boundary-types': 'off',
		'@typescript-eslint/restrict-template-expressions': 'off',
		// '@typescript-eslint/restrict-plus-operands': 'off',
		'@typescript-eslint/require-await': 'off',
	},
};

module.exports = config;
