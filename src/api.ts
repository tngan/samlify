import { SamlifyError, SamlifyErrorCode } from './error';

// global module configuration
type Context = ValidatorContext;

interface ValidatorContext {
	validate?: (xml: string) => Promise<any>;
}

const context: Context = {
	validate: undefined,
};

export function getContext() {
	return context;
}

export function setSchemaValidator(params: ValidatorContext) {
	if (typeof params.validate !== 'function') {
		throw new SamlifyError(SamlifyErrorCode.TypeError, 'validate must be a function having one argument as xml input');
	}
	// assign the validate function to the context
	context.validate = params.validate;
}
