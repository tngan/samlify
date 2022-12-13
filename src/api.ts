// global module configuration
interface Context extends ValidatorContext {}

interface ValidatorContext {
  validate?: (xml: string) => Promise<any>;
}

const context: Context = {
  validate: undefined
};

export function getContext() {
  return context;
}

export function setSchemaValidator(params: ValidatorContext) {

  if (typeof params.validate !== 'function') {
    throw new Error('validate must be a callback function having one argument as xml input');
  }

  // assign the validate function to the context
  context.validate = params.validate;

}
