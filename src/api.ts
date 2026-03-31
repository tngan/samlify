import { DOMParser as dom, Options as DOMParserOptions } from '@xmldom/xmldom';

// global module configuration
interface Context extends ValidatorContext, DOMParserContext {}

interface ValidatorContext {
  validate?: (xml: string) => Promise<any>;
}

interface DOMParserContext {
  dom: dom;
}

const XXE_SAFE_OPTIONS: DOMParserOptions = {
  /**
   * Treat XML parsing errors as fatal to prevent XXE attacks.
   * Entity references (e.g. &xxe;) and malformed XML in SAML messages
   * are not expected and may indicate an attack attempt.
   */
  errorHandler: {
    error: (msg: string) => { throw new Error(`XML parsing error: ${msg}`); },
    fatalError: (msg: string) => { throw new Error(`XML fatal error: ${msg}`); },
  },
};

const context: Context = {
  validate: undefined,
  dom: new dom(XXE_SAFE_OPTIONS)
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

export function setDOMParserOptions(options: DOMParserOptions = {}) {
  context.dom = new dom(options);
}
