import { DOMParser as dom } from '@xmldom/xmldom';
import type { Options as DOMParserOptions } from '@xmldom/xmldom';
import {validate as defaultValidator} from "./schemaValidator.js";

// global module configuration
interface Context extends ValidatorContext, DOMParserContext {}

interface ValidatorContext {
  validate?: (xml: string) => Promise<any>;
}

interface DOMParserContext {
  dom: dom;
}

const context: Context = {
  validate: defaultValidator,
  dom: new dom()
};

export function getContext():Context {
  return context;
}

export function setSchemaValidator(params: ValidatorContext):void {

  if (typeof params.validate !== 'function') {
    throw new Error('validate must be a callback function having one argument as xml input');
  }

  // assign the validate function to the context
  context.validate = params.validate;

}

export function setDOMParserOptions(options: DOMParserOptions = {}):void {
  context.dom = new dom(options);
}
