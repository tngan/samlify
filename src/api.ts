import { DOMParser as dom } from '@xmldom/xmldom';

import {validate as defaultValidator} from "./schemaValidator.js";

// global module configuration
interface Context extends ValidatorContext, DOMParserContext {}

// 定义函数类型
type ValidateFunction = (xml: string, isSoap?: boolean) => Promise<any>;

// 使用类型别名定义接口
interface ValidatorContext {
  validate: ValidateFunction;
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

export function setDOMParserOptions(options = {}):void {
  context.dom = new dom(options);
}
