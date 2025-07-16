// version <= 1.25
import IdentityProvider, { IdentityProvider as IdentityProviderInstance } from './src/entity-idp.js';
import ServiceProvider, { ServiceProvider as ServiceProviderInstance } from './src/entity-sp.js';

export { default as IdPMetadata } from './src/metadata-idp.js';
export { default as SPMetadata } from './src/metadata-sp.js';
export { default as Utility } from './src/utility.js';
export { default as SamlLib } from './src/libsaml.js';
// roadmap
// new name convention in version >= 3.0
import * as Constants from './src/urn.js';
import * as Extractor from './src/extractor.js';
import * as Soap from './src/soap.js';
import {validate,validateMetadata} from './src/schemaValidator.js'
// exposed methods for customizing samlify
import { setSchemaValidator, setDOMParserOptions } from './src/api.js';

export {
  Constants,
  Extractor,
  // temp: resolve the conflict after version >= 3.0
  IdentityProvider,
  IdentityProviderInstance,
  ServiceProvider,
  ServiceProviderInstance,
  // set context
  setSchemaValidator,
  setDOMParserOptions,
  validate,
  validateMetadata,
  Soap

};
