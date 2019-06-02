// version <= 1.25
export { default as IdentityProvider } from './src/entity-idp';
export { default as ServiceProvider } from './src/entity-sp';
export { default as IdPMetadata } from './src/metadata-idp';
export { default as SPMetadata } from './src/metadata-sp';
export { default as Utility } from './src/utility';
export { default as SamlLib } from './src/libsaml';
// roadmap
// new name convention in version >= 3.0
import * as Constants from './src/urn';
import * as Extractor from './src/extractor';

// exposed methods for customising samlify
import { setSchemaValidator } from './src/api';

export {
  Constants,
  Extractor,
  // set context
  setSchemaValidator
};
