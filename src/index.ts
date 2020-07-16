// version <= 1.25
import IdentityProvider, {
  IdentityProvider as IdentityProviderInstance,
} from "./entity-idp";
import ServiceProvider, {
  ServiceProvider as ServiceProviderInstance,
} from "./entity-sp";

export { default as IdPMetadata } from "./metadata-idp";
export { default as SPMetadata } from "./metadata-sp";
export { default as Utility } from "./utility";
export { default as SamlLib } from "./libsaml";
// roadmap
// new name convention in version >= 3.0
import * as Constants from "./urn";
import * as Extractor from "./extractor";

// exposed methods for customising samlify
import { setSchemaValidator } from "./api";

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
};
