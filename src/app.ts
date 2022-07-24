/**
 * This is the data structure for idp-sp management, most of the saml 
 * operations will be defined here.
 * 
 * This will provide one idp to N sp and N idp to N sp according to the saml
 * backend use cases. Developer can link pairs
 */

import { IdentityProvider } from "./idp";
import { ServiceProvider } from "./sp";

export interface SamlApp {

}

/**
 * Pair up with another entity result in a new data structure with all
 * common functions
 */
export const create = (): SamlApp => {

  const connections = {};
  const entities = {};

  /**
   * 
   * @param idp 
   * @param sp 
   */
  const bind = (idp: IdentityProvider, sp: ServiceProvider) => {

    // TODO: Validate for the pair up to see if there is any conflict

    // Cached into the nested object for function access
    if (!connections[idp.id]) {
      connections[idp.id] = {};
    }
    if (!connections[idp.id][sp.id]) {
      connections[idp.id][sp.id] = {};
    }
    connections[idp.id][sp.id] = true;
    entities[idp.id] = idp;
    entities[sp.id] = sp;

  };

  /**
   * Check if the connection is active
   * 
   * @param idpId 
   * @param spId 
   * @returns 
   */
  const isActive = (idpId: string, spId: string) => {
    return !!connections[idpId]?.[spId];
  };

  return {
    bind,
    isActive
  };

}