/**
 * Define the identity provider interface, construction and feature
 * 
 * Usage:
 * 
 * const idp = create(props);
 * const sp = create(props);
 * 
 * // Perform the validation and pre-operation check before running into problem
 * // during runtime
 * 
 * const app = bind(idp, sp);
 * 
 * app.createLoginRequest();
 * app.createLogoutRequest();
 * app.processLoginRequest();
 * app.processLogoutRequest();
 * 
 */

export type CreateProps = {
  //
  id: string;
};

export type LoadProps = {
  //
  id: string;
  metadata: string;
};

export type BindOptions = {

};

export interface IdentityProvider {
  id: string
};

/**
 * Create function and returns a set of helper functions
 * 
 * @param props 
 * @returns 
 */
export const create = (props: CreateProps): IdentityProvider => {

  return {
    id: props.id
  };

}

/**
 * Create an idp by import a metadata, we separate the creation via metadata
 * into another 
 * 
 * @param props 
 * @returns 
 */
export const load = (props: LoadProps): IdentityProvider => {

  return {
    id: props.id
  }

};