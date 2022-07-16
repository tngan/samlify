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
 * const app = link(idp, sp);
 * 
 * app.createLoginRequest();
 * app.createLogoutRequest();
 * app.processLoginRequest();
 * app.processLogoutRequest();
 * 
 */
export type CreateProps = {
  id: string;
};

export type BindOptions = {

};

export interface ServiceProvider {
  id: string;
};

/**
 * Create function and returns a set of helper functions
 */
export const create = (props: CreateProps): ServiceProvider => {

  return {
    id: props.id
  };

}