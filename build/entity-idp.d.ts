/**
 * @file entity-idp.ts
 * @author tngan
 * @desc  Declares the actions taken by identity provider
 */
import Entity, { BindingContext, ESamlHttpRequest } from "./entity";
import { IdentityProviderMetadata, IdentityProviderSettings, ServiceProviderConstructor as ServiceProvider } from "./types";
/**
 * Identity prvider can be configured using either metadata importing or idpSetting
 */
export default function (props: IdentityProviderSettings): IdentityProvider;
/**
 * Identity prvider can be configured using either metadata importing or idpSetting
 */
export declare class IdentityProvider extends Entity {
    entityMeta: IdentityProviderMetadata;
    constructor(idpSetting: IdentityProviderSettings);
    /**
     * @desc  Generates the login response for developers to design their own method
     * @param  sp                        object of service provider
     * @param  requestInfo               corresponding request, used to obtain the id
     * @param  binding                   protocol binding
     * @param  user                      current logged user (e.g. req.user)
     * @param  customTagReplacement      used when developers have their own login response template
     * @param  encryptThenSign           whether or not to encrypt then sign first (if signing)
     */
    createLoginResponse(sp: ServiceProvider, requestInfo: {
        [key: string]: any;
    }, binding: string, user: {
        [key: string]: any;
    }, customTagReplacement?: (template: string) => BindingContext, encryptThenSign?: boolean): Promise<{
        entityEndpoint: string | string[];
        type: string;
        context: string;
        id: string;
    }>;
    /**
     * Validation of the parsed URL parameters
     * @param sp ServiceProvider instance
     * @param binding Protocol binding
     * @param req RequesmessageSigningOrderst
     */
    parseLoginRequest(sp: ServiceProvider, binding: string, req: ESamlHttpRequest): Promise<import("./flow").FlowResult>;
}
