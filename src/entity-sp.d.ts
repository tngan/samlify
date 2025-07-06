/**
 * @file entity-sp.ts
 * @author tngan
 * @desc  Declares the actions taken by service provider
 */
import Entity from './entity.js';
import type { BindingContext, PostBindingContext, ESamlHttpRequest, SimpleSignBindingContext } from './entity.js';
import { IdentityProviderConstructor as IdentityProvider, ServiceProviderMetadata, type ServiceProviderSettings } from './types.js';
import { type FlowResult } from './flow.js';
export default function (props: ServiceProviderSettings): ServiceProvider;
/**
 * @desc Service provider can be configured using either metadata importing or spSetting
 * @param  {object} spSettingimport { FlowResult } from '../types/src/flow.d';

 */
export declare class ServiceProvider extends Entity {
    entityMeta: ServiceProviderMetadata;
    /**
     * @desc  Inherited from Entity
     * @param {object} spSetting    setting of service provider
     */
    constructor(spSetting: ServiceProviderSettings);
    /**
     * @desc  Generates the login request for developers to design their own method
     * @param  {IdentityProvider} idp               object of identity provider
     * @param  {string}   binding                   protocol binding
     * @param  {function} customTagReplacement     used when developers have their own login response template
     */
    createLoginRequest(idp: IdentityProvider, binding?: string, customTagReplacement?: (template: string) => BindingContext): BindingContext | PostBindingContext | SimpleSignBindingContext;
    /**
     * @desc  Generates the Art login request for developers to design their own method
     * @param  {IdentityProvider} idp               object of identity provider
     * @param  {string}   binding                   protocol binding
     * @param  {function} customTagReplacement     used when developers have their own login response template
     */
    createLoginRequestArt(idp: IdentityProvider, binding?: string, customTagReplacement?: (template: string) => BindingContext): BindingContext | PostBindingContext | SimpleSignBindingContext;
    /**
     * @desc   Validation of the parsed the URL parameters
     * @param  {IdentityProvider}   idp             object of identity provider
     * @param  {string}   binding                   protocol binding
     * @param  {request}   req                      request
     */
    parseLoginResponse(idp: any, binding: any, request: ESamlHttpRequest): Promise<FlowResult>;
    /**
     * @desc   request SamlResponse by Arc id
     * @param  {IdentityProvider}   idp             object of identity provider
     * @param  {string}   binding                   protocol binding
     * @param  {request}   req                      request
     */
    parseLoginResponseArt(idp: any, binding: any, request: ESamlHttpRequest): Promise<FlowResult>;
    /**
     * @desc   generate Art id
     *
     * @param entityIDString
     */
    createArt(entityIDString: string, endpointIndex?: number): string;
    /**
     * @desc   generate Art id
     * @param artifact
     */
    parseArt(artifact: string): {
        typeCode: number;
        endpointIndex: number;
        sourceId: string;
        messageHandle: string;
    };
}
//# sourceMappingURL=entity-sp.d.ts.map