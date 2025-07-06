import Entity, { type ESamlHttpRequest } from './entity.js';
import { ServiceProviderConstructor as ServiceProvider, IdentityProviderMetadata, type IdentityProviderSettings } from './types.js';
import { type FlowResult } from './flow.js';
import type { BindingContext } from './entity.js';
/**
 * Identity provider can be configured using either metadata importing or idpSetting
 */
export default function (props: IdentityProviderSettings): IdentityProvider;
/**
 * Identity provider can be configured using either metadata importing or idpSetting
 */
export declare class IdentityProvider extends Entity {
    entityMeta: IdentityProviderMetadata;
    constructor(idpSetting: IdentityProviderSettings);
    /**
     * @desc  Generates the login response for developers to design their own method
     * @param params
     */
    createLoginResponse(params: {
        sp: ServiceProvider;
        requestInfo: Record<string, any>;
        binding?: string;
        user: Record<string, any>;
        customTagReplacement?: (template: string) => BindingContext;
        encryptThenSign?: boolean;
        relayState?: string;
        context: Record<string, any>;
        AttributeStatement: [];
    }): Promise<any>;
    /**
     * Validation of the parsed URL parameters
     * @param sp ServiceProvider instance
     * @param binding Protocol binding
     * @param req RequesmessageSigningOrderst
     */
    parseLoginRequest(sp: ServiceProvider, binding: string, req: ESamlHttpRequest): Promise<FlowResult>;
}
//# sourceMappingURL=entity-idp.d.ts.map