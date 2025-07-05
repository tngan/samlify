/**
 * @file entity-sp.ts
 * @author tngan
 * @desc  Declares the actions taken by service provider
 */
import Entity, {} from './entity.js';
import * as crypto from "node:crypto";
import type {
    BindingContext,
    PostBindingContext,
    ESamlHttpRequest,
    SimpleSignBindingContext,
} from './entity.js';
import {
    IdentityProviderConstructor as IdentityProvider,
    ServiceProviderMetadata,
    type ServiceProviderSettings,
} from './types.js';
import {namespace} from './urn.js';
import redirectBinding from './binding-redirect.js';
import postBinding from './binding-post.js';
import simpleSignBinding from './binding-simplesign.js';
import artifactSignBinding from './binding-artifact.js';
import {flow, type FlowResult} from './flow.js';

/*
 * @desc interface function
 */
export default function (props: ServiceProviderSettings) {
    return new ServiceProvider(props);
}

/**
 * @desc Service provider can be configured using either metadata importing or spSetting
 * @param  {object} spSettingimport { FlowResult } from '../types/src/flow.d';

 */
export class ServiceProvider extends Entity {
    declare entityMeta: ServiceProviderMetadata;

    /**
     * @desc  Inherited from Entity
     * @param {object} spSetting    setting of service provider
     */
    constructor(spSetting: ServiceProviderSettings) {
        const entitySetting = Object.assign({
            authnRequestsSigned: false,
            wantAssertionsSigned: false,
            wantMessageSigned: false,
        }, spSetting);
        super(entitySetting, 'sp');
    }

    /**
     * @desc  Generates the login request for developers to design their own method
     * @param  {IdentityProvider} idp               object of identity provider
     * @param  {string}   binding                   protocol binding
     * @param  {function} customTagReplacement     used when developers have their own login response template
     */
    public createLoginRequest(
        idp: IdentityProvider,
        binding = 'redirect',
        customTagReplacement?: (template: string) => BindingContext,
    ): BindingContext | PostBindingContext | SimpleSignBindingContext {
        const nsBinding = namespace.binding;
        const protocol = nsBinding[binding];
        if (this.entityMeta.isAuthnRequestSigned() !== idp.entityMeta.isWantAuthnRequestsSigned()) {
            throw new Error('ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG');
        }

        let context: any = null;
        switch (protocol) {
            case nsBinding.redirect:
                return redirectBinding.loginRequestRedirectURL({idp, sp: this}, customTagReplacement);

            case nsBinding.post:
                context = postBinding.base64LoginRequest("/*[local-name(.)='AuthnRequest']", {
                    idp,
                    sp: this
                }, customTagReplacement);
                break;

            case nsBinding.simpleSign:
                // Object context = {id, context, signature, sigAlg}
                context = simpleSignBinding.base64LoginRequest({idp, sp: this}, customTagReplacement);
                break;
            case nsBinding.artifact:
                context = artifactSignBinding.base64LoginRequest("/*[local-name(.)='AuthnRequest']", {
                    idp,
                    sp: this
                }, customTagReplacement);
                break;
            default:
                // Will support artifact in the next release
                throw new Error('ERR_SP_LOGIN_REQUEST_UNDEFINED_BINDING');
        }

        return {
            ...context,
            relayState: this.entitySetting.relayState,
            entityEndpoint: idp.entityMeta.getSingleSignOnService(binding) as string,
            type: 'SAMLRequest',
        };
    }


    /**
     * @desc  Generates the Art login request for developers to design their own method
     * @param  {IdentityProvider} idp               object of identity provider
     * @param  {string}   binding                   protocol binding
     * @param  {function} customTagReplacement     used when developers have their own login response template
     */
    public createLoginRequestArt(
        idp: IdentityProvider,
        binding = 'redirect',
        customTagReplacement?: (template: string) => BindingContext,
    ): BindingContext | PostBindingContext | SimpleSignBindingContext {
        const nsBinding = namespace.binding;
        const protocol = nsBinding[binding];
        if (this.entityMeta.isAuthnRequestSigned() !== idp.entityMeta.isWantAuthnRequestsSigned()) {
            throw new Error('ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG');
        }

        let context: any = null;
        switch (protocol) {
            case nsBinding.redirect:
                return redirectBinding.loginRequestRedirectURLArt({idp, sp: this}, customTagReplacement);
            case nsBinding.post:
                context = postBinding.base64LoginRequest("/*[local-name(.)='AuthnRequest']", {
                    idp,
                    sp: this,
                    soap: true
                }, customTagReplacement);
                break;

            default:
                // Will support artifact in the next release
                throw new Error('ERR_SP_LOGIN_REQUEST_UNDEFINED_BINDING');
        }

        return {
            ...context,
            relayState: this.entitySetting.relayState,
            entityEndpoint: idp.entityMeta.getSingleSignOnService(binding) as string,
            type: 'SAMLRequest',
        };
    }


    /**
     * @desc   Validation of the parsed the URL parameters
     * @param  {IdentityProvider}   idp             object of identity provider
     * @param  {string}   binding                   protocol binding
     * @param  {request}   req                      request
     */
    public parseLoginResponse(idp, binding, request: ESamlHttpRequest) {
        const self = this;
        return flow({
            from: idp,
            self: self,
            checkSignature: true, // saml response must have signature
            parserType: 'SAMLResponse',
            type: 'login',
            binding: binding,
            request: request
        });
    }

    /**
     * @desc   request SamlResponse by Arc id
     * @param  {IdentityProvider}   idp             object of identity provider
     * @param  {string}   binding                   protocol binding
     * @param  {request}   req                      request
     */
    public parseLoginResponseArt(idp, binding, request: ESamlHttpRequest) {
        const self = this;
        return flow({
            soap: true,
            from: idp,
            self: self,
            checkSignature: true, // saml response must have signature
            parserType: 'SAMLResponse',
            type: 'login',
            binding: binding,
            request: request
        });
    }

    /**
     * @desc   generate Art id
     *
     * @param entityIDString
     */
    public createArt(entityIDString:string) {

        let entityID  = entityIDString ? entityIDString:this.entityMeta.getEntityID();
console.log(entityID)
        console.log("0000000000000000000000000000000000000000")
        // 2. 生成 SHA-1 SourceID (20字节)
        const sourceId = crypto.createHash('sha1')
            .update(entityID)
            .digest()
            .subarray(0, 20); // 取前20字节

        // 3. 生成随机 MessageHandle (20字节)
        const messageHandle = crypto.randomBytes(20);

        // 4. 构建工件二进制数据 (44字节)
        const artifactBuf = Buffer.alloc(44);

        // 类型码 (2字节, SAML 2.0 固定为 0x0004)
        artifactBuf.writeUInt16BE(0x0004, 0);

        // 端点索引 (2字节, 通常为0)
        artifactBuf.writeUInt16BE(0x0000, 2);

        // SourceID (20字节)
        sourceId.copy(artifactBuf, 4);

        // MessageHandle (20字节)
        messageHandle.copy(artifactBuf, 24);

        // 5. Base64 编码
        return artifactBuf.toString('base64');
    }
  /**
   * @desc   generate Art id
   * @param artifact
   */
 public parseArt(artifact: string) {
    // 解码 Base64
    const decoded = Buffer.from(artifact, 'base64');

    // 确保长度正确（SAML 工件固定为 44 字节）
    if (decoded.length !== 44) {
      throw new Error(`Invalid artifact length: ${decoded.length}, expected 44 bytes`);
    }

    // 读取前 4 字节（TypeCode + EndpointIndex）
    const typeCode = decoded.readUInt16BE(0);
    const endpointIndex = decoded.readUInt16BE(2);

    // 使用 Buffer.from() 替代 slice()
    const sourceId = Buffer.from(
        decoded.buffer,         // 底层 ArrayBuffer
        decoded.byteOffset + 4, // 起始偏移量
        20                     // 长度
    ).toString('hex');

    const messageHandle = Buffer.from(
        decoded.buffer,          // 底层 ArrayBuffer
        decoded.byteOffset + 24,  // 起始偏移量
        20                       // 长度
    ).toString('hex');

    return { typeCode, endpointIndex, sourceId, messageHandle };
  }

}
