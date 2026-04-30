/**
 * @file entity.ts
 * @author tngan
 * @desc Shared base class for identity-provider and service-provider
 * entities. Owns configuration merging, metadata delegation, and the
 * high-level parse/create helpers used by both sides.
 */
import { randomUUID } from 'crypto';
import { isString, isNonEmptyArray } from './utility';
import { namespace, wording, algorithms, messageConfigurations } from './urn';
import IdpMetadata, { IdpMetadata as IdpMetadataConstructor } from './metadata-idp';
import SpMetadata, { SpMetadata as SpMetadataConstructor } from './metadata-sp';
import redirectBinding from './binding-redirect';
import postBinding from './binding-post';
import simpleSignBinding from './binding-simplesign';
import type {
  MetadataIdpConstructor,
  MetadataSpConstructor,
  EntitySetting,
  ESamlHttpRequest,
  BindingContext,
  PostBindingContext,
  SimpleSignBindingContext,
  SimpleSignComputedContext,
  ParseResult,
  RequestInfo,
  SAMLUser,
  CreateLogoutRequestOptions,
  CreateLogoutResponseOptions,
  CustomTagReplacement,
} from './types';
import {
  normalizeCreateLogoutRequestOptions,
  normalizeCreateLogoutResponseOptions,
} from './options';
import { flow } from './flow';

export type {
  ESamlHttpRequest,
  BindingContext,
  PostBindingContext,
  SimpleSignBindingContext,
  SimpleSignComputedContext,
  ParseResult,
} from './types';

const dataEncryptionAlgorithm = algorithms.encryption.data;
const keyEncryptionAlgorithm = algorithms.encryption.key;
const signatureAlgorithms = algorithms.signature;
const messageSigningOrders = messageConfigurations.signingOrder;

const defaultEntitySetting = {
  wantLogoutResponseSigned: false,
  messageSigningOrder: messageSigningOrders.SIGN_THEN_ENCRYPT,
  wantLogoutRequestSigned: false,
  allowCreate: false,
  isAssertionEncrypted: false,
  requestSignatureAlgorithm: signatureAlgorithms.RSA_SHA256,
  dataEncryptionAlgorithm: dataEncryptionAlgorithm.AES_256,
  keyEncryptionAlgorithm: keyEncryptionAlgorithm.RSA_OAEP_MGF1P,
  generateID: (): string => '_' + randomUUID(),
  relayState: '',
};

/** Constructor argument shared by both SP and IdP factories. */
export type EntityConstructor = (MetadataIdpConstructor | MetadataSpConstructor)
  & { metadata?: string | Buffer };

export default class Entity {
  entitySetting: EntitySetting;
  entityType: string;
  entityMeta: IdpMetadataConstructor | SpMetadataConstructor;

  /**
   * Build an entity, merging the provided configuration with defaults and
   * hydrating the metadata abstraction for its role.
   *
   * @param entitySetting IdP or SP settings (metadata XML or options)
   * @param entityType `idp` or `sp`
   */
  constructor(entitySetting: EntityConstructor, entityType: 'idp' | 'sp') {
    this.entitySetting = Object.assign({}, defaultEntitySetting, entitySetting);
    this.entityType = entityType;
    const metadata = entitySetting.metadata || entitySetting;
    switch (entityType) {
      case 'idp':
        this.entityMeta = IdpMetadata(metadata);
        // Metadata takes precedence over settings when both supply the same key.
        this.entitySetting.wantAuthnRequestsSigned = (this.entityMeta as IdpMetadataConstructor).isWantAuthnRequestsSigned();
        this.entitySetting.nameIDFormat = this.entityMeta.getNameIDFormat() || this.entitySetting.nameIDFormat;
        break;
      case 'sp':
        this.entityMeta = SpMetadata(metadata);
        // Metadata takes precedence over settings when both supply the same key.
        this.entitySetting.authnRequestsSigned = (this.entityMeta as SpMetadataConstructor).isAuthnRequestSigned();
        this.entitySetting.wantAssertionsSigned = (this.entityMeta as SpMetadataConstructor).isWantAssertionsSigned();
        this.entitySetting.nameIDFormat = this.entityMeta.getNameIDFormat() || this.entitySetting.nameIDFormat;
        break;
      default:
        throw new Error('ERR_UNDEFINED_ENTITY_TYPE');
    }
  }

  /**
   * Return the effective entity settings (defaults merged with overrides).
   */
  getEntitySetting(): EntitySetting {
    return this.entitySetting;
  }

  /**
   * Return the serialized metadata XML for this entity.
   */
  getMetadata(): string {
    return this.entityMeta.getMetadata();
  }

  /**
   * Persist the metadata XML to disk.
   *
   * @param exportFile absolute file path
   */
  exportMetadata(exportFile: string): void {
    return this.entityMeta.exportMetadata(exportFile);
  }

  /**
   * Equality check between a field value extracted from a SAML message and
   * the value declared in the peer's metadata. Arrays must match on every
   * entry.
   *
   * @param field value(s) from the inbound SAML message
   * @param metaField value from peer metadata
   * @returns true when every provided value equals `metaField`
   */
  verifyFields(field: string | string[], metaField: string): boolean {
    if (isString(field)) {
      return field === metaField;
    }
    if (isNonEmptyArray(field)) {
      let res = true;
      (field as string[]).forEach(f => {
        if (f !== metaField) {
          res = false;
        }
      });
      return res;
    }
    return false;
  }

  /**
   * Build a logout request targeting `targetEntity`. The return type depends
   * on the binding: `redirect` produces a URL; `post` and `simpleSign`
   * produce a base64 envelope (the latter with a detached signature).
   *
   * The fourth parameter accepts either a string (legacy `relayState`
   * positional shape) or an options bag `{ relayState?, customTagReplacement? }`.
   * Per `saml-bindings §3.4.3 / §3.5.3`, RelayState is request-scoped — pass
   * it via the options bag instead of `entitySetting.relayState`.
   *
   * @param targetEntity peer to receive the logout request
   * @param binding `redirect`, `post`, or `simpleSign`
   * @param user currently authenticated user
   * @param optionsOrRelayState per-request options or legacy RelayState string
   * @param legacyCustomTagReplacement optional custom template transformer (legacy positional form)
   */
  createLogoutRequest(
    targetEntity: Entity,
    binding: string,
    user: SAMLUser,
    optionsOrRelayState?: CreateLogoutRequestOptions | string,
    legacyCustomTagReplacement?: CustomTagReplacement,
  ): BindingContext | PostBindingContext | SimpleSignBindingContext {
    const opts = normalizeCreateLogoutRequestOptions(optionsOrRelayState, legacyCustomTagReplacement);
    const relayState = opts.relayState ?? this.entitySetting.relayState ?? '';
    const customTagReplacement = opts.customTagReplacement;

    if (binding === wording.binding.redirect) {
      return redirectBinding.logoutRequestRedirectURL(user, {
        init: this,
        target: targetEntity,
      }, relayState, customTagReplacement);
    }
    if (binding === wording.binding.post) {
      const entityEndpoint = targetEntity.entityMeta.getSingleLogoutService(binding) as string;
      const context = postBinding.base64LogoutRequest(user, "/*[local-name(.)='LogoutRequest']", { init: this, target: targetEntity }, customTagReplacement);
      return {
        ...context,
        relayState,
        entityEndpoint,
        type: 'SAMLRequest',
      };
    }
    if (binding === wording.binding.simpleSign) {
      const entityEndpoint = targetEntity.entityMeta.getSingleLogoutService(binding) as string;
      const context = simpleSignBinding.base64LogoutRequest(
        user,
        { init: this, target: targetEntity },
        relayState,
        customTagReplacement,
      );
      return {
        ...context,
        relayState,
        entityEndpoint,
        type: 'SAMLRequest',
      };
    }
    // Artifact binding is not yet implemented.
    throw new Error('ERR_UNDEFINED_BINDING');
  }

  /**
   * Build a logout response to the peer that initiated logout.
   *
   * The fourth parameter accepts either a string (legacy `relayState`
   * positional shape) or an options bag `{ relayState?, customTagReplacement? }`.
   * Per `saml-bindings §3.4.3 / §3.5.3`, RelayState is request-scoped — pass
   * it via the options bag instead of `entitySetting.relayState`.
   *
   * @param target peer that sent the corresponding logout request
   * @param requestInfo parsed request used to link `InResponseTo`
   * @param binding `redirect`, `post`, or `simpleSign`
   * @param optionsOrRelayState per-request options or legacy RelayState string
   * @param legacyCustomTagReplacement optional custom template transformer (legacy positional form)
   */
  createLogoutResponse(
    target: Entity,
    requestInfo: RequestInfo,
    binding: string,
    optionsOrRelayState?: CreateLogoutResponseOptions | string,
    legacyCustomTagReplacement?: CustomTagReplacement,
  ): BindingContext | PostBindingContext | SimpleSignBindingContext {
    const opts = normalizeCreateLogoutResponseOptions(optionsOrRelayState, legacyCustomTagReplacement);
    const relayState = opts.relayState ?? this.entitySetting.relayState ?? '';
    const customTagReplacement = opts.customTagReplacement;
    const protocol = namespace.binding[binding];
    if (protocol === namespace.binding.redirect) {
      return redirectBinding.logoutResponseRedirectURL(requestInfo, {
        init: this,
        target,
      }, relayState, customTagReplacement);
    }
    if (protocol === namespace.binding.post) {
      const context = postBinding.base64LogoutResponse(requestInfo, {
        init: this,
        target,
      }, customTagReplacement);
      return {
        ...context,
        relayState,
        entityEndpoint: target.entityMeta.getSingleLogoutService(binding) as string,
        type: 'SAMLResponse',
      };
    }
    if (protocol === namespace.binding.simpleSign) {
      const context = simpleSignBinding.base64LogoutResponse(
        requestInfo,
        { init: this, target },
        relayState,
        customTagReplacement,
      );
      return {
        ...context,
        relayState,
        entityEndpoint: target.entityMeta.getSingleLogoutService(binding) as string,
        type: 'SAMLResponse',
      };
    }
    throw new Error('ERR_CREATE_LOGOUT_RESPONSE_UNDEFINED_BINDING');
  }

  /**
   * Parse, validate and verify an inbound logout request.
   *
   * @param from peer entity that produced the request
   * @param binding `redirect`, `post`, or `simpleSign`
   * @param request HTTP request envelope
   */
  parseLogoutRequest(from: Entity, binding: string, request: ESamlHttpRequest) {
    return flow({
      from,
      self: this,
      type: 'logout',
      parserType: 'LogoutRequest',
      checkSignature: this.entitySetting.wantLogoutRequestSigned,
      binding,
      request,
    });
  }

  /**
   * Parse, validate and verify an inbound logout response.
   *
   * @param from peer entity that produced the response
   * @param binding `redirect`, `post`, or `simpleSign`
   * @param request HTTP request envelope
   */
  parseLogoutResponse(from: Entity, binding: string, request: ESamlHttpRequest) {
    return flow({
      from,
      self: this,
      type: 'logout',
      parserType: 'LogoutResponse',
      checkSignature: this.entitySetting.wantLogoutResponseSigned,
      binding,
      request,
    });
  }
}
