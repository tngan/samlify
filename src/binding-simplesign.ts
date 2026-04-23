/**
 * @file binding-simplesign.ts
 * @author Orange
 * @desc Binding-level API for SAML HTTP-POST-SimpleSign. Produces base64
 * payloads alongside a detached signature over the canonical octet string.
 */

import { wording, StatusCode } from './urn';
import type {
  BindingContext,
  SimpleSignComputedContext,
  RequestInfo,
  SAMLUser,
  TagReplacementMap,
} from './types';
import type { IdentityProvider as Idp } from './entity-idp';
import type { ServiceProvider as Sp } from './entity-sp';
import libsaml from './libsaml';
import utility, { get } from './utility';

const binding = wording.binding;
const urlParams = wording.urlParams;

/** Options consumed by {@link buildSimpleSignature}. */
export interface BuildSimpleSignConfig {
  type: string;
  context: string;
  entitySetting: {
    requestSignatureAlgorithm?: string;
    privateKey?: string | Buffer;
    privateKeyPass?: string;
  };
  relayState?: string;
}

/** Return value for login-response building with simple signatures. */
export interface BindingSimpleSignContext {
  id: string;
  context: string;
  signature: string | Buffer;
  sigAlg: string;
}

/** `{ idp, sp }` handle used by simple-sign builders. */
interface SimpleSignIdpSpPair {
  idp: Idp;
  sp: Sp;
}

/**
 * Build a `key=value` URL fragment prefixed with the correct separator.
 */
function pvPair(param: string, value: string, first?: boolean): string {
  return (first === true ? '?' : '&') + param + '=' + value;
}

/**
 * Compute a detached RSA signature over a SimpleSign canonical octet string.
 *
 * @param opts signing inputs
 * @returns base64-encoded signature
 */
function buildSimpleSignature(opts: BuildSimpleSignConfig): string {
  const { type, context, entitySetting } = opts;
  let { relayState = '' } = opts;
  const queryParam = libsaml.getQueryParamByType(type);

  if (relayState !== '') {
    relayState = pvPair(urlParams.relayState, relayState);
  }

  const sigAlg = pvPair(urlParams.sigAlg, entitySetting.requestSignatureAlgorithm!);
  const octetString = context + relayState + sigAlg;
  return libsaml.constructMessageSignature(
    queryParam + '=' + octetString,
    entitySetting.privateKey as string,
    entitySetting.privateKeyPass,
    undefined,
    entitySetting.requestSignatureAlgorithm,
  ).toString();
}

/**
 * Generate a base64-encoded AuthnRequest together with a detached simple
 * signature when the IdP advertises `WantAuthnRequestsSigned`.
 *
 * @param entity `{ idp, sp }` handles
 * @param customTagReplacement optional custom template transformer
 */
function base64LoginRequest(
  entity: SimpleSignIdpSpPair,
  customTagReplacement?: (template: string) => BindingContext,
): SimpleSignComputedContext {
  const metadata = { idp: entity.idp.entityMeta, sp: entity.sp.entityMeta };
  const spSetting = entity.sp.entitySetting;
  let id = '';

  if (metadata && metadata.idp && metadata.sp) {
    const base = metadata.idp.getSingleSignOnService(binding.simpleSign);
    let rawSamlRequest: string;
    if (spSetting.loginRequestTemplate && customTagReplacement) {
      const info = customTagReplacement(spSetting.loginRequestTemplate.context!);
      id = get<string>(info as unknown as Record<string, unknown>, 'id') as string;
      rawSamlRequest = get<string>(info as unknown as Record<string, unknown>, 'context') as string;
    } else {
      const nameIDFormat = spSetting.nameIDFormat;
      const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;
      id = spSetting.generateID!();
      const tags: TagReplacementMap = {
        ID: id,
        Destination: base as string,
        Issuer: metadata.sp.getEntityID(),
        IssueInstant: new Date().toISOString(),
        AssertionConsumerServiceURL: metadata.sp.getAssertionConsumerService(binding.simpleSign) as string,
        EntityID: metadata.sp.getEntityID(),
        AllowCreate: spSetting.allowCreate,
        NameIDFormat: selectedNameIDFormat,
      };
      rawSamlRequest = libsaml.replaceTagsByValue(libsaml.defaultLoginRequestTemplate.context, tags);
    }

    let simpleSignatureContext: { signature: string; sigAlg: string } | null = null;
    if (metadata.idp.isWantAuthnRequestsSigned()) {
      const simpleSignature = buildSimpleSignature({
        type: urlParams.samlRequest,
        context: rawSamlRequest,
        entitySetting: spSetting,
        relayState: spSetting.relayState,
      });
      simpleSignatureContext = {
        signature: simpleSignature,
        sigAlg: spSetting.requestSignatureAlgorithm!,
      };
    }
    return {
      id,
      context: utility.base64Encode(rawSamlRequest),
      ...(simpleSignatureContext ?? {}),
    };
  }
  throw new Error('ERR_GENERATE_POST_SIMPLESIGN_LOGIN_REQUEST_MISSING_METADATA');
}

/**
 * Generate a base64-encoded login response together with a detached simple
 * signature. Login responses are always signed under this binding.
 *
 * @param requestInfo parsed request used to link `InResponseTo`
 * @param entity `{ idp, sp }` handles
 * @param user authenticated user
 * @param relayState caller-supplied redirect URL
 * @param customTagReplacement optional custom template transformer
 */
async function base64LoginResponse(
  requestInfo: RequestInfo | { extract?: { request?: { id?: string } } } = {} as RequestInfo,
  entity: SimpleSignIdpSpPair,
  user: SAMLUser = {},
  relayState?: string,
  customTagReplacement?: (template: string) => BindingContext,
): Promise<BindingSimpleSignContext> {
  const idpSetting = entity.idp.entitySetting;
  const spSetting = entity.sp.entitySetting;
  const id = idpSetting.generateID!();
  const metadata = {
    idp: entity.idp.entityMeta,
    sp: entity.sp.entityMeta,
  };
  const nameIDFormat = idpSetting.nameIDFormat;
  const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;
  if (metadata && metadata.idp && metadata.sp) {
    const base = metadata.sp.getAssertionConsumerService(binding.simpleSign);
    let rawSamlResponse: string;
    const nowTime = new Date();
    const fiveMinutesLaterTime = new Date(nowTime.getTime() + 300_000);
    const tvalue: TagReplacementMap = {
      ID: id,
      AssertionID: idpSetting.generateID!(),
      Destination: base as string,
      Audience: metadata.sp.getEntityID(),
      EntityID: metadata.sp.getEntityID(),
      SubjectRecipient: base as string,
      Issuer: metadata.idp.getEntityID(),
      IssueInstant: nowTime.toISOString(),
      AssertionConsumerServiceURL: base as string,
      StatusCode: StatusCode.Success,
      ConditionsNotBefore: nowTime.toISOString(),
      ConditionsNotOnOrAfter: fiveMinutesLaterTime.toISOString(),
      SubjectConfirmationDataNotOnOrAfter: fiveMinutesLaterTime.toISOString(),
      NameIDFormat: selectedNameIDFormat,
      NameID: user.email || '',
      InResponseTo: get<string>(requestInfo as Record<string, unknown>, 'extract.request.id', '') as string,
      AuthnStatement: '',
      AttributeStatement: '',
    };
    if (idpSetting.loginResponseTemplate && customTagReplacement) {
      const template = customTagReplacement(idpSetting.loginResponseTemplate.context!);
      rawSamlResponse = get<string>(template as unknown as Record<string, unknown>, 'context') as string;
    } else {
      if (requestInfo !== null && (requestInfo as RequestInfo).extract?.request) {
        tvalue.InResponseTo = (requestInfo as RequestInfo).extract.request!.id as string;
      }
      rawSamlResponse = libsaml.replaceTagsByValue(libsaml.defaultLoginResponseTemplate.context, tvalue);
    }
    const { privateKey, privateKeyPass, requestSignatureAlgorithm: signatureAlgorithm } = idpSetting;
    const config = {
      privateKey: privateKey as string,
      privateKeyPass,
      signatureAlgorithm: signatureAlgorithm!,
      signingCert: metadata.idp.getX509Certificate('signing') as string,
      isBase64Output: false,
    };
    if (metadata.sp.isWantAssertionsSigned()) {
      rawSamlResponse = libsaml.constructSAMLSignature({
        ...config,
        rawSamlMessage: rawSamlResponse,
        transformationAlgorithms: spSetting.transformationAlgorithms,
        referenceTagXPath: "/*[local-name(.)='Response']/*[local-name(.)='Assertion']",
        signatureConfig: {
          prefix: 'ds',
          location: { reference: "/*[local-name(.)='Response']/*[local-name(.)='Assertion']/*[local-name(.)='Issuer']", action: 'after' },
        },
      });
    }

    // Login response is always signed in the simple-sign binding.
    const simpleSignature = buildSimpleSignature({
      type: urlParams.samlResponse,
      context: rawSamlResponse,
      entitySetting: idpSetting,
      relayState,
    });

    return Promise.resolve({
      id,
      context: utility.base64Encode(rawSamlResponse),
      signature: simpleSignature,
      sigAlg: idpSetting.requestSignatureAlgorithm!,
    });
  }
  throw new Error('ERR_GENERATE_POST_SIMPLESIGN_LOGIN_RESPONSE_MISSING_METADATA');
}

const simpleSignBinding = {
  base64LoginRequest,
  base64LoginResponse,
};

export default simpleSignBinding;
