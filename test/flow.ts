import * as esaml2 from '../index';
import { readFileSync, writeFileSync } from 'fs';
import { test, expect, describe } from 'vitest';
import { PostBindingContext, SimpleSignBindingContext } from '../src/entity';
import { randomUUID } from 'crypto';
import * as url from 'url';
import util from '../src/utility';
import * as tk from 'timekeeper';

import * as validator from '@authenio/samlify-xsd-schema-validator';
// import * as validator from '@authenio/samlify-validate-with-xmllint';
// import * as validator from '@authenio/samlify-node-xmllint';
// import * as validator from '@authenio/samlify-libxml-xsd';

// const validator = require('@authenio/samlify-xsd-schema-validator');
// const validator = require('@authenio/samlify-validate-with-xmllint');
// const validator = require('@authenio/samlify-node-xmllint');
// const validator = require('@authenio/samlify-libxml-xsd');

esaml2.setSchemaValidator(validator);

const isString = util.isString;

const {
  IdentityProvider: identityProvider,
  ServiceProvider: serviceProvider,
  Utility: utility,
  SamlLib: libsaml,
  Constants: ref,
} = esaml2;

const binding = ref.namespace.binding;

// Custom template
const loginResponseTemplate = {
  context: '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status><saml:Assertion ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}" InResponseTo="{InResponseTo}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{AttributeStatement}</saml:Assertion></samlp:Response>',
  attributes: [
    { name: 'mail', valueTag: 'user.email', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', valueXsiType: 'xs:string' },
    { name: 'name', valueTag: 'user.name', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', valueXsiType: 'xs:string' },
  ],
};

const failedResponse: string = String(readFileSync('./test/misc/failed_response.xml'));

// Callers pass the binding URN; getAssertionConsumerService expects the short name.
const acsOf = (_sp, _binding) =>
  _sp.entityMeta.getAssertionConsumerService(Object.keys(binding).find(k => binding[k] === _binding) ?? _binding);

const createTemplateCallback = (_idp, _sp, _binding, user, render: (t: string, v: any) => string = libsaml.replaceTagsByValue) => template => {
  const _id =  '_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6';
  const now = new Date();
  const spEntityID = _sp.entityMeta.getEntityID();
  const idpSetting = _idp.entitySetting;
  const fiveMinutesLater = new Date(now.getTime());
  fiveMinutesLater.setMinutes(fiveMinutesLater.getMinutes() + 5);
  const tvalue = {
    ID: _id,
    AssertionID: idpSetting.generateID ? idpSetting.generateID() : `${randomUUID()}`,
    Destination: acsOf(_sp, _binding),
    Audience: spEntityID,
    SubjectRecipient: acsOf(_sp, _binding),
    NameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    NameID: user.email,
    Issuer: idp.entityMeta.getEntityID(),
    IssueInstant: now.toISOString(),
    ConditionsNotBefore: now.toISOString(),
    ConditionsNotOnOrAfter: fiveMinutesLater.toISOString(),
    SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater.toISOString(),
    AssertionConsumerServiceURL: acsOf(_sp, _binding),
    EntityID: spEntityID,
    // sampleRequestInfo is hoisted via `const`; the inner `template => ...`
    // function only dereferences it at runtime, by which time the binding
    // has invoked the callback. After the #549 fix the callback fires even
    // when the IdP did not supply a custom loginResponseTemplate, so the
    // request id has to come from the request info rather than a hard-
    // coded literal — otherwise non-custom-template tests would observe
    // the literal in extract.response.inResponseTo.
    InResponseTo: (sampleRequestInfo as { extract: { request: { id: string } } }).extract.request.id,
    StatusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',
    // Library-default loginResponseTemplate (now also fed to the callback
    // when no custom template is supplied — see #549) leaves these as
    // optional placeholder tags. Populate them as empty strings so the
    // resulting XML stays schema-valid.
    AuthnStatement: '',
    AttributeStatement: '',
    attrUserEmail: 'myemailassociatedwithsp@sp.com',
    attrUserName: 'mynameinsp',
  };
  return {
    id: _id,
    context: render(template, tvalue),
  };
};

// Parse Redirect Url context

const parseRedirectUrlContextCallBack = (_context: string) => {
  const originalURL = url.parse(_context, true);
  const _SAMLResponse = originalURL.query.SAMLResponse;
  const _Signature = originalURL.query.Signature;
  const _SigAlg = originalURL.query.SigAlg;
  delete originalURL.query.Signature;
  const _octetString = Object.keys(originalURL.query).map(q => q + '=' + encodeURIComponent(originalURL.query[q] as string)).join('&');

  return { query: {
    SAMLResponse: _SAMLResponse,
    Signature: _Signature,
    SigAlg: _SigAlg, },
    octetString: _octetString,
  };
};

// Build SimpleSign octetString
const buildSimpleSignOctetString = (type:string, context:string, sigAlg:string|undefined, relayState:string|undefined, signature: string|undefined) =>{
  const rawRequest = String(utility.base64Decode(context, true));
  let octetString:string = '';
  octetString += type + '=' + rawRequest;
  if (relayState !== undefined && relayState.length > 0){
    octetString += '&RelayState=' + relayState;
  }
  if (signature !== undefined && signature.length >0 && sigAlg && sigAlg.length > 0){
    octetString += '&SigAlg=' + sigAlg;
  }
  return octetString;
};

// Define of metadata

const defaultIdpConfig = {
  privateKey: readFileSync('./test/key/idp/privkey.pem'),
  privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  isAssertionEncrypted: true,
  encPrivateKey: readFileSync('./test/key/idp/encryptKey.pem'),
  encPrivateKeyPass: 'g7hGcRmp8PxT5QeP2q9Ehf1bWe9zTALN',
  metadata: readFileSync('./test/misc/idpmeta.xml'),
};

const oneloginIdpConfig = {
  privateKey: readFileSync('./test/key/idp/privkey.pem'),
  privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  isAssertionEncrypted: true,
  encPrivateKey: readFileSync('./test/key/idp/encryptKey.pem'),
  encPrivateKeyPass: 'g7hGcRmp8PxT5QeP2q9Ehf1bWe9zTALN',
  metadata: readFileSync('./test/misc/idpmeta_onelogoutservice.xml'),
};

const defaultSpConfig = {
  privateKey: readFileSync('./test/key/sp/privkey.pem'),
  privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
  isAssertionEncrypted: true, // for logout purpose
  encPrivateKey: readFileSync('./test/key/sp/encryptKey.pem'),
  encPrivateKeyPass: 'BXFNKpxrsjrCkGA8cAu5wUVHOSpci1RU',
  metadata: readFileSync('./test/misc/spmeta.xml'),
};

const noSignedIdpMetadata = readFileSync('./test/misc/idpmeta_nosign.xml').toString().trim();
const spmetaNoAssertSign = readFileSync('./test/misc/spmeta_noassertsign.xml').toString().trim();

const sampleRequestInfo = { extract: { request: { id: 'request_id' } } };

// Define entities
const idp = identityProvider(defaultIdpConfig);
const sp = serviceProvider(defaultSpConfig);
const idpNoEncrypt = identityProvider({ ...defaultIdpConfig, isAssertionEncrypted: false });
const idpcustomNoEncrypt = identityProvider({ ...defaultIdpConfig, isAssertionEncrypted: false, loginResponseTemplate });
const idpcustom = identityProvider({ ...defaultIdpConfig, loginResponseTemplate });
const idpEncryptThenSign = identityProvider({ ...defaultIdpConfig, messageSigningOrder: 'encrypt-then-sign' });
const spWantLogoutReqSign = serviceProvider({ ...defaultSpConfig, wantLogoutRequestSigned: true });
const idpWantLogoutResSign = identityProvider({ ...defaultIdpConfig, wantLogoutResponseSigned: true });
const spNoAssertSign = serviceProvider({ ...defaultSpConfig, metadata: spmetaNoAssertSign });
const spNoAssertSignCustomConfig = serviceProvider({ ...defaultSpConfig,
  metadata: spmetaNoAssertSign,
  signatureConfig: {
    prefix: 'ds',
    location: { reference: "/*[local-name(.)='Response']/*[local-name(.)='Issuer']", action: 'after' },
  },
});
const spWithClockDrift = serviceProvider({ ...defaultSpConfig, clockDrifts: [-2000, 2000] });

function writer(str) {
  writeFileSync('test.txt', str);
}

test('create login request with redirect binding using default template and parse it', async () => {
  const { id, context } = sp.createLoginRequest(idp, 'redirect');
  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');
  const originalURL = url.parse(context, true);
  const SAMLRequest = originalURL.query.SAMLRequest;
  const Signature = originalURL.query.Signature;
  const SigAlg = originalURL.query.SigAlg;
  delete originalURL.query.Signature;
  const octetString = Object.keys(originalURL.query).map(q => q + '=' + encodeURIComponent(originalURL.query[q] as string)).join('&');
  const { samlContent, extract } = await idp.parseLoginRequest(sp, 'redirect', { query: { SAMLRequest, Signature, SigAlg }, octetString});
  expect(extract.issuer).toBe('https://sp.example.org/metadata');
  expect(typeof extract.request.id).toBe('string');
  expect(extract.nameIDPolicy.format).toBe('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
  expect(extract.nameIDPolicy.allowCreate).toBe('false');
});

test('redirect binding rejects a message whose inflated size exceeds the cap', async () => {
  const SAMLRequest = util.base64Encode(util.deflateString(`<samlp:AuthnRequest>${' '.repeat(4 * 1024 * 1024)}</samlp:AuthnRequest>`));
  await expect(idp.parseLoginRequest(sp, 'redirect', { query: { SAMLRequest } }))
    .rejects.toThrow('ERR_INFLATED_MESSAGE_TOO_LARGE');
});

test('create login request with post simpleSign binding using default template and parse it', async () => {
  const { relayState, id, context: SAMLRequest, type, sigAlg, signature } = sp.createLoginRequest(idp, 'simpleSign') as SimpleSignBindingContext;
  expect(typeof id).toBe('string');
  expect(typeof SAMLRequest).toBe('string');
  const octetString = buildSimpleSignOctetString(type, SAMLRequest, sigAlg, relayState,signature);
  const { samlContent, extract } = await idp.parseLoginRequest(sp, 'simpleSign', { body: { SAMLRequest, Signature: signature, SigAlg:sigAlg }, octetString});
  expect(extract.issuer).toBe('https://sp.example.org/metadata');
  expect(typeof extract.request.id).toBe('string');
  expect(extract.nameIDPolicy.format).toBe('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
  expect(extract.nameIDPolicy.allowCreate).toBe('false');
});

test('create login request with post binding using default template and parse it', async () => {
  const { relayState, type, entityEndpoint, id, context: SAMLRequest } = sp.createLoginRequest(idp, 'post') as PostBindingContext;
  expect(typeof id).toBe('string');
  expect(typeof SAMLRequest).toBe('string');
  expect(typeof entityEndpoint).toBe('string');
  expect(type).toBe('SAMLRequest');
  const { extract } = await idp.parseLoginRequest(sp, 'post', { body: { SAMLRequest }});
  expect(extract.issuer).toBe('https://sp.example.org/metadata');
  expect(typeof extract.request.id).toBe('string');
  expect(extract.nameIDPolicy.format).toBe('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
  expect(extract.nameIDPolicy.allowCreate).toBe('false');
  expect(typeof extract.signature).toBe('string');
});

test('signed in sp is not matched with the signed notation in idp with post request', () => {
  const _idp = identityProvider({ ...defaultIdpConfig, metadata: noSignedIdpMetadata });
  try {
    const { id, context } = sp.createLoginRequest(_idp, 'post');
    expect(true).toBe(false);
  } catch (e: any) {
    expect(e.message).toContain('ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG');
  }
});

test('signed in sp is not matched with the signed notation in idp with redirect request', () => {
  const _idp = identityProvider({ ...defaultIdpConfig, metadata: noSignedIdpMetadata });
  try {
    const { id, context } = sp.createLoginRequest(_idp, 'redirect');
    expect(true).toBe(false);
  } catch (e: any) {
    expect(e.message).toContain('ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG');
  }
});

test('signed in sp is not matched with the signed notation in idp with post simpleSign request', () => {
  const _idp = identityProvider({ ...defaultIdpConfig, metadata: noSignedIdpMetadata });
  try {
    const { id, context } = sp.createLoginRequest(_idp, 'simpleSign');
    expect(true).toBe(false);
  } catch (e: any) {
    expect(e.message).toContain('ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG');
  }
});

test('ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG embeds both observed flags (saml-core §3.4.1 / saml-metadata §2.4.4)', () => {
  const _idp = identityProvider({ ...defaultIdpConfig, metadata: noSignedIdpMetadata });
  try {
    sp.createLoginRequest(_idp, 'redirect');
    expect(true).toBe(false);
  } catch (e: any) {
    expect(e.message).toContain('ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG');
    expect(e.message).toContain('AuthnRequestsSigned=');
    expect(e.message).toContain('WantAuthnRequestsSigned=');
  }
});

test('create login request with redirect binding using [custom template]', () => {
  const _sp = serviceProvider({
    ...defaultSpConfig, loginRequestTemplate: {
      context: '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="{AllowCreate}"/></samlp:AuthnRequest>',
    },
  });
  const { id, context } = _sp.createLoginRequest(idp, 'redirect', template => {
    return {
      id: 'exposed_testing_id',
      context: template, // all the tags are supposed to be replaced
    };
  });
  (id === 'exposed_testing_id' && isString(context)) ? expect(true).toBe(true) : expect(true).toBe(false);
});

test('create login request with redirect binding signing with unencrypted PKCS#8', () => {
  const _sp = serviceProvider({
    authnRequestsSigned: true,
    signingCert: readFileSync('./test/key/sp/cert.unencrypted.pkcs8.cer'),
    privateKey: readFileSync('./test/key/sp/privkey.unencrypted.pkcs8.pem'),
    privateKeyPass: undefined,
  });

  const { context } = _sp.createLoginRequest(idp, 'redirect');

  const parsed = parseRedirectUrlContextCallBack(context)
  const signature =  Buffer.from(parsed.query.Signature as string, 'base64');

  const valid = libsaml.verifyMessageSignature(_sp.entityMeta, parsed.octetString, signature, parsed.query.SigAlg as string);
  expect(valid).toBe(true);
});

test('create login request with redirect binding signing with encrypted PKCS#8', () => {
  const _sp = serviceProvider({
    authnRequestsSigned: true,
    signingCert: readFileSync('./test/key/sp/cert.encrypted.pkcs8.cer'),
    privateKey: readFileSync('./test/key/sp/privkey.encrypted.pkcs8.pem'),
    privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
  });

  const { context } = _sp.createLoginRequest(idp, 'redirect');

  const parsed = parseRedirectUrlContextCallBack(context)
  const signature =  Buffer.from(parsed.query.Signature as string, 'base64');

  const valid = libsaml.verifyMessageSignature(_sp.entityMeta, parsed.octetString, signature, parsed.query.SigAlg as string);
  expect(valid).toBe(true);
});

test('create login request with post binding using [custom template]', () => {
  const _sp = serviceProvider({
    ...defaultSpConfig, loginRequestTemplate: {
      context: '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="{AllowCreate}"/></samlp:AuthnRequest>',
    },
  });
  const { id, context, entityEndpoint, type, relayState } = _sp.createLoginRequest(idp, 'post', template => {
    return {
      id: 'exposed_testing_id',
      context: template, // all the tags are supposed to be replaced
    };
  }) as PostBindingContext;
  id === 'exposed_testing_id' &&
    isString(context) &&
    isString(relayState) &&
    isString(entityEndpoint) &&
    type === 'SAMLRequest'
    ? expect(true).toBe(true) : expect(true).toBe(false);
});

test('create login request with post simpleSign binding using [custom template]', () => {
  const _sp = serviceProvider({
    ...defaultSpConfig, loginRequestTemplate: {
      context: '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="{AllowCreate}"/></samlp:AuthnRequest>',
    },
  });
  const { id, context, entityEndpoint, type, relayState, signature, sigAlg } = _sp.createLoginRequest(idp, 'simpleSign', template => {
    return {
      id: 'exposed_testing_id',
      context: template, // all the tags are supposed to be replaced
    };
  }) as SimpleSignBindingContext;
  id === 'exposed_testing_id' &&
    isString(context) &&
    isString(relayState) &&
    isString(entityEndpoint) &&
    isString(signature) &&
    isString(sigAlg) &&
    type === 'SAMLRequest'
    ? expect(true).toBe(true) : expect(true).toBe(false);
});

test('create login response with undefined binding', async () => {
  const user = { email: 'user@esaml2.com' };
  await expect(idp.createLoginResponse(sp, {}, 'undefined', user, createTemplateCallback(idp, sp, binding.post, user))).rejects.toThrow();
  const error = await idp.createLoginResponse(sp, {}, 'undefined', user, createTemplateCallback(idp, sp, binding.post, user)).catch(e => e);
  expect(error?.message).toBe('ERR_CREATE_RESPONSE_UNDEFINED_BINDING');
});

test('create redirect login response', async () => {
  const user = { email: 'user@esaml2.com' };
  const { id, context } = await idp.createLoginResponse(sp, sampleRequestInfo, 'redirect', user, createTemplateCallback(idp, sp, binding.redirect, user), undefined, 'relaystate');
  isString(id) && isString(context) ? expect(true).toBe(true) : expect(true).toBe(false);
});

test('create post simpleSign login response', async () => {
  const user = { email: 'user@esaml2.com' };
  const { id, context, entityEndpoint, type, signature, sigAlg } = await idp.createLoginResponse(sp, sampleRequestInfo, 'simpleSign', user, createTemplateCallback(idp, sp, binding.simpleSign, user), undefined, 'relaystate') as SimpleSignBindingContext;
  isString(id) &&
    isString(context) &&
    isString(entityEndpoint) &&
    isString(signature) &&
    isString(sigAlg) ? expect(true).toBe(true) : expect(true).toBe(false);
});

test('create post login response', async () => {
  const user = { email: 'user@esaml2.com' };
  const { id, context } = await idp.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idp, sp, binding.post, user));
  isString(id) && isString(context) ? expect(true).toBe(true) : expect(true).toBe(false);
});

test('create logout request with redirect binding', () => {
  const { id, context } = sp.createLogoutRequest(idp, 'redirect', { logoutNameID: 'user@esaml2' });
  isString(id) && isString(context) ? expect(true).toBe(true) : expect(true).toBe(false);
});

test('create logout request with post binding', () => {
  const { relayState, type, entityEndpoint, id, context } = sp.createLogoutRequest(idp, 'post', { logoutNameID: 'user@esaml2' }) as PostBindingContext;
  isString(id) && isString(context) && isString(entityEndpoint) && type === 'SAMLRequest' ? expect(true).toBe(true) : expect(true).toBe(false);
});

test('create logout request when idp only has one binding', () => {
  const testIdp = identityProvider(oneloginIdpConfig);
  const { id, context } = sp.createLogoutRequest(testIdp, 'redirect', { logoutNameID: 'user@esaml2' });
  isString(id) && isString(context) ? expect(true).toBe(true) : expect(true).toBe(false);
});

test('create logout response with undefined binding', () => {
  try {
    const { id, context } = idp.createLogoutResponse(sp, {}, 'undefined', '', createTemplateCallback(idp, sp, binding.post, {}));
    expect(true).toBe(false);
  } catch (e: any) {
    expect(e.message).toBe('ERR_CREATE_LOGOUT_RESPONSE_UNDEFINED_BINDING');
  }
});

test('create logout response with redirect binding', () => {
  const { id, context } = idp.createLogoutResponse(sp, {}, 'redirect', '', createTemplateCallback(idp, sp, binding.post, {}));
  isString(id) && isString(context) ? expect(true).toBe(true) : expect(true).toBe(false);
});

test('create logout response with post binding', () => {
  const { relayState, type, entityEndpoint, id, context } = idp.createLogoutResponse(sp, {}, 'post', '', createTemplateCallback(idp, sp, binding.post, {})) as PostBindingContext;
  isString(id) && isString(context) && isString(entityEndpoint) && type === 'SAMLResponse' ? expect(true).toBe(true) : expect(true).toBe(false);
});

// Check if the response data parsing is correct
// All test cases are using customize template

// simulate idp-initiated sso
test('send response with signed assertion and parse it', async () => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, sp, binding.post, user));
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await sp.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse } });
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

describe('login response must be addressed to the receiving SP', () => {
  const user = { email: 'user@esaml2.com' };
  const acs = acsOf(sp, binding.post) as string;
  // Rewrite the unsigned template output before the IdP signs it.
  const issue = async (rewrite: (xml: string) => string, receiver = sp) => {
    const callback = createTemplateCallback(idpNoEncrypt, receiver, binding.post, user);
    const { context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(receiver, sampleRequestInfo, 'post', user, template => {
      const result = callback(template);
      return { ...result, context: rewrite(result.context) };
    });
    return receiver.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse } });
  };
  const spEntityID = sp.entityMeta.getEntityID();

  test('rejects a response whose Audience is another SP', async () => {
    await expect(issue(xml => xml.replace(`<saml:Audience>${spEntityID}<`, '<saml:Audience>https://other-sp.example.org/metadata<')))
      .rejects.toThrow('ERR_AUDIENCE_MISMATCH');
  });

  test('rejects a response without an AudienceRestriction', async () => {
    await expect(issue(xml => xml.replace(/<saml:AudienceRestriction>.*<\/saml:AudienceRestriction>/, '')))
      .rejects.toThrow('ERR_AUDIENCE_MISMATCH');
  });

  test('accepts a response listing several audiences including this SP', async () => {
    const { extract } = await issue(xml => xml.replace(
      `<saml:Audience>${spEntityID}</saml:Audience>`,
      `<saml:Audience>https://other-sp.example.org/metadata</saml:Audience><saml:Audience>${spEntityID}</saml:Audience>`,
    ));
    expect(extract.audience).toEqual(['https://other-sp.example.org/metadata', spEntityID]);
  });

  test('rejects a response when any AudienceRestriction excludes this SP', async () => {
    await expect(issue(xml => xml.replace(
      '<saml:AudienceRestriction>',
      '<saml:AudienceRestriction><saml:Audience>https://other-sp.example.org/metadata</saml:Audience></saml:AudienceRestriction><saml:AudienceRestriction>',
    ))).rejects.toThrow('ERR_AUDIENCE_MISMATCH');
  });

  test('accepts a response when every AudienceRestriction includes this SP', async () => {
    const { extract } = await issue(xml => xml.replace(
      '<saml:AudienceRestriction>',
      `<saml:AudienceRestriction><saml:Audience>https://other-sp.example.org/metadata</saml:Audience><saml:Audience>${spEntityID}</saml:Audience></saml:AudienceRestriction><saml:AudienceRestriction>`,
    ));
    expect(extract.audienceRestriction).toHaveLength(2);
  });

  test('rejects a response whose SubjectConfirmationData Recipient is not an ACS of this SP', async () => {
    await expect(issue(xml => xml.replace(`Recipient="${acs}"`, 'Recipient="https://other-sp.example.org/acs"')))
      .rejects.toThrow('ERR_RECIPIENT_MISMATCH');
  });

  test('rejects a response whose Destination is not an ACS of this SP', async () => {
    await expect(issue(xml => xml.replace(`Destination="${acs}"`, 'Destination="https://other-sp.example.org/acs"')))
      .rejects.toThrow('ERR_RECIPIENT_MISMATCH');
  });

  test('exposes the signed SubjectConfirmationData on the extract', async () => {
    const { extract } = await issue(xml => xml);
    expect(extract.subjectConfirmation.recipient).toBe(acs);
    expect(extract.subjectConfirmation.inResponseTo).toBe('request_id');
  });

  test('wantAudienceCheck: false disables the audience, Destination and Recipient checks', async () => {
    const lenientSp = serviceProvider({ ...defaultSpConfig, wantAudienceCheck: false });
    const { extract } = await issue(xml => xml
      .replace(`<saml:Audience>${spEntityID}<`, '<saml:Audience>https://other-sp.example.org/metadata<')
      .replace(`Recipient="${acs}"`, 'Recipient="https://other-sp.example.org/acs"'), lenientSp);
    expect(extract.audience).toBe('https://other-sp.example.org/metadata');
  });
});

// + REDIRECT
test('send response with signed assertion by redirect and parse it', async () => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const user = { email: 'user@esaml2.com' };
  const { id, context } = await idpNoEncrypt.createLoginResponse(sp, sampleRequestInfo, 'redirect', user, createTemplateCallback(idpNoEncrypt, sp, binding.redirect, user), undefined, 'relaystate');
  const query = url.parse(context).query;
  expect(query!.includes('SAMLResponse=')).toBe(true);
  expect(query!.includes('SigAlg=')).toBe(true);
  expect(query!.includes('Signature=')).toBe(true);
  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await sp.parseLoginResponse(idpNoEncrypt, 'redirect', parseRedirectUrlContextCallBack(context) );
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

// SimpleSign
test('send response with signed assertion by post simplesign and parse it', async () => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse, type, sigAlg, signature, relayState } = await idpNoEncrypt.createLoginResponse(
    sp,
    sampleRequestInfo,
    'simpleSign',
    user,
    createTemplateCallback(idpNoEncrypt, sp, binding.simpleSign, user),
    undefined,
    'relaystate'
  ) as SimpleSignBindingContext;
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const octetString = buildSimpleSignOctetString(type, SAMLResponse, sigAlg, relayState, signature);
  const { samlContent, extract } = await sp.parseLoginResponse(idpNoEncrypt, 'simpleSign', { body: { SAMLResponse, Signature: signature, SigAlg:sigAlg }, octetString });
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send response with signed assertion + custom transformation algorithms and parse it', async () => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const signedAssertionSp = serviceProvider(
    {
      ...defaultSpConfig,
      transformationAlgorithms: [
          'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
          'http://www.w3.org/2001/10/xml-exc-c14n#'
      ]
    }
  );

  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(signedAssertionSp, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, sp, binding.post, user));
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await sp.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse } });
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.response.inResponseTo).toBe('request_id');

  // Verify xmldsig#enveloped-signature is included in the response
  if (samlContent.indexOf('http://www.w3.org/2000/09/xmldsig#enveloped-signature') === -1) {
    expect(true).toBe(false);
  }
});

test('send response with signed assertion + custom transformation algorithms by redirect and parse it', async () => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const signedAssertionSp = serviceProvider(
    {
      ...defaultSpConfig,
      transformationAlgorithms: [
          'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
          'http://www.w3.org/2001/10/xml-exc-c14n#'
      ]
    }
  );
  const user = { email: 'user@esaml2.com' };
  const { id, context } = await idpNoEncrypt.createLoginResponse(signedAssertionSp, sampleRequestInfo, 'redirect', user, createTemplateCallback(idpNoEncrypt, signedAssertionSp, binding.redirect, user), undefined, 'relaystate');
  const query = url.parse(context).query;
  expect(query!.includes('SAMLResponse=')).toBe(true);
  expect(query!.includes('SigAlg=')).toBe(true);
  expect(query!.includes('Signature=')).toBe(true);
  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await signedAssertionSp.parseLoginResponse(idpNoEncrypt, 'redirect', parseRedirectUrlContextCallBack(context) );
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.response.inResponseTo).toBe('request_id');

  // Verify xmldsig#enveloped-signature is included in the response
  if (samlContent.indexOf('http://www.w3.org/2000/09/xmldsig#enveloped-signature') === -1) {
    expect(true).toBe(false);
  }
});

test('send response with signed assertion + custom transformation algorithms by post simplesign and parse it', async () => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const signedAssertionSp = serviceProvider(
    {
      ...defaultSpConfig,
      transformationAlgorithms: [
          'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
          'http://www.w3.org/2001/10/xml-exc-c14n#'
      ]
    }
  );

  const user = { email: 'user@esaml2.com' }
  const { id, context: SAMLResponse, type, sigAlg, signature, relayState } = await idpNoEncrypt.createLoginResponse(
    signedAssertionSp,
    sampleRequestInfo,
    'simpleSign',
    user,
    createTemplateCallback(idpNoEncrypt, sp, binding.simpleSign, user),
    undefined,
    'relaystate'
    ) as SimpleSignBindingContext;
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const octetString = buildSimpleSignOctetString(type, SAMLResponse, sigAlg, relayState, signature);
  const { samlContent, extract } = await sp.parseLoginResponse(idpNoEncrypt, 'simpleSign', { body: { SAMLResponse, Signature: signature, SigAlg:sigAlg }, octetString });
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.response.inResponseTo).toBe('request_id');

  // Verify xmldsig#enveloped-signature is included in the response
  if (samlContent.indexOf('http://www.w3.org/2000/09/xmldsig#enveloped-signature') === -1) {
    expect(true).toBe(false);
  }
});

test('send response with [custom template] signed assertion and parse it', async () => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const requestInfo = { extract: { request: { id: 'request_id' } } };
  const user = { email: 'user@esaml2.com'};
  const { id, context: SAMLResponse } = await idpcustomNoEncrypt.createLoginResponse(
    sp,
    requestInfo,
    'post',
    user,
    // declare the callback to do custom template replacement
    createTemplateCallback(idpcustomNoEncrypt, sp, binding.post, user),
  );
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await sp.parseLoginResponse(idpcustomNoEncrypt, 'post', { body: { SAMLResponse } });
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.attributes.name).toBe('mynameinsp');
  expect(extract.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send response with [custom template] signed assertion by redirect and parse it', async () => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const requestInfo = { extract: { request: { id: 'request_id' } } };
  const user = { email: 'user@esaml2.com' };
  const { id, context } = await idpcustomNoEncrypt.createLoginResponse(
    sp,
    requestInfo,
    'redirect',
    user,
    createTemplateCallback(idpcustomNoEncrypt, sp, binding.redirect, user),
    undefined,
    'relaystate'
    );
  const query = url.parse(context).query;
  expect(query!.includes('SAMLResponse=')).toBe(true);
  expect(query!.includes('SigAlg=')).toBe(true);
  expect(query!.includes('Signature=')).toBe(true);
  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await sp.parseLoginResponse(idpcustomNoEncrypt, 'redirect', parseRedirectUrlContextCallBack(context));
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.attributes.name).toBe('mynameinsp');
  expect(extract.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send response with [custom template] signed assertion by post simpleSign and parse it', async () => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const requestInfo = { extract: { request: { id: 'request_id' } } };
  const user = { email: 'user@esaml2.com'};
  const { id, context: SAMLResponse, type, sigAlg, signature, entityEndpoint, relayState } = await idpcustomNoEncrypt.createLoginResponse(
    sp,
    requestInfo,
    'simpleSign',
    user,
    // declare the callback to do custom template replacement
    createTemplateCallback(idpcustomNoEncrypt, sp, binding.simpleSign, user),
    undefined,
    'relaystate'
  ) as SimpleSignBindingContext;
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const octetString = buildSimpleSignOctetString(type, SAMLResponse, sigAlg, relayState, signature);
  const { samlContent, extract } = await sp.parseLoginResponse(idpcustomNoEncrypt, 'simpleSign', { body: { SAMLResponse, Signature: signature, SigAlg:sigAlg }, octetString });
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(entityEndpoint).toBe('https://sp.example.org/sp/sso');
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.attributes.name).toBe('mynameinsp');
  expect(extract.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send response with signed message and parse it', async () => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(spNoAssertSign, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, spNoAssertSign, binding.post, user));
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spNoAssertSign.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse } });
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send response with signed message by redirect and parse it', async () => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const requestInfo = { extract: { request: { id: 'request_id' } } };
  const user = { email: 'user@esaml2.com' };
  const { id, context } = await idpNoEncrypt.createLoginResponse(
    spNoAssertSign,
    requestInfo,
    'redirect',
    user,
    createTemplateCallback(idpNoEncrypt, spNoAssertSign, binding.redirect, user),
    undefined,
    'relaystate'
    );
  const query = url.parse(context).query;
  expect(query!.includes('SAMLResponse=')).toBe(true);
  expect(query!.includes('SigAlg=')).toBe(true);
  expect(query!.includes('Signature=')).toBe(true);
  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spNoAssertSign.parseLoginResponse(idpNoEncrypt, 'redirect', parseRedirectUrlContextCallBack(context) );
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send response with signed message by post simplesign and parse it', async () => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse, type, sigAlg, signature, relayState } = await idpNoEncrypt.createLoginResponse(
    spNoAssertSign,
    sampleRequestInfo,
    'simpleSign',
    user,
    createTemplateCallback(idpNoEncrypt, spNoAssertSign, binding.simpleSign, user),
    undefined,
    'relaystate'
  ) as SimpleSignBindingContext;
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const octetString = buildSimpleSignOctetString(type, SAMLResponse, sigAlg, relayState, signature);
  const { samlContent, extract } = await spNoAssertSign.parseLoginResponse(idpNoEncrypt, 'simpleSign', { body: { SAMLResponse, Signature: signature, SigAlg:sigAlg }, octetString });
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send response with [custom template] and signed message and parse it', async () => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const requestInfo = { extract: { authnrequest: { id: 'request_id' } } };
  const user = { email: 'user@esaml2.com'};
  const { id, context: SAMLResponse } = await idpcustomNoEncrypt.createLoginResponse(
    spNoAssertSign,
    { extract: { authnrequest: { id: 'request_id' } } }, 'post',
    { email: 'user@esaml2.com' },
    createTemplateCallback(idpcustomNoEncrypt, spNoAssertSign, binding.post, user),
  );
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spNoAssertSign.parseLoginResponse(idpcustomNoEncrypt, 'post', { body: { SAMLResponse } });
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.attributes.name).toBe('mynameinsp');
  expect(extract.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send response with [custom template] and signed message by redirect and parse it', async () => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const requestInfo = { extract: { request: { id: 'request_id' } } };
  const user = { email: 'user@esaml2.com' };
  const { id, context } = await idpcustomNoEncrypt.createLoginResponse(
    spNoAssertSign,
    requestInfo,
    'redirect',
    user,
    createTemplateCallback(idpcustomNoEncrypt, spNoAssertSign, binding.redirect, user),
    undefined,
    'relaystate'
    );
  const query = url.parse(context).query;
  expect(query!.includes('SAMLResponse=')).toBe(true);
  expect(query!.includes('SigAlg=')).toBe(true);
  expect(query!.includes('Signature=')).toBe(true);
  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spNoAssertSign.parseLoginResponse(idpcustomNoEncrypt, 'redirect', parseRedirectUrlContextCallBack(context) );
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.attributes.name).toBe('mynameinsp');
  expect(extract.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send response with [custom template] and signed message by post simplesign and parse it', async () => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const requestInfo = { extract: { authnrequest: { id: 'request_id' } } };
  const user = { email: 'user@esaml2.com'};
  const { id, context: SAMLResponse, type, sigAlg, signature, relayState } = await idpcustomNoEncrypt.createLoginResponse(
    spNoAssertSign,
    { extract: { authnrequest: { id: 'request_id' } } }, 'simpleSign',
    { email: 'user@esaml2.com' },
    createTemplateCallback(idpcustomNoEncrypt, spNoAssertSign, binding.simpleSign, user),
    undefined,
    'relaystate'
  ) as SimpleSignBindingContext;
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const octetString = buildSimpleSignOctetString(type, SAMLResponse, sigAlg, relayState, signature);
  const { samlContent, extract } = await spNoAssertSign.parseLoginResponse(idpcustomNoEncrypt, 'simpleSign', { body: { SAMLResponse, Signature: signature, SigAlg:sigAlg }, octetString });
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.attributes.name).toBe('mynameinsp');
  expect(extract.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send login response with signed assertion + signed message and parse it', async () => {
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(spWantMessageSign, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, spWantMessageSign, binding.post, user));
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spWantMessageSign.parseLoginResponse (idpNoEncrypt, 'post', { body: { SAMLResponse } });
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send response with signed assertion + signed message by redirect and parse it', async () => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });
  const requestInfo = { extract: { request: { id: 'request_id' } } };
  const user = { email: 'user@esaml2.com' };
  const { id, context } = await idpNoEncrypt.createLoginResponse(
    spWantMessageSign,
    requestInfo,
    'redirect',
    user,
    createTemplateCallback(idpNoEncrypt, spWantMessageSign, binding.redirect, user),
    undefined,
    'relaystate'
    );
  const query = url.parse(context).query;
  expect(query!.includes('SAMLResponse=')).toBe(true);
  expect(query!.includes('SigAlg=')).toBe(true);
  expect(query!.includes('Signature=')).toBe(true);
  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spWantMessageSign.parseLoginResponse(idpNoEncrypt, 'redirect', parseRedirectUrlContextCallBack(context) );
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send login response with signed assertion + signed message by post simplesign and parse it', async () => {
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse, type, sigAlg, signature, relayState } = await idpNoEncrypt.createLoginResponse(spWantMessageSign, sampleRequestInfo,
    'simpleSign', user,
    createTemplateCallback(idpNoEncrypt, spWantMessageSign, binding.simpleSign, user),
    undefined,
    'relaystate'
  ) as SimpleSignBindingContext;
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const octetString = buildSimpleSignOctetString(type, SAMLResponse, sigAlg, relayState, signature);
  const { samlContent, extract } = await spWantMessageSign.parseLoginResponse (idpNoEncrypt, 'simpleSign', { body: { SAMLResponse, Signature: signature, SigAlg:sigAlg }, octetString });
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send login response with [custom template] and signed assertion + signed message and parse it', async () => {
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });
  const user = { email: 'user@esaml2.com'};
  const { id, context: SAMLResponse } = await idpcustomNoEncrypt.createLoginResponse(
    spWantMessageSign,
    { extract: { authnrequest: { id: 'request_id' } } }, 'post',
    { email: 'user@esaml2.com' },
    createTemplateCallback(idpcustomNoEncrypt, spWantMessageSign, binding.post, user),
  );
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spWantMessageSign.parseLoginResponse(idpcustomNoEncrypt, 'post', { body: { SAMLResponse } });
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.attributes.name).toBe('mynameinsp');
  expect(extract.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send response with [custom template] and signed assertion + signed message by redirect and parse it', async () => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });
  const requestInfo = { extract: { request: { id: 'request_id' } } };
  const user = { email: 'user@esaml2.com' };
  const { id, context } = await idpcustomNoEncrypt.createLoginResponse(
    spWantMessageSign,
    requestInfo,
    'redirect',
    user,
    createTemplateCallback(idpcustomNoEncrypt, spWantMessageSign, binding.redirect, user),
    undefined,
    'relaystate'
    );
  const query = url.parse(context).query;
  expect(query!.includes('SAMLResponse=')).toBe(true);
  expect(query!.includes('SigAlg=')).toBe(true);
  expect(query!.includes('Signature=')).toBe(true);
  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spWantMessageSign.parseLoginResponse(idpcustomNoEncrypt, 'redirect', parseRedirectUrlContextCallBack(context) );
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.attributes.name).toBe('mynameinsp');
  expect(extract.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send login response with [custom template] and signed assertion + signed message by post simplesign and parse it', async () => {
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });
  const user = { email: 'user@esaml2.com'};
  const { id, context: SAMLResponse, type, sigAlg, signature, relayState } = await idpcustomNoEncrypt.createLoginResponse(
    spWantMessageSign,
    { extract: { authnrequest: { id: 'request_id' } } },
    'simpleSign',
    { email: 'user@esaml2.com' },
    createTemplateCallback(idpcustomNoEncrypt, spWantMessageSign, binding.simpleSign, user),
    undefined,
    'relaystate'
  ) as SimpleSignBindingContext;
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const octetString = buildSimpleSignOctetString(type, SAMLResponse, sigAlg, relayState, signature);
  const { samlContent, extract } = await spWantMessageSign.parseLoginResponse(idpcustomNoEncrypt, 'simpleSign', { body: { SAMLResponse, Signature: signature, SigAlg:sigAlg }, octetString });
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.attributes.name).toBe('mynameinsp');
  expect(extract.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send login response with encrypted non-signed assertion and parse it', async () => {
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idp.createLoginResponse(spNoAssertSign, sampleRequestInfo, 'post', user, createTemplateCallback(idp, spNoAssertSign, binding.post, user));
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spNoAssertSign.parseLoginResponse(idp, 'post', { body: { SAMLResponse } });
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send login response with encrypted signed assertion and parse it', async () => {
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idp.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idp, sp, binding.post, user));
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await sp.parseLoginResponse(idp, 'post', { body: { SAMLResponse } });
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send login response with [custom template] and encrypted signed assertion and parse it', async () => {
  const user = { email: 'user@esaml2.com'};
  const { id, context: SAMLResponse } = await idpcustom.createLoginResponse(
    sp,
    { extract: { request: { id: 'request_id' } } }, 'post',
    { email: 'user@esaml2.com' },
    createTemplateCallback(idpcustom, sp, binding.post, user),
  );
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await sp.parseLoginResponse(idpcustom, 'post', { body: { SAMLResponse } });
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.attributes.name).toBe('mynameinsp');
  expect(extract.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send login response with encrypted signed assertion + signed message and parse it', async () => {
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idp.createLoginResponse(spWantMessageSign, sampleRequestInfo, 'post', user, createTemplateCallback(idp, spWantMessageSign, binding.post, user));
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spWantMessageSign.parseLoginResponse(idp, 'post', { body: { SAMLResponse } });

  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send login response with [custom template] encrypted signed assertion + signed message and parse it', async () => {
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });
  const requestInfo = { extract: { authnrequest: { id: 'request_id' } } };
  const user = { email: 'user@esaml2.com'};
  const { id, context: SAMLResponse } = await idpcustom.createLoginResponse(
    spWantMessageSign,
    { extract: { authnrequest: { id: 'request_id' } } }, 'post',
    { email: 'user@esaml2.com' },
    createTemplateCallback(idpcustom, spWantMessageSign, binding.post, user),
  );
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spWantMessageSign.parseLoginResponse(idpcustom, 'post', { body: { SAMLResponse } });
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.attributes.name).toBe('mynameinsp');
  expect(extract.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

// simulate idp-init slo
test('idp sends a redirect logout request without signature and sp parses it', async () => {
  const { id, context } = idp.createLogoutRequest(sp, 'redirect', { logoutNameID: 'user@esaml2.com' });
  const query = url.parse(context).query;
  expect(query!.includes('SAMLRequest=')).toBe(true);
  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');
  const originalURL = url.parse(context, true);
  const SAMLRequest = encodeURIComponent(originalURL.query.SAMLRequest as string);
  let result;
  const { samlContent, extract } = result = await sp.parseLogoutRequest(idp, 'redirect', { query: { SAMLRequest }});
  expect(result.sigAlg).toBe(null);
  expect(typeof samlContent).toBe('string');
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.signature).toBe(null);
  expect(typeof extract.request.id).toBe('string');
  expect(extract.request.destination).toBe('https://sp.example.org/sp/slo');
  expect(extract.issuer).toBe('https://idp.example.com/metadata');
});

test('idp sends a redirect logout request with signature and sp parses it', async () => {
  const { id, context } = idp.createLogoutRequest(spWantLogoutReqSign, 'redirect', { logoutNameID: 'user@esaml2.com' });
  const query = url.parse(context).query;
  expect(query!.includes('SAMLRequest=')).toBe(true);
  expect(query!.includes('SigAlg=')).toBe(true);
  expect(query!.includes('Signature=')).toBe(true);
  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');
  const originalURL = url.parse(context, true);
  const SAMLRequest = originalURL.query.SAMLRequest;
  const Signature = originalURL.query.Signature;
  const SigAlg = originalURL.query.SigAlg;
  delete originalURL.query.Signature;
  const octetString = Object.keys(originalURL.query).map(q => q + '=' + encodeURIComponent(originalURL.query[q] as string)).join('&');
  const { extract } = await spWantLogoutReqSign.parseLogoutRequest(idp, 'redirect', { query: { SAMLRequest, Signature, SigAlg }, octetString});
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.issuer).toBe('https://idp.example.com/metadata');
  expect(typeof extract.request.id).toBe('string');
  expect(extract.request.destination).toBe('https://sp.example.org/sp/slo');
  expect(extract.signature).toBe(null); // redirect binding doesn't embed the signature
});

test('idp sends a post logout request without signature and sp parses it', async () => {
  const { type, entityEndpoint, id, context } = idp.createLogoutRequest(sp, 'post', { logoutNameID: 'user@esaml2.com' }) as PostBindingContext;
  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');
  expect(typeof entityEndpoint).toBe('string');
  expect(type).toBe('SAMLRequest');
  const { extract } = await sp.parseLogoutRequest(idp, 'post', { body: { SAMLRequest: context } });
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.issuer).toBe('https://idp.example.com/metadata');
  expect(typeof extract.request.id).toBe('string');
  expect(extract.request.destination).toBe('https://sp.example.org/sp/slo');
  expect(extract.signature).toBe(null);
});

test('idp sends a post logout request with signature and sp parses it', async () => {
  const { type, entityEndpoint, id, context } = idp.createLogoutRequest(spWantLogoutReqSign, 'post', { logoutNameID: 'user@esaml2.com' }) as PostBindingContext;
  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');
  expect(typeof entityEndpoint).toBe('string');
  expect(type).toBe('SAMLRequest');
  const { extract } = await spWantLogoutReqSign.parseLogoutRequest(idp, 'post', { body: { SAMLRequest: context } });
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.issuer).toBe('https://idp.example.com/metadata');
  expect(extract.request.destination).toBe('https://sp.example.org/sp/slo');
  expect(typeof extract.request.id).toBe('string');
  expect(typeof extract.signature).toBe('string');
});

// simulate init-slo
test('sp sends a post logout response without signature and parse', async () => {
  // saml-bindings §3.5 — no callback supplied so the binding builder uses
  // its built-in default template (with the SP as Issuer). Previously this
  // test passed a login-response callback that the binding silently
  // ignored; after #549 such a callback would actually fire and fill
  // Issuer with the IdP's entity ID, breaking the issuer match.
  const { context: SAMLResponse } = sp.createLogoutResponse(idp, sampleRequestInfo, 'post', '') as PostBindingContext;
  const { extract } = await idp.parseLogoutResponse(sp, 'post', { body: { SAMLResponse }});
  expect(extract.signature).toBe(null);
  expect(extract.issuer).toBe('https://sp.example.org/metadata');
  expect(typeof extract.response.id).toBe('string');
  expect(extract.response.destination).toBe('https://idp.example.org/sso/SingleLogoutService');
});

test('sp sends a post logout response with signature and parse', async () => {
  // See note above (#549).
  const { relayState, type, entityEndpoint, id, context: SAMLResponse } = sp.createLogoutResponse(idpWantLogoutResSign, sampleRequestInfo, 'post', '') as PostBindingContext;
  const { samlContent, extract } = await idpWantLogoutResSign.parseLogoutResponse(sp, 'post', { body: { SAMLResponse }});
  expect(typeof extract.signature).toBe('string');
  expect(extract.issuer).toBe('https://sp.example.org/metadata');
  expect(typeof extract.response.id).toBe('string');
  expect(extract.response.destination).toBe('https://idp.example.org/sso/SingleLogoutService');
});

test('send login response with encrypted non-signed assertion with EncryptThenSign and parse it', async () => {
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idpEncryptThenSign.createLoginResponse(spNoAssertSignCustomConfig, sampleRequestInfo, 'post', user, createTemplateCallback(idpEncryptThenSign, spNoAssertSignCustomConfig, binding.post, user), true);
  const { samlContent, extract } = await spNoAssertSignCustomConfig.parseLoginResponse(idpEncryptThenSign, 'post', { body: { SAMLResponse } });
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
});

test('Customize prefix (saml2) for encrypted assertion tag', async () => {
  const user = { email: 'test@email.com' };
  const idpCustomizePfx = identityProvider(Object.assign(defaultIdpConfig, { tagPrefix: {
    encryptedAssertion: 'saml2',
  }}));
  const { id, context: SAMLResponse } = await idpCustomizePfx.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idpCustomizePfx, sp, binding.post, user));
  expect((utility.base64Decode(SAMLResponse) as string).includes('saml2:EncryptedAssertion')).toBe(true);
  const { samlContent, extract } = await sp.parseLoginResponse(idpCustomizePfx, 'post', { body: { SAMLResponse } });
});

test('Customize prefix (default is saml) for encrypted assertion tag', async () => {
  const user = { email: 'test@email.com' };
  const { id, context: SAMLResponse } = await idp.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idp, sp, binding.post, user));
  expect((utility.base64Decode(SAMLResponse) as string).includes('saml:EncryptedAssertion')).toBe(true);
  const { samlContent, extract } = await sp.parseLoginResponse(idp, 'post', { body: { SAMLResponse } });
});

test('avoid malformatted response', async () => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const user = { email: 'user@email.com' };
  const { context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, sp, binding.post, user));
  const rawResponse = String(utility.base64Decode(SAMLResponse, true));
  const attackResponse = `<NameID>evil@evil.com${rawResponse}</NameID>`;
  try {
    await sp.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse: utility.base64Encode(attackResponse) } });
    expect(true).toBe(false);
  } catch (e) {
    // it must throw an error
    expect(true).toBe(true);
  }
});

test('avoid malformatted response with redirect binding', async () => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const user = { email: 'user@email.com' };
  const { id, context } = await idpNoEncrypt.createLoginResponse(sp, sampleRequestInfo, 'redirect', user, createTemplateCallback(idpNoEncrypt, sp, binding.redirect, user), undefined, '');
  const originalURL = url.parse(context, true);
  const SAMLResponse = originalURL.query.SAMLResponse;
  const signature = originalURL.query.Signature;
  const sigAlg = originalURL.query.SigAlg;
  delete originalURL.query.Signature;

  const rawResponse = utility.inflateString(SAMLResponse as string);
  const attackResponse = `<NameID>evil@evil.com${rawResponse}</NameID>`;
  const octetString = 'SAMLResponse=' + encodeURIComponent(utility.base64Encode(utility.deflateString(attackResponse))) + '&SigAlg=' + encodeURIComponent(sigAlg as string);
  try {
    await sp.parseLoginResponse(idpNoEncrypt, 'redirect', { query :{ SAMLResponse, SigAlg: sigAlg, Signature: signature}, octetString });
    expect(true).toBe(false);
  } catch (e) {
    // it must throw an error
    expect(true).toBe(true);
  }
});

test('avoid malformatted response with simplesign binding', async () => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const user = { email: 'user@email.com' };
  const { context: SAMLResponse, type, sigAlg, signature, relayState } = await idpNoEncrypt.createLoginResponse(sp, sampleRequestInfo, 'simpleSign', user, createTemplateCallback(idpNoEncrypt, sp, binding.simpleSign, user), undefined, 'relaystate');
  const rawResponse = String(utility.base64Decode(SAMLResponse, true));
  const attackResponse = `<NameID>evil@evil.com${rawResponse}</NameID>`;
  const octetString = buildSimpleSignOctetString(type, SAMLResponse, sigAlg, relayState, signature);
  try {
    await sp.parseLoginResponse(idpNoEncrypt, 'simpleSign', { body: { SAMLResponse: utility.base64Encode(attackResponse), Signature: signature, SigAlg:sigAlg }, octetString });
    expect(true).toBe(false);
  } catch (e) {
    // it must throw an error
    expect(true).toBe(true);
  }
});

test('should reject signature wrapped response - case 1', async () => {
  //
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, sp, binding.post, user));
  //Decode
  const buffer = Buffer.from(SAMLResponse, 'base64');
  const xml = buffer.toString();
  //Create version of response without signature
  const stripped = xml
    .replace(/<ds:Signature[\s\S]*ds:Signature>/, '');
  //Create version of response with altered IDs and new username
  const outer = xml
    .replace(/assertion" ID="_[0-9a-f]{3}/g, 'assertion" ID="_000')
    .replace('user@esaml2.com', 'admin@esaml2.com');
  //Put stripped version under SubjectConfirmationData of modified version
  const xmlWrapped = outer.replace(/<saml:SubjectConfirmationData[^>]*\/>/, '<saml:SubjectConfirmationData>' + stripped.replace('<?xml version="1.0" encoding="UTF-8"?>', '') + '</saml:SubjectConfirmationData>');
  const wrappedResponse = Buffer.from(xmlWrapped).toString('base64');
  try {
    await sp.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse: wrappedResponse } });
    expect(true).toBe(false);
  } catch (e: any) {
    expect(e.message).toBe('ERR_POTENTIAL_WRAPPING_ATTACK');
  }
});

test('should use signed contents in signature wrapped response - case 2', async () => {
  //
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, sp, binding.post, user));
  //Decode
  const buffer = Buffer.from(SAMLResponse, 'base64');
  const xml = buffer.toString();
  //Create version of response without signature
  const stripped = xml
    .replace(/<ds:Signature[\s\S]*ds:Signature>/, '');
  //Create version of response with altered IDs and new username
  const outer = xml
    .replace(/assertion" ID="_[0-9a-f]{3}/g, 'assertion" ID="_000')
    .replace('user@esaml2.com', 'admin@esaml2.com');
  //Put stripped version under SubjectConfirmationData of modified version
  const xmlWrapped = outer.replace(/<\/saml:Conditions>/, '</saml:Conditions><saml:Advice>' + stripped.replace('<?xml version="1.0" encoding="UTF-8"?>', '') + '</saml:Advice>');
  const wrappedResponse = Buffer.from(xmlWrapped).toString('base64');
  // The genuine signature now sits under an assertion it does not sign.
  await expect(sp.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse: wrappedResponse } }))
    .rejects.toThrow('ERR_POTENTIAL_WRAPPING_ATTACK');
});

test('should throw two-tiers code error when the response does not return success status', async () => {
  try {
    await sp.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse: utility.base64Encode(failedResponse) } });
    expect(true).toBe(false);
  } catch (e: any) {
    expect(e.message).toBe('ERR_FAILED_STATUS with top tier code: urn:oasis:names:tc:SAML:2.0:status:Requester, second tier code: urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy');
  }
});

test('should throw two-tiers code error when the response by redirect does not return success status', async () => {
  try {
    const SAMLResponse = utility.base64Encode(utility.deflateString(failedResponse));
    const sigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    const encodedSigAlg = encodeURIComponent(sigAlg);
    const octetString = 'SAMLResponse=' + encodeURIComponent(SAMLResponse) + '&SigAlg=' + encodedSigAlg;
    await sp.parseLoginResponse(idpNoEncrypt, 'redirect',{ query :{ SAMLResponse, SigAlg: encodedSigAlg} , octetString}   );
    expect(true).toBe(false);
  } catch (e: any) {
    expect(e.message).toBe('ERR_FAILED_STATUS with top tier code: urn:oasis:names:tc:SAML:2.0:status:Requester, second tier code: urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy');
  }
});

test('should throw two-tiers code error when the response over simpleSign does not return success status', async () => {
  try {
    await sp.parseLoginResponse(idpNoEncrypt, 'simpleSign', { body: { SAMLResponse: utility.base64Encode(failedResponse) } });
    expect(true).toBe(false);
  } catch (e: any) {
    expect(e.message).toBe('ERR_FAILED_STATUS with top tier code: urn:oasis:names:tc:SAML:2.0:status:Requester, second tier code: urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy');
  }
});

test.sequential('should throw ERR_SUBJECT_UNCONFIRMED for the expired SAML response without clock drift setup', async () => {

  const now = new Date();
  const fiveMinutesOneSecLater = new Date(now.getTime());
  fiveMinutesOneSecLater.setMinutes(fiveMinutesOneSecLater.getMinutes() + 5);
  fiveMinutesOneSecLater.setSeconds(fiveMinutesOneSecLater.getSeconds() + 1);

  const user = { email: 'user@esaml2.com' };

  try {
    const { context: SAMLResponse } = await idp.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idp, sp, binding.post, user));
    // simulate the time on client side when response arrives after 5.1 sec
    tk.freeze(fiveMinutesOneSecLater);
    await sp.parseLoginResponse(idp, 'post', { body: { SAMLResponse } });
    // test failed, it shouldn't happen
    expect(true).toBe(false);
  } catch (e: any) {
    expect(e.message).toBe('ERR_SUBJECT_UNCONFIRMED');
  } finally {
    tk.reset();
  }
});

test.sequential('should throw ERR_SUBJECT_UNCONFIRMED for the expired SAML response by redirect without clock drift setup', async () => {

  const now = new Date();
  const fiveMinutesOneSecLater = new Date(now.getTime());
  fiveMinutesOneSecLater.setMinutes(fiveMinutesOneSecLater.getMinutes() + 5);
  fiveMinutesOneSecLater.setSeconds(fiveMinutesOneSecLater.getSeconds() + 1);

  const user = { email: 'user@esaml2.com' };

  try {
    const { context: SAMLResponse } = await idp.createLoginResponse(sp, sampleRequestInfo, 'redirect', user, createTemplateCallback(idp, sp, binding.redirect, user), undefined, 'relaystate');
    // simulate the time on client side when response arrives after 5.1 sec
    tk.freeze(fiveMinutesOneSecLater);
    await sp.parseLoginResponse(idp, 'redirect', parseRedirectUrlContextCallBack(SAMLResponse));
    // test failed, it shouldn't happen
    expect(true).toBe(false);
  } catch (e: any) {
    expect(e.message).toBe('ERR_SUBJECT_UNCONFIRMED');
  } finally {
    tk.reset();
  }
});

test.sequential('should throw ERR_SUBJECT_UNCONFIRMED for the expired SAML response by simpleSign without clock drift setup', async () => {

  const now = new Date();
  const fiveMinutesOneSecLater = new Date(now.getTime() + 301_000);

  const user = { email: 'user@esaml2.com' };

  try {
    const { context: SAMLResponse, type, sigAlg, signature, relayState } = await idp.createLoginResponse(sp, sampleRequestInfo, 'simpleSign', user, createTemplateCallback(idp, sp, binding.simpleSign, user), undefined, 'relaystate');
    const octetString = buildSimpleSignOctetString(type, SAMLResponse, sigAlg, relayState, signature);
    // simulate the time on client side when response arrives after 5.1 sec
    tk.freeze(fiveMinutesOneSecLater);
    await sp.parseLoginResponse(idp, 'simpleSign', { body: { SAMLResponse, Signature: signature, SigAlg:sigAlg }, octetString });
    // test failed, it shouldn't happen
    expect(true).toBe(false);
  } catch (e: any) {
    expect(e.message).toBe('ERR_SUBJECT_UNCONFIRMED');
  } finally {
    tk.reset();
  }
});

test.sequential('should not throw ERR_SUBJECT_UNCONFIRMED for the expired SAML response with clock drift setup', async () => {

  const now = new Date();
  const fiveMinutesOneSecLater = new Date(now.getTime() + 301_000);
  const user = { email: 'user@esaml2.com' };

  try {
    const { context: SAMLResponse } = await idp.createLoginResponse(spWithClockDrift, sampleRequestInfo, 'post', user, createTemplateCallback(idp, spWithClockDrift, binding.post, user));
    // simulate the time on client side when response arrives after 5.1 sec
    tk.freeze(fiveMinutesOneSecLater);
    await spWithClockDrift.parseLoginResponse(idp, 'post', { body: { SAMLResponse } });
    expect(true).toBe(true);
  } catch (e) {
    // test failed, it shouldn't happen
    expect(true).toBe(false);
  } finally {
    tk.reset();
  }

});

test.sequential('should not throw ERR_SUBJECT_UNCONFIRMED for the expired SAML response by redirect with clock drift setup', async () => {

  const now = new Date();
  const fiveMinutesOneSecLater = new Date(now.getTime() + 301_000);
  const user = { email: 'user@esaml2.com' };

  try {
    const { context: SAMLResponse } = await idp.createLoginResponse(spWithClockDrift, sampleRequestInfo, 'redirect', user, createTemplateCallback(idp, spWithClockDrift, binding.redirect, user), undefined, '');
    // simulate the time on client side when response arrives after 5.1 sec
    tk.freeze(fiveMinutesOneSecLater);
    await spWithClockDrift.parseLoginResponse(idp, 'redirect', parseRedirectUrlContextCallBack(SAMLResponse));
    expect(true).toBe(true);
  } catch (e) {
    // test failed, it shouldn't happen
    expect(true).toBe(false);
  } finally {
    tk.reset();
  }

});

test.sequential('should not throw ERR_SUBJECT_UNCONFIRMED for the expired SAML response by simpleSign with clock drift setup', async () => {

  const now = new Date();
  const fiveMinutesOneSecLater = new Date(now.getTime() + 301_000);
  const user = { email: 'user@esaml2.com' };

  try {
    const { context: SAMLResponse, type, signature, sigAlg, relayState } = await idp.createLoginResponse(spWithClockDrift, sampleRequestInfo, 'simpleSign', user, createTemplateCallback(idp, spWithClockDrift, binding.simpleSign, user), undefined, 'relaystate');
    const octetString = buildSimpleSignOctetString(type, SAMLResponse, sigAlg, relayState, signature);
    // simulate the time on client side when response arrives after 5.1 sec
    tk.freeze(fiveMinutesOneSecLater);
    await spWithClockDrift.parseLoginResponse(idp, 'simpleSign', { body: { SAMLResponse, Signature: signature, SigAlg:sigAlg }, octetString });
    expect(true).toBe(true);
  } catch (e) {
    // test failed, it shouldn't happen
    expect(true).toBe(false);
  } finally {
    tk.reset();
  }

});

describe('signature verification trusts only metadata-declared certificates', () => {
  const idpMetaXml = String(readFileSync('./test/misc/idpmeta.xml'));
  const certBody = (pem: Buffer) => String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  // An unrelated key pair: same entityID as the trusted IdP, its own cert in KeyInfo.
  const otherKeyIdp = identityProvider({
    ...defaultIdpConfig,
    isAssertionEncrypted: false,
    privateKey: readFileSync('./test/key/sp/privkey.pem'),
    privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
    metadata: idpMetaXml.replace(
      /(<KeyDescriptor use="signing">[\s\S]*?<X509Certificate>)[^<]+(<\/X509Certificate>)/,
      `$1${certBody(readFileSync('./test/key/sp/cert.cer'))}$2`,
    ),
  });
  const mint = async (issuer: typeof idp) => {
    const { context } = await issuer.createLoginResponse(sp, sampleRequestInfo, 'post', { email: 'user@esaml2.com' });
    return { body: { SAMLResponse: context } };
  };

  test('rejects a response whose embedded certificate is not declared in IdP metadata', async () => {
    await expect(sp.parseLoginResponse(idpNoEncrypt, 'post', await mint(otherKeyIdp)))
      .rejects.toThrow('ERROR_UNMATCH_CERTIFICATE_DECLARATION_IN_METADATA');
  });

  test('rejects a response when IdP metadata declares no X.509 signing certificate', async () => {
    // Signing key published only as ds:RSAKeyValue, which samlify does not import.
    const keyValueOnlyMeta = idpMetaXml
      .replace(/<KeyDescriptor use="encryption">[\s\S]*?<\/KeyDescriptor>/, '')
      .replace(
        /<KeyDescriptor use="signing">[\s\S]*?<\/KeyDescriptor>/,
        '<KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>AQAB</ds:Modulus><ds:Exponent>AQAB</ds:Exponent></ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo></KeyDescriptor>',
      );
    const keyValueOnlyIdp = identityProvider({ ...defaultIdpConfig, isAssertionEncrypted: false, metadata: keyValueOnlyMeta });
    await expect(sp.parseLoginResponse(keyValueOnlyIdp, 'post', await mint(otherKeyIdp)))
      .rejects.toThrow('NO_SELECTED_CERTIFICATE');
  });
});

describe('login response must answer the expected request', () => {
  const user = { email: 'user@esaml2.com' };
  const spStrict = serviceProvider({ ...defaultSpConfig, allowUnsolicitedResponse: false });
  // Template edits applied before the IdP fills and signs the response.
  const withoutAnyInResponseTo = (t: string) => t.replace(/ InResponseTo="\{InResponseTo\}"/g, '');
  const withoutSubjectInResponseTo = (t: string) =>
    t.replace(/(<saml:SubjectConfirmationData\b[^>]*?) InResponseTo="\{InResponseTo\}"/, '$1');
  const mint = (b: 'post' | 'redirect', target = sp, edit: (t: string) => string = t => t) =>
    idpNoEncrypt.createLoginResponse(
      target, sampleRequestInfo, b, user,
      (template: string) => createTemplateCallback(idpNoEncrypt, target, binding[b], user)(edit(template)),
      undefined, 'relaystate',
    );
  const postRequest = async (target = sp, edit?: (t: string) => string) =>
    ({ body: { SAMLResponse: (await mint('post', target, edit)).context } });

  test('rejects a response whose outer InResponseTo differs from the signed one', async () => {
    const { body } = await postRequest();
    const xml = String(utility.base64Decode(body.SAMLResponse, true))
      .replace(/(<samlp:Response\b[^>]*?\bInResponseTo=")[^"]*(")/, '$1_other_request$2');
    await expect(sp.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse: utility.base64Encode(xml) } }))
      .rejects.toThrow('ERR_INRESPONSETO_MISMATCH');
  });

  test('accepts a response answering one of the expected request IDs', async () => {
    const one = await sp.parseLoginResponse(idpNoEncrypt, 'post', await postRequest(), { inResponseTo: 'request_id' });
    expect(one.extract.nameID).toBe(user.email);
    const many = await sp.parseLoginResponse(idpNoEncrypt, 'post', await postRequest(), { inResponseTo: ['_older', 'request_id'] });
    expect(many.extract.nameID).toBe(user.email);
  });

  test('rejects a response answering a different request', async () => {
    await expect(sp.parseLoginResponse(idpNoEncrypt, 'post', await postRequest(), { inResponseTo: '_another_request' }))
      .rejects.toThrow('ERR_INRESPONSETO_MISMATCH');
  });

  test('rejects an unsolicited response when a request ID is expected', async () => {
    await expect(sp.parseLoginResponse(idpNoEncrypt, 'post', await postRequest(sp, withoutAnyInResponseTo), { inResponseTo: 'request_id' }))
      .rejects.toThrow('ERR_MISSING_INRESPONSETO');
  });

  test('post binding: an InResponseTo outside the signed assertion does not answer the request', async () => {
    await expect(sp.parseLoginResponse(idpNoEncrypt, 'post', await postRequest(sp, withoutSubjectInResponseTo), { inResponseTo: 'request_id' }))
      .rejects.toThrow('ERR_MISSING_INRESPONSETO');
  });

  test('redirect binding: the signed message InResponseTo answers the request', async () => {
    const { context } = await mint('redirect', sp, withoutSubjectInResponseTo);
    const { extract } = await sp.parseLoginResponse(idpNoEncrypt, 'redirect', parseRedirectUrlContextCallBack(context), { inResponseTo: 'request_id' });
    expect(extract.nameID).toBe(user.email);
  });

  test('unsolicited responses are accepted by default', async () => {
    const { extract } = await sp.parseLoginResponse(idpNoEncrypt, 'post', await postRequest(sp, withoutAnyInResponseTo));
    expect(extract.nameID).toBe(user.email);
  });

  test('allowUnsolicitedResponse: false rejects a response that answers no request', async () => {
    await expect(spStrict.parseLoginResponse(idpNoEncrypt, 'post', await postRequest(spStrict, withoutAnyInResponseTo)))
      .rejects.toThrow('ERR_UNSOLICITED_RESPONSE');
    const { extract } = await spStrict.parseLoginResponse(idpNoEncrypt, 'post', await postRequest(spStrict));
    expect(extract.nameID).toBe(user.email);
  });
});

describe('replay protection with an application-supplied store', () => {
  const user = { email: 'user@esaml2.com' };
  const memoryStore = () => {
    const saved = new Map<string, Date>();
    return { saved, saveIfAbsent: (key: string, expiresAt: Date) => saved.has(key) ? false : (saved.set(key, expiresAt), true) };
  };
  const mintPost = async (target: typeof sp) => {
    const { context } = await idpNoEncrypt.createLoginResponse(
      target, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, target, binding.post, user),
    );
    return { body: { SAMLResponse: context } };
  };

  test('without a store the same response is accepted again', async () => {
    const request = await mintPost(sp);
    await sp.parseLoginResponse(idpNoEncrypt, 'post', request);
    const { extract } = await sp.parseLoginResponse(idpNoEncrypt, 'post', request);
    expect(extract.nameID).toBe(user.email);
  });

  test('rejects an assertion that was already accepted', async () => {
    const store = memoryStore();
    const spWithStore = serviceProvider({ ...defaultSpConfig, replayCache: store });
    const request = await mintPost(spWithStore);
    const { extract } = await spWithStore.parseLoginResponse(idpNoEncrypt, 'post', request);
    expect(extract.nameID).toBe(user.email);
    await expect(spWithStore.parseLoginResponse(idpNoEncrypt, 'post', request)).rejects.toThrow('ERR_REPLAYED_ASSERTION');

    expect(store.saved.size).toBe(1);
    const [[key, expiresAt]] = [...store.saved];
    expect(JSON.parse(key)).toEqual(['assertion', idpNoEncrypt.entityMeta.getEntityID(), extract.assertionID]);
    // Kept until the earliest NotOnOrAfter of Conditions / SubjectConfirmationData.
    const notOnOrAfter = [extract.conditions.notOnOrAfter, extract.subjectConfirmation.notOnOrAfter].map(v => new Date(v).getTime());
    expect(expiresAt.getTime()).toBe(Math.min(...notOnOrAfter));
  });

  test('keeps the assertion for the allowed clock drift as well', async () => {
    const store = memoryStore();
    const spWithStore = serviceProvider({ ...defaultSpConfig, replayCache: store, clockDrifts: [0, 60000] });
    const { extract } = await spWithStore.parseLoginResponse(idpNoEncrypt, 'post', await mintPost(spWithStore));
    const [[, expiresAt]] = [...store.saved];
    expect(expiresAt.getTime()).toBe(new Date(extract.conditions.notOnOrAfter).getTime() + 60000);
  });

  test('an assertion without NotOnOrAfter is kept for 24 hours', async () => {
    const store = memoryStore();
    const spWithStore = serviceProvider({ ...defaultSpConfig, replayCache: store });
    const withoutExpiry = (t: string) => t.replace(/ NotOnOrAfter="\{(ConditionsNotOnOrAfter|SubjectConfirmationDataNotOnOrAfter)\}"/g, '');
    const { context } = await idpNoEncrypt.createLoginResponse(
      spWithStore, sampleRequestInfo, 'post', user,
      (template: string) => createTemplateCallback(idpNoEncrypt, spWithStore, binding.post, user)(withoutExpiry(template)),
    );
    const before = Date.now();
    await spWithStore.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse: context } });
    const [[, expiresAt]] = [...store.saved];
    expect(expiresAt.getTime() - before).toBeGreaterThanOrEqual(24 * 60 * 60 * 1000);
    expect(expiresAt.getTime() - Date.now()).toBeLessThanOrEqual(24 * 60 * 60 * 1000);
  });

  test('a response that fails validation does not use up its assertion', async () => {
    const store = memoryStore();
    const spWithStore = serviceProvider({ ...defaultSpConfig, replayCache: store });
    const otherSp = serviceProvider({ ...defaultSpConfig, replayCache: store, metadata: String(defaultSpConfig.metadata).replace(/sp\.example\.org/g, 'sp-b.example.org') });
    const request = await mintPost(spWithStore);
    await expect(otherSp.parseLoginResponse(idpNoEncrypt, 'post', request)).rejects.toThrow('ERR_AUDIENCE_MISMATCH');
    expect(store.saved.size).toBe(0);
    const { extract } = await spWithStore.parseLoginResponse(idpNoEncrypt, 'post', request);
    expect(extract.nameID).toBe(user.email);
  });

  test('encrypted assertion: the decrypted assertion ID is remembered', async () => {
    const spWithStore = serviceProvider({ ...defaultSpConfig, replayCache: memoryStore() });
    const { context } = await idp.createLoginResponse(
      spWithStore, sampleRequestInfo, 'post', user, createTemplateCallback(idp, spWithStore, binding.post, user),
    );
    const request = { body: { SAMLResponse: context } };
    const { extract } = await spWithStore.parseLoginResponse(idp, 'post', request);
    expect(extract.assertionID).toMatch(/^_/);
    await expect(spWithStore.parseLoginResponse(idp, 'post', request)).rejects.toThrow('ERR_REPLAYED_ASSERTION');
  });

  test('redirect binding: rejects a replayed response', async () => {
    const spWithStore = serviceProvider({ ...defaultSpConfig, replayCache: memoryStore() });
    const { context } = await idpNoEncrypt.createLoginResponse(
      spWithStore, sampleRequestInfo, 'redirect', user, createTemplateCallback(idpNoEncrypt, spWithStore, binding.redirect, user), undefined, 'relaystate',
    );
    await spWithStore.parseLoginResponse(idpNoEncrypt, 'redirect', parseRedirectUrlContextCallBack(context));
    await expect(spWithStore.parseLoginResponse(idpNoEncrypt, 'redirect', parseRedirectUrlContextCallBack(context)))
      .rejects.toThrow('ERR_REPLAYED_ASSERTION');
  });

  test('supports an asynchronous store and surfaces its errors', async () => {
    const asyncSp = serviceProvider({ ...defaultSpConfig, replayCache: { saveIfAbsent: async () => false } });
    await expect(asyncSp.parseLoginResponse(idpNoEncrypt, 'post', await mintPost(asyncSp))).rejects.toThrow('ERR_REPLAYED_ASSERTION');
    const failingSp = serviceProvider({ ...defaultSpConfig, replayCache: { saveIfAbsent: async () => { throw new Error('store unavailable'); } } });
    await expect(failingSp.parseLoginResponse(idpNoEncrypt, 'post', await mintPost(failingSp))).rejects.toThrow('store unavailable');
  });
});

describe('a signature must cover the element that contains it', () => {
  const SIGNATURE = /<(ds:)?Signature\b[\s\S]*<\/(ds:)?Signature>/;
  // Move the genuine signature under a forged root and hide the signed message in <Extensions>.
  const wrap = (signedXml: string, forge: (xml: string) => string) => {
    const signature = signedXml.match(SIGNATURE)![0];
    const hidden = signedXml.replace(SIGNATURE, '').replace(/^<\?xml[^>]*>/, '');
    return forge(hidden)
      .replace(/(<saml:Issuer>[^<]*<\/saml:Issuer>)/, `$1${signature}<samlp:Extensions><x:w xmlns:x="urn:x">${hidden}</x:w></samlp:Extensions>`);
  };
  const decode = (b64: string) => String(utility.base64Decode(b64, true));

  test('rejects a wrapped AuthnRequest', async () => {
    const { context } = sp.createLoginRequest(idp, 'post') as PostBindingContext;
    const genuine = decode(context);
    expect(genuine).toMatch(SIGNATURE);
    const forged = wrap(genuine, xml => xml
      .replace(/ ID="[^"]+"/, ' ID="_forged"')
      .replace(/AssertionConsumerServiceURL="[^"]+"/, 'AssertionConsumerServiceURL="https://evil.example.com/acs"'));
    await expect(idp.parseLoginRequest(sp, 'post', { body: { SAMLRequest: utility.base64Encode(forged) } }))
      .rejects.toThrow('ERR_POTENTIAL_WRAPPING_ATTACK');
    // The genuine request is still accepted.
    const { extract } = await idp.parseLoginRequest(sp, 'post', { body: { SAMLRequest: context } });
    expect(extract.request.id).not.toBe('_forged');
  });

  test('rejects a wrapped LogoutRequest', async () => {
    const { context } = idp.createLogoutRequest(spWantLogoutReqSign, 'post', { logoutNameID: 'attacker@esaml2.com' }) as PostBindingContext;
    const genuine = decode(context);
    expect(genuine).toMatch(SIGNATURE);
    const forged = wrap(genuine, xml => xml
      .replace(/ ID="[^"]+"/, ' ID="_forged"')
      .replace('attacker@esaml2.com', 'victim@esaml2.com'));
    await expect(spWantLogoutReqSign.parseLogoutRequest(idp, 'post', { body: { SAMLRequest: utility.base64Encode(forged) } }))
      .rejects.toThrow('ERR_POTENTIAL_WRAPPING_ATTACK');
    const { extract } = await spWantLogoutReqSign.parseLogoutRequest(idp, 'post', { body: { SAMLRequest: context } });
    expect(extract.nameID).toBe('attacker@esaml2.com');
  });
});

describe('wantMessageSigned is enforced when parsing a login response', () => {
  const user = { email: 'user@esaml2.com' };
  const spWantMessageSigned = serviceProvider({ ...defaultSpConfig, wantMessageSigned: true });
  const SIGNATURE = /<(ds:)?Signature\b/g;
  const mint = async (issuer: typeof idp, target: typeof sp, encryptThenSign = false) => {
    const { context } = await issuer.createLoginResponse(
      target, sampleRequestInfo, 'post', user, createTemplateCallback(issuer, target, binding.post, user), undefined, { encryptThenSign },
    );
    return String(utility.base64Decode(context, true));
  };
  const post = (xml: string) => ({ body: { SAMLResponse: utility.base64Encode(xml) } });
  const breakMessageSignature = (xml: string) =>
    xml.replace(/(<samlp:Response\b[^>]*?\bIssueInstant=")[^"]*(")/, '$12001-01-01T00:00:00Z$2');
  const stripMessageSignature = (xml: string) =>
    xml.replace(/(<\/saml:Issuer>)<ds:Signature\b[\s\S]*?<\/ds:Signature>(<samlp:Status>)/, '$1$2');

  test('rejects a response without a message signature', async () => {
    const xml = await mint(idpNoEncrypt, sp); // assertion signed only
    expect(xml.match(SIGNATURE)!.length).toBe(1);
    await expect(spWantMessageSigned.parseLoginResponse(idpNoEncrypt, 'post', post(xml))).rejects.toThrow('ERR_MISSING_MESSAGE_SIGNATURE');
  });

  test('accepts a response with a valid message signature', async () => {
    const xml = await mint(idpNoEncrypt, spWantMessageSigned);
    expect(xml.match(SIGNATURE)!.length).toBe(2);
    const { extract } = await spWantMessageSigned.parseLoginResponse(idpNoEncrypt, 'post', post(xml));
    expect(extract.nameID).toBe(user.email);
  });

  test('a broken message signature fails even when the assertion signature verifies', async () => {
    const xml = breakMessageSignature(await mint(idpNoEncrypt, spWantMessageSigned));
    await expect(spWantMessageSigned.parseLoginResponse(idpNoEncrypt, 'post', post(xml))).rejects.toThrow('FAILED_TO_VERIFY_SIGNATURE');
    // Also without wantMessageSigned: a signature that is present must verify.
    await expect(sp.parseLoginResponse(idpNoEncrypt, 'post', post(xml))).rejects.toThrow('FAILED_TO_VERIFY_SIGNATURE');
  });

  test('sign-then-encrypt: message signature verified after decryption, and still required', async () => {
    const xml = await mint(idp, spWantMessageSigned);
    expect(xml).toContain('EncryptedAssertion');
    const { extract } = await spWantMessageSigned.parseLoginResponse(idp, 'post', post(xml));
    expect(extract.nameID).toBe(user.email);
    await expect(spWantMessageSigned.parseLoginResponse(idp, 'post', post(stripMessageSignature(xml)))).rejects.toThrow('ERR_MISSING_MESSAGE_SIGNATURE');
    await expect(spWantMessageSigned.parseLoginResponse(idp, 'post', post(breakMessageSignature(xml)))).rejects.toThrow('FAILED_TO_VERIFY_SIGNATURE');
  });

  test('encrypt-then-sign: message signature required and must verify', async () => {
    const xml = await mint(idp, spWantMessageSigned, true);
    const { extract } = await spWantMessageSigned.parseLoginResponse(idp, 'post', post(xml));
    expect(extract.nameID).toBe(user.email);
    await expect(spWantMessageSigned.parseLoginResponse(idp, 'post', post(stripMessageSignature(xml)))).rejects.toThrow('ERR_MISSING_MESSAGE_SIGNATURE');
    await expect(spWantMessageSigned.parseLoginResponse(idp, 'post', post(breakMessageSignature(xml)))).rejects.toThrow('FAILED_TO_VERIFY_SIGNATURE');
  });
});

describe('templateRenderer: strict', () => {
  const user = { email: 'user@esaml2.com' };
  const strictSp = serviceProvider({ ...defaultSpConfig, templateRenderer: 'strict' });
  const strictIdp = identityProvider({ ...defaultIdpConfig, isAssertionEncrypted: false, templateRenderer: 'strict' });

  test('login request round-trips (post)', async () => {
    const { id, context } = strictSp.createLoginRequest(strictIdp, 'post') as PostBindingContext;
    const { extract } = await strictIdp.parseLoginRequest(strictSp, 'post', { body: { SAMLRequest: context } });
    expect(extract.request.id).toBe(id);
  });

  test('login request round-trips (redirect)', async () => {
    const { id, context } = strictSp.createLoginRequest(strictIdp, 'redirect');
    const originalURL = url.parse(context, true);
    const { SAMLRequest, Signature, SigAlg } = originalURL.query;
    delete originalURL.query.Signature;
    const octetString = Object.keys(originalURL.query).map(q => q + '=' + encodeURIComponent(originalURL.query[q] as string)).join('&');
    const { extract } = await strictIdp.parseLoginRequest(strictSp, 'redirect', { query: { SAMLRequest, Signature, SigAlg }, octetString } as any);
    expect(extract.request.id).toBe(id);
  });

  test('login request round-trips (simpleSign)', async () => {
    const { relayState, id, context: SAMLRequest, type, sigAlg, signature } = strictSp.createLoginRequest(strictIdp, 'simpleSign') as SimpleSignBindingContext;
    const octetString = buildSimpleSignOctetString(type, SAMLRequest, sigAlg, relayState, signature);
    const { extract } = await strictIdp.parseLoginRequest(strictSp, 'simpleSign', { body: { SAMLRequest, Signature: signature, SigAlg: sigAlg }, octetString });
    expect(extract.request.id).toBe(id);
  });

  test('login response with attributes round-trips, using renderTemplate in the callback', async () => {
    const idpWithAttributes = identityProvider({ ...defaultIdpConfig, isAssertionEncrypted: false, templateRenderer: 'strict', loginResponseTemplate });
    const { context } = await idpWithAttributes.createLoginResponse(
      strictSp, sampleRequestInfo, 'post', user, createTemplateCallback(idpWithAttributes, strictSp, binding.post, user, libsaml.renderTemplate),
    );
    const { extract } = await strictSp.parseLoginResponse(idpWithAttributes, 'post', { body: { SAMLResponse: context } });
    expect(extract.nameID).toBe(user.email);
    expect(extract.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  });

  test('default login response round-trips', async () => {
    const { context } = await strictIdp.createLoginResponse(strictSp, sampleRequestInfo, 'post', user);
    const { extract } = await strictSp.parseLoginResponse(strictIdp, 'post', { body: { SAMLResponse: context } });
    expect(extract.nameID).toBe(user.email);
  });

  test('logout request and response round-trip', async () => {
    const logoutRequest = strictIdp.createLogoutRequest(strictSp, 'post', { logoutNameID: user.email, sessionIndex: '_session' }) as PostBindingContext;
    const parsedRequest = await strictSp.parseLogoutRequest(strictIdp, 'post', { body: { SAMLRequest: logoutRequest.context } });
    expect(parsedRequest.extract.nameID).toBe(user.email);
    expect(parsedRequest.extract.sessionIndex).toBe('_session');

    const logoutResponse = strictSp.createLogoutResponse(strictIdp, parsedRequest, 'post') as PostBindingContext;
    const parsedResponse = await strictIdp.parseLogoutResponse(strictSp, 'post', { body: { SAMLResponse: logoutResponse.context } });
    expect(parsedResponse.extract.response.inResponseTo).toBe(parsedRequest.extract.request.id);
  });
});

test.each(['legacy', 'strict'] as const)('attribute names cannot inject attributes into the signed assertion (%s)', async renderer => {
  const user = { email: 'user@esaml2.com' };
  const injectedName = 'mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"><saml:AttributeValue>x</saml:AttributeValue></saml:Attribute><saml:Attribute Name="role';
  const idpWithInjectedName = identityProvider({
    ...defaultIdpConfig,
    isAssertionEncrypted: false,
    templateRenderer: renderer,
    loginResponseTemplate: {
      ...loginResponseTemplate,
      attributes: [{ name: injectedName, valueTag: 'user.email', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', valueXsiType: 'xs:string' }],
    },
  });
  const { context } = await idpWithInjectedName.createLoginResponse(
    sp, sampleRequestInfo, 'post', user, createTemplateCallback(idpWithInjectedName, sp, binding.post, user),
  );
  const { extract } = await sp.parseLoginResponse(idpWithInjectedName, 'post', { body: { SAMLResponse: context } });
  expect(extract.attributes.role).toBeUndefined();
  expect(extract.attributes[injectedName]).toBe('myemailassociatedwithsp@sp.com');
});

test('redirect binding: a comment inside a signed NameID does not truncate it', async () => {
  const user = { email: 'user@esaml2.com' };
  const withComment = (template: string) => {
    const filled = createTemplateCallback(idpNoEncrypt, sp, binding.redirect, user)(template);
    return { ...filled, context: filled.context.replace('>user@esaml2.com<', '>user@esaml2.com<!-- x -->.evil.example<') };
  };
  const { context } = await idpNoEncrypt.createLoginResponse(sp, sampleRequestInfo, 'redirect', user, withComment, undefined, 'relaystate');
  const { extract } = await sp.parseLoginResponse(idpNoEncrypt, 'redirect', parseRedirectUrlContextCallBack(context));
  expect(extract.nameID).toBe('user@esaml2.com.evil.example');
});
