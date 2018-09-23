import esaml2 = require('../index');
import { readFileSync, writeFileSync } from 'fs';
import test from 'ava';
import * as _ from 'lodash';
import { PostBindingContext } from '../src/entity';
import * as uuid from 'uuid';
import * as url from 'url';

const {
  IdentityProvider: identityProvider,
  ServiceProvider: serviceProvider,
  IdPMetadata: idpMetadata,
  SPMetadata: spMetadata,
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

const createTemplateCallback = (idp, sp, user) => template => {
  const _id =  '_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6';
  const now = new Date();
  const spEntityID = sp.entityMeta.getEntityID();
  const idpSetting = idp.entitySetting;
  const fiveMinutesLater = new Date(now.getTime());
  fiveMinutesLater.setMinutes(fiveMinutesLater.getMinutes() + 5);
  const tvalue = {
    ID: _id,
    AssertionID: idpSetting.generateID ? idpSetting.generateID() : `${uuid.v4()}`,
    Destination: sp.entityMeta.getAssertionConsumerService(binding.post),
    Audience: spEntityID,
    SubjectRecipient: spEntityID,
    NameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    NameID: user.email,
    Issuer: idp.entityMeta.getEntityID(),
    IssueInstant: now.toISOString(),
    ConditionsNotBefore: now.toISOString(),
    ConditionsNotOnOrAfter: fiveMinutesLater.toISOString(),
    SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater.toISOString(),
    AssertionConsumerServiceURL: sp.entityMeta.getAssertionConsumerService(binding.post),
    EntityID: spEntityID,
    InResponseTo: '_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4',
    StatusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',
    attrUserEmail: 'myemailassociatedwithsp@sp.com',
    attrUserName: 'mynameinsp',
  };
  return {
    id: _id,
    context: libsaml.replaceTagsByValue(template, tvalue),
  };
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

const defaultSpConfig = {
  privateKey: readFileSync('./test/key/sp/privkey.pem'),
  privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
  isAssertionEncrypted: true, // for logout purpose
  encPrivateKey: readFileSync('./test/key/sp/encryptKey.pem'),
  encPrivateKeyPass: 'BXFNKpxrsjrCkGA8cAu5wUVHOSpci1RU',
  metadata: readFileSync('./test/misc/spmeta.xml'),
};

// Define metadata
const IdPMetadata = idpMetadata(readFileSync('./test/misc/idpmeta.xml'));
const SPMetadata = spMetadata(readFileSync('./test/misc/spmeta.xml'));
const sampleSignedResponse = readFileSync('./test/misc/response_signed.xml').toString();
const wrongResponse = readFileSync('./test/misc/invalid_response.xml').toString();
const spCertKnownGood = readFileSync('./test/key/sp/knownGoodCert.cer').toString().trim();
const spPemKnownGood = readFileSync('./test/key/sp/knownGoodEncryptKey.pem').toString().trim();
const noSignedIdpMetadata = readFileSync('./test/misc/idpmeta_nosign.xml').toString().trim();
const spmetaNoAssertSign = readFileSync('./test/misc/spmeta_noassertsign.xml').toString().trim();

const sampleRequestInfo = { extract: { authnrequest: { id: 'request_id' } } };

// Define entities
const idp = identityProvider(defaultIdpConfig);
const sp = serviceProvider(defaultSpConfig);
const idpNoEncrypt = identityProvider({ ...defaultIdpConfig, isAssertionEncrypted: false });
const idpcustomNoEncrypt = identityProvider({ ...defaultIdpConfig, isAssertionEncrypted: false, loginResponseTemplate });
const idpcustom = identityProvider({ ...defaultIdpConfig, loginResponseTemplate });
const idpEncryptThenSign = identityProvider({ ...defaultIdpConfig, messageSigningOrder: 'encrypt-then-sign' });
const spWantLogoutReqSign = serviceProvider({ ...defaultSpConfig, wantLogoutRequestSigned: true });
const spWantLogoutResSign = serviceProvider({ ...defaultSpConfig, wantLogoutResponseSigned: true });
const idpWantLogoutResSign = identityProvider({ ...defaultIdpConfig, wantLogoutResponseSigned: true });
const spNoAssertSign = serviceProvider({ ...defaultSpConfig, metadata: spmetaNoAssertSign });
const spNoAssertSignCustomConfig = serviceProvider({ ...defaultSpConfig,
  metadata: spmetaNoAssertSign,
  signatureConfig: {
    prefix: 'ds',
    location: { reference: '/samlp:Response/saml:Issuer', action: 'after' },
  },
});

function writer(str) {
  writeFileSync('test.txt', str);
}

test('create login request with redirect binding using default template and parse it', async t => {
  const { id, context } = sp.createLoginRequest(idp, 'redirect');
  t.is(typeof id, 'string');
  t.is(typeof context, 'string');
  const originalURL = url.parse(context, true);
  const SAMLRequest = originalURL.query.SAMLRequest;
  const Signature = originalURL.query.Signature;
  const SigAlg = originalURL.query.SigAlg;
  delete originalURL.query.Signature;
  const octetString = Object.keys(originalURL.query).map(q => q + '=' + encodeURIComponent(originalURL.query[q])).join('&');
  const { samlContent, extract } = await idp.parseLoginRequest(sp, 'redirect', { query: { SAMLRequest, Signature, SigAlg }, octetString});
  t.is(extract.issuer, 'https://sp.example.org/metadata');
  t.is(typeof extract.authnrequest.id, 'string');
  t.is(extract.nameidpolicy.format, 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
  t.is(extract.nameidpolicy.allowcreate, 'false');
});

test('create login request with post binding using default template and parse it', async t => {
  const { relayState, type, entityEndpoint, id, context: SAMLRequest } = sp.createLoginRequest(idp, 'post') as PostBindingContext;
  t.is(typeof id, 'string');
  t.is(typeof SAMLRequest, 'string');
  t.is(typeof entityEndpoint, 'string');
  t.is(type, 'SAMLRequest');
  const { extract } = await idp.parseLoginRequest(sp, 'post', { body: { SAMLRequest }});
  t.is(extract.issuer, 'https://sp.example.org/metadata');
  t.is(typeof extract.authnrequest.id, 'string');
  t.is(extract.nameidpolicy.format, 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
  t.is(extract.nameidpolicy.allowcreate, 'false');
  t.is(typeof extract.signature, 'string');
});

test('signed in sp is not matched with the signed notation in idp with post request', t => {
  const _idp = identityProvider({ ...defaultIdpConfig, metadata: noSignedIdpMetadata });
  try {
    const { id, context } = sp.createLoginRequest(_idp, 'post');
    t.fail();
  } catch (e) {
    t.is(e.message, 'metadata conflict - sp isAuthnRequestSigned is not equal to idp isWantAuthnRequestsSigned');
  }
});

test('signed in sp is not matched with the signed notation in idp with redirect request', t => {
  const _idp = identityProvider({ ...defaultIdpConfig, metadata: noSignedIdpMetadata });
  try {
    const { id, context } = sp.createLoginRequest(_idp, 'redirect');
    t.fail();
  } catch (e) {
    t.is(e.message, 'metadata conflict - sp isAuthnRequestSigned is not equal to idp isWantAuthnRequestsSigned');
  }
});

test('create login request with redirect binding using [custom template]', t => {
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
  (id === 'exposed_testing_id' && _.isString(context)) ? t.pass() : t.fail();
});

test('create login request with post binding using [custom template]', t => {
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
    _.isString(context) &&
    _.isString(relayState) &&
    _.isString(entityEndpoint) &&
    _.isEqual(type, 'SAMLRequest')
    ? t.pass() : t.fail();
});

test('create login response with undefined binding', async t => {
  const user = { email: 'user@esaml2.com' };
  const error = await t.throws(idp.createLoginResponse(sp, {}, 'undefined', user, createTemplateCallback(idp, sp, user)));
  t.is(error.message, 'this binding is not supported');
});

test('create post login response', async t => {
  const user = { email: 'user@esaml2.com' };
  const { id, context } = await idp.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idp, sp, user));
  _.isString(id) && _.isString(context) ? t.pass() : t.fail();
});

test('create logout request with redirect binding', t => {
  const { id, context } = sp.createLogoutRequest(idp, 'redirect', { logoutNameID: 'user@esaml2' });
  _.isString(id) && _.isString(context) ? t.pass() : t.fail();
});

test('create logout request with post binding', t => {
  const { relayState, type, entityEndpoint, id, context } = sp.createLogoutRequest(idp, 'post', { logoutNameID: 'user@esaml2' }) as PostBindingContext;
  _.isString(id) && _.isString(context) && _.isString(entityEndpoint) && _.isEqual(type, 'SAMLRequest') ? t.pass() : t.fail();
});

test('create logout response with undefined binding', t => {
  try {
    const { id, context } = idp.createLogoutResponse(sp, {}, 'undefined', '', createTemplateCallback(idp, sp, {}));
    t.fail();
  } catch (e) {
    t.is(e.message, 'this binding is not supported');
  }
});

test('create logout response with redirect binding', t => {
  const { id, context } = idp.createLogoutResponse(sp, {}, 'redirect', '', createTemplateCallback(idp, sp, {}));
  _.isString(id) && _.isString(context) ? t.pass() : t.fail();
});

test('create logout response with post binding', t => {
  const { relayState, type, entityEndpoint, id, context } = idp.createLogoutResponse(sp, {}, 'post', '', createTemplateCallback(idp, sp, {})) as PostBindingContext;
  _.isString(id) && _.isString(context) && _.isString(entityEndpoint) && _.isEqual(type, 'SAMLResponse') ? t.pass() : t.fail();
});

// Check if the response data parsing is correct
// All test cases are using customize template

// simulate idp-initiated sso
test('send response with signed assertion and parse it', async t => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, sp, user));
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await sp.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse } });
  // test phrase 1: samlContent is a string (parsed version)
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  // test phrase 2: useful information is included in extract object
  t.is(extract.nameid, 'user@esaml2.com');
  t.is(typeof extract.signature, 'string');
  // Ensure that inresponseto was added to the response
  t.is(extract.response.inresponseto, 'request_id');
});

test('send response with [custom template] signed assertion and parse it', async t => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const requestInfo = { extract: { authnrequest: { id: 'request_id' } } };
  const user = { email: 'user@esaml2.com'};
  const { id, context: SAMLResponse } = await idpcustomNoEncrypt.createLoginResponse(
    sp,
    requestInfo,
    'post',
    user,
    // declare the callback to do custom template replacement
    createTemplateCallback(idpcustomNoEncrypt, sp, user),
  );
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await sp.parseLoginResponse(idpcustomNoEncrypt, 'post', { body: { SAMLResponse } });
  // test phrase 1: samlContent is a string (parsed version)
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  // test phrase 2: useful information is included in extract object
  t.is(extract.nameid, 'user@esaml2.com');
  t.is(typeof extract.signature, 'string');
  // test phrase 3: check if attribute is parsed properly
  t.is(extract.attribute.name, 'mynameinsp');
  t.is(extract.attribute.mail, 'myemailassociatedwithsp@sp.com');
  // Ensure that inresponseto was added to the response
  t.is(extract.response.inresponseto, '_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});

test('send response with signed message and parse it', async t => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(spNoAssertSign, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, spNoAssertSign, user));
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spNoAssertSign.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse } });
  // test phrase 1: samlContent is a string (parsed version)
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  // test phrase 2: useful information is included in extract object
  t.is(extract.nameid, 'user@esaml2.com');
  t.is(typeof extract.signature, 'string');
  // Ensure that inresponseto was added to the response
  t.is(extract.response.inresponseto, 'request_id');
});

test('send response with [custom template] and signed message and parse it', async t => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const requestInfo = { extract: { authnrequest: { id: 'request_id' } } };
  const user = { email: 'user@esaml2.com'};
  const { id, context: SAMLResponse } = await idpcustomNoEncrypt.createLoginResponse(
    spNoAssertSign,
    { extract: { authnrequest: { id: 'request_id' } } }, 'post',
    { email: 'user@esaml2.com' },
    createTemplateCallback(idpcustomNoEncrypt, spNoAssertSign, user),
  );
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spNoAssertSign.parseLoginResponse(idpcustomNoEncrypt, 'post', { body: { SAMLResponse } });
  // test phrase 1: samlContent is a string (parsed version)
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  // test phrase 2: useful information is included in extract object
  t.is(extract.nameid, 'user@esaml2.com');
  t.is(typeof extract.signature, 'string');
  // test phrase 3: check if attribute is parsed properly
  t.is(extract.attribute.name, 'mynameinsp');
  t.is(extract.attribute.mail, 'myemailassociatedwithsp@sp.com');
  // Ensure that inresponseto was added to the response
  t.is(extract.response.inresponseto, '_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});

test('send login response with signed assertion + signed message and parse it', async t => {
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(spWantMessageSign, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, spWantMessageSign, user));
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spWantMessageSign.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse } });
  // test phrase 1: samlContent is a string (parsed version)
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  // test phrase 2: useful information is included in extract object
  t.is(extract.nameid, 'user@esaml2.com');
  t.is(typeof extract.signature, 'object');
  // Ensure that inresponseto was added to the response
  t.is(extract.response.inresponseto, 'request_id');
});

test('send login response with [custom template] and signed assertion + signed message and parse it', async t => {
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });
  const requestInfo = { extract: { authnrequest: { id: 'request_id' } } };
  const user = { email: 'user@esaml2.com'};
  const { id, context: SAMLResponse } = await idpcustomNoEncrypt.createLoginResponse(
    spWantMessageSign,
    { extract: { authnrequest: { id: 'request_id' } } }, 'post',
    { email: 'user@esaml2.com' },
    createTemplateCallback(idpcustomNoEncrypt, spWantMessageSign, user),
  );
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spWantMessageSign.parseLoginResponse(idpcustomNoEncrypt, 'post', { body: { SAMLResponse } });
  // test phrase 1: samlContent is a string (parsed version)
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  // test phrase 2: useful information is included in extract object
  t.is(extract.nameid, 'user@esaml2.com');
  t.is(typeof extract.signature, 'object');
  // test phrase 3: check if attribute is parsed properly
  t.is(extract.attribute.name, 'mynameinsp');
  t.is(extract.attribute.mail, 'myemailassociatedwithsp@sp.com');
  // Ensure that inresponseto was added to the response
  t.is(extract.response.inresponseto, '_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});

test('send login response with encrypted non-signed assertion and parse it', async t => {
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idp.createLoginResponse(spNoAssertSign, sampleRequestInfo, 'post', user, createTemplateCallback(idp, spNoAssertSign, user));
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spNoAssertSign.parseLoginResponse(idp, 'post', { body: { SAMLResponse } });
  // test phrase 1: samlContent is a string (parsed version)
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  // test phrase 2: useful information is included in extract object
  t.is(extract.nameid, 'user@esaml2.com');
  t.is(typeof extract.signature, 'string');
  // Ensure that inresponseto was added to the response
  t.is(extract.response.inresponseto, 'request_id');
});

test('send login response with encrypted signed assertion and parse it', async t => {
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idp.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idp, sp, user));
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await sp.parseLoginResponse(idp, 'post', { body: { SAMLResponse } });
  // test phrase 1: samlContent is a string (parsed version)
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  // test phrase 2: useful information is included in extract object
  t.is(extract.nameid, 'user@esaml2.com');
  t.is(typeof extract.signature, 'string');
  // Ensure that inresponseto was added to the response
  t.is(extract.response.inresponseto, 'request_id');
});

test('send login response with [custom template] and encrypted signed assertion and parse it', async t => {
  const requestInfo = { extract: { authnrequest: { id: 'request_id' } } };
  const user = { email: 'user@esaml2.com'};
  const { id, context: SAMLResponse } = await idpcustom.createLoginResponse(
    sp,
    { extract: { authnrequest: { id: 'request_id' } } }, 'post',
    { email: 'user@esaml2.com' },
    createTemplateCallback(idpcustom, sp, user),
  );
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await sp.parseLoginResponse(idpcustom, 'post', { body: { SAMLResponse } });
  // test phrase 1: samlContent is a string (parsed version)
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  // test phrase 2: useful information is included in extract object
  t.is(extract.nameid, 'user@esaml2.com');
  t.is(typeof extract.signature, 'string');
  // test phrase 3: check if attribute is parsed properly
  t.is(extract.attribute.name, 'mynameinsp');
  t.is(extract.attribute.mail, 'myemailassociatedwithsp@sp.com');
  // Ensure that inresponseto was added to the response
  t.is(extract.response.inresponseto, '_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});

test('send login response with encrypted signed assertion + signed message and parse it', async t => {
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idp.createLoginResponse(spWantMessageSign, sampleRequestInfo, 'post', user, createTemplateCallback(idp, spWantMessageSign, user));
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spWantMessageSign.parseLoginResponse(idp, 'post', { body: { SAMLResponse } });
  // test phrase 1: samlContent is a string (parsed version)
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  // test phrase 2: useful information is included in extract object
  t.is(extract.nameid, 'user@esaml2.com');
  t.is(typeof extract.signature, 'object');
  // Ensure that inresponseto was added to the response
  t.is(extract.response.inresponseto, 'request_id');
});

test('send login response with [custom template] encrypted signed assertion + signed message and parse it', async t => {
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
    createTemplateCallback(idpcustom, spWantMessageSign, user),
  );
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spWantMessageSign.parseLoginResponse(idpcustom, 'post', { body: { SAMLResponse } });
  // test phrase 1: samlContent is a string (parsed version)
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  // test phrase 2: useful information is included in extract object
  t.is(extract.nameid, 'user@esaml2.com');
  t.is(typeof extract.signature, 'object');
  // test phrase 3: check if attribute is parsed properly
  t.is(extract.attribute.name, 'mynameinsp');
  t.is(extract.attribute.mail, 'myemailassociatedwithsp@sp.com');
  // Ensure that inresponseto was added to the response
  t.is(extract.response.inresponseto, '_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});

// simulate idp-init slo
test('idp sends a redirect logout request without signature and sp parses it', async t => {
  const { id, context } = idp.createLogoutRequest(sp, 'redirect', { logoutNameID: 'user@esaml2.com' });
  const query = url.parse(context).query;
  t.is(_.includes(query, 'SAMLRequest='), true);
  t.is(typeof id, 'string');
  t.is(typeof context, 'string');
  // const originURL = new url.URL(context);
  // const SAMLRequest = originURL.searchParams.get('SAMLRequest');
  const originalURL = url.parse(context, true);
  const SAMLRequest = encodeURIComponent(originalURL.query.SAMLRequest);
  let result;
  const { samlContent, extract } = result = await sp.parseLogoutRequest(idp, 'redirect', { query: { SAMLRequest }});
  t.is(result.sigAlg, undefined);
  t.is(typeof samlContent, 'string');
  t.is(extract.nameid, 'user@esaml2.com');
  t.is(extract.signature, undefined);
  t.is(typeof extract.logoutrequest.id, 'string');
  t.is(extract.logoutrequest.destination, 'https://sp.example.org/sp/slo');
  t.is(extract.issuer, 'https://idp.example.com/metadata');
});

test('idp sends a redirect logout request with signature and sp parses it', async t => {
  const { id, context } = idp.createLogoutRequest(spWantLogoutReqSign, 'redirect', { logoutNameID: 'user@esaml2.com' });
  const query = url.parse(context).query;
  t.is(_.includes(query, 'SAMLRequest='), true);
  t.is(_.includes(query, 'SigAlg='), true);
  t.is(_.includes(query, 'Signature='), true);
  t.is(typeof id, 'string');
  t.is(typeof context, 'string');
  // const originalURL = new url.URL(context);
  // const SAMLRequest = originalURL.searchParams.get('SAMLRequest');
  // const Signature = originalURL.searchParams.get('Signature');
  // const SigAlg = originalURL.searchParams.get('SigAlg');
  // originalURL.searchParams.delete('Signature');
  // const octetString = originalURL.searchParams.toString();
  const originalURL = url.parse(context, true);
  const SAMLRequest = originalURL.query.SAMLRequest;
  const Signature = originalURL.query.Signature;
  const SigAlg = originalURL.query.SigAlg;
  delete originalURL.query.Signature;
  const octetString = Object.keys(originalURL.query).map(q => q + '=' + encodeURIComponent(originalURL.query[q])).join('&');
  const { extract } = await spWantLogoutReqSign.parseLogoutRequest(idp, 'redirect', { query: { SAMLRequest, Signature, SigAlg }, octetString});
  t.is(extract.nameid, 'user@esaml2.com');
  t.is(extract.issuer, 'https://idp.example.com/metadata');
  t.is(typeof extract.logoutrequest.id, 'string');
  t.is(extract.logoutrequest.destination, 'https://sp.example.org/sp/slo');
  t.is(extract.signature, undefined); // redirect binding doesn't embed the signature
});

test('idp sends a post logout request without signature and sp parses it', async t => {
  const { relayState, type, entityEndpoint, id, context } = idp.createLogoutRequest(sp, 'post', { logoutNameID: 'user@esaml2.com' }) as PostBindingContext;
  t.is(typeof id, 'string');
  t.is(typeof context, 'string');
  t.is(typeof entityEndpoint, 'string');
  t.is(type, 'SAMLRequest');
  const { extract } = await sp.parseLogoutRequest(idp, 'post', { body: { SAMLRequest: context } });
  t.is(extract.nameid, 'user@esaml2.com');
  t.is(extract.issuer, 'https://idp.example.com/metadata');
  t.is(typeof extract.logoutrequest.id, 'string');
  t.is(extract.logoutrequest.destination, 'https://sp.example.org/sp/slo');
  t.is(extract.signature, undefined);
});

test('idp sends a post logout request with signature and sp parses it', async t => {
  const { relayState, type, entityEndpoint, id, context } = idp.createLogoutRequest(spWantLogoutReqSign, 'post', { logoutNameID: 'user@esaml2.com' }) as PostBindingContext;
  t.is(typeof id, 'string');
  t.is(typeof context, 'string');
  t.is(typeof entityEndpoint, 'string');
  t.is(type, 'SAMLRequest');
  const { extract } = await spWantLogoutReqSign.parseLogoutRequest(idp, 'post', { body: { SAMLRequest: context } });
  t.is(extract.nameid, 'user@esaml2.com');
  t.is(extract.issuer, 'https://idp.example.com/metadata');
  t.is(extract.logoutrequest.destination, 'https://sp.example.org/sp/slo');
  t.is(typeof extract.logoutrequest.id, 'string');
  t.is(typeof extract.signature, 'string');
});

// simulate init-slo
test('sp sends a post logout response without signature and parse', async t => {
  const { relayState, type, entityEndpoint, id, context: SAMLResponse } = sp.createLogoutResponse(idp, null, 'post', '', createTemplateCallback(idp, sp, {})) as PostBindingContext;
  const { samlContent, extract } = await idp.parseLogoutResponse(sp, 'post', { body: { SAMLResponse }});
  t.is(extract.signature, undefined);
  t.is(extract.issuer, 'https://sp.example.org/metadata');
  t.is(typeof extract.logoutresponse.id, 'string');
  t.is(extract.logoutresponse.destination, 'https://idp.example.org/sso/SingleLogoutService');
});

test('sp sends a post logout response with signature and parse', async t => {
  const { relayState, type, entityEndpoint, id, context: SAMLResponse } = sp.createLogoutResponse(idpWantLogoutResSign, null, 'post', '', createTemplateCallback(idpWantLogoutResSign, sp, {})) as PostBindingContext;
  const { samlContent, extract } = await idpWantLogoutResSign.parseLogoutResponse(sp, 'post', { body: { SAMLResponse }});
  t.is(typeof extract.signature, 'string');
  t.is(extract.issuer, 'https://sp.example.org/metadata');
  t.is(typeof extract.logoutresponse.id, 'string');
  t.is(extract.logoutresponse.destination, 'https://idp.example.org/sso/SingleLogoutService');
});

test('send login response with encrypted non-signed assertion with EncryptThenSign and parse it', async t => {
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idpEncryptThenSign.createLoginResponse(spNoAssertSignCustomConfig, sampleRequestInfo, 'post', user, createTemplateCallback(idpEncryptThenSign, spNoAssertSignCustomConfig, user), true);
  const { samlContent, extract } = await spNoAssertSignCustomConfig.parseLoginResponse(idpEncryptThenSign, 'post', { body: { SAMLResponse } });
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  t.is(extract.nameid, 'user@esaml2.com');
  t.is(typeof extract.signature, 'string');
});

test('Customize prefix (saml2) for encrypted assertion tag', async t => {
  const user = { email: 'test@email.com' };
  const idpCustomizePfx = identityProvider(Object.assign(defaultIdpConfig, { tagPrefix: {
    encryptedAssertion: 'saml2',
  }}));
  const { id, context: SAMLResponse } = await idpCustomizePfx.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idpCustomizePfx, sp, user));
  t.is((utility.base64Decode(SAMLResponse) as string).includes('saml2:EncryptedAssertion'), true);
  const { samlContent, extract } = await sp.parseLoginResponse(idpCustomizePfx, 'post', { body: { SAMLResponse } });
});

test('Customize prefix (default is saml) for encrypted assertion tag', async t => {
  const user = { email: 'test@email.com' };
  const { id, context: SAMLResponse } = await idp.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idp, sp, user));
  t.is((utility.base64Decode(SAMLResponse) as string).includes('saml:EncryptedAssertion'), true);
  const { samlContent, extract } = await sp.parseLoginResponse(idp, 'post', { body: { SAMLResponse } });
});

test('avoid mitm attack', async t => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const user = { email: 'user@email.com' };
  const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, sp, user));
  const rawResponse = String(utility.base64Decode(SAMLResponse, true));
  const attackResponse = `<NameID>evil@evil.com${rawResponse}</NameID>`;
  const error = await t.throws(sp.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse: utility.base64Encode(attackResponse) } }));
});


test.only('should reject signature wrapped response', async t => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, sp, user));
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  //Decode
  const buffer = new Buffer(SAMLResponse, 'base64');
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

  const wrappedResponse = new Buffer(xmlWrapped).toString('base64');

  const result = await sp.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse: wrappedResponse } });

  // ignore the tampering value
  t.is(result.extract.nameID, 'admin@esaml2.com');
  
  //should probalby be like this -> const error = await t.throws(sp.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse: wrappedResponse } }));
});
