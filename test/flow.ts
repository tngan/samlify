import esaml2 = require('../index');
import { readFileSync, writeFileSync } from 'fs';
import test from 'ava';
import { assign } from 'lodash';
import xpath from 'xpath';
import { DOMParser as dom } from 'xmldom';
import { xpath as select } from 'xml-crypto';
import * as _ from 'lodash';
import { PostRequestInfo } from '../src/entity';
import * as uuid from 'uuid';

const {
  IdentityProvider: identityProvider,
  ServiceProvider: serviceProvider,
  IdPMetadata: idpMetadata,
  SPMetadata: spMetadata,
  Utility: utility,
  SamlLib: libsaml,
  Constants: ref,
} = esaml2;

const getQueryParamByType = libsaml.getQueryParamByType;
const binding = ref.namespace.binding;
const algorithms = ref.algorithms;
const wording = ref.wording;
const signatureAlgorithms = algorithms.signature;

// Custom template
const loginResponseTemplate = {
  context: '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status><saml:Assertion ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}" InResponseTo="{InResponseTo}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{AttributeStatement}</saml:Assertion></samlp:Response>',
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
    IssueInstant: now,
    ConditionsNotBefore: now,
    ConditionsNotOnOrAfter: fiveMinutesLater,
    SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater,
    AssertionConsumerServiceURL: sp.entityMeta.getAssertionConsumerService(binding.post),
    EntityID: spEntityID,
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
const _spKeyFolder = './test/key/sp/';
const _spPrivPem = String(readFileSync(_spKeyFolder + 'privkey.pem'));
const _spPrivKey = _spKeyFolder + 'nocrypt.pem';
const _spPrivKeyPass = 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px';

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

// Define an identity provider
const idp = identityProvider(defaultIdpConfig);
const sp = serviceProvider(defaultSpConfig);
const idpNoEncrypt = identityProvider({ ...defaultIdpConfig, isAssertionEncrypted: false });
const idpcustomNoEncrypt = identityProvider({ ...defaultIdpConfig, isAssertionEncrypted: false, loginResponseTemplate });
const idpcustom = identityProvider({ ...defaultIdpConfig, loginResponseTemplate });

// Define metadata
const IdPMetadata = idpMetadata(readFileSync('./test/misc/idpmeta.xml'));
const SPMetadata = spMetadata(readFileSync('./test/misc/spmeta.xml'));
const sampleSignedResponse = readFileSync('./test/misc/response_signed.xml').toString();
const wrongResponse = readFileSync('./test/misc/invalid_response.xml').toString();
const spCertKnownGood = readFileSync('./test/key/sp/knownGoodCert.cer').toString().trim();
const spPemKnownGood = readFileSync('./test/key/sp/knownGoodEncryptKey.pem').toString().trim();
const noSignedIdpMetadata = readFileSync('./test/misc/idpmeta_nosign.xml').toString().trim();
const spmetaNoAssertSign = readFileSync('./test/misc/spmeta_noassertsign.xml').toString().trim();

function writer(str) {
  writeFileSync('test.txt', str);
}

test('create login request with redirect binding using default template', t => {
  const { id, context } = sp.createLoginRequest(idp, 'redirect');
  _.isString(id) && _.isString(context) ? t.pass() : t.fail();
});

test('create login request with post binding using default template', t => {
  const { relayState, type, entityEndpoint, id, context } = sp.createLoginRequest(idp, 'post') as PostRequestInfo;
  _.isString(id) && _.isString(context) && _.isString(entityEndpoint) && _.isEqual(type, 'SAMLRequest') ? t.pass() : t.fail();
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
  }) as PostRequestInfo;
  id === 'exposed_testing_id' &&
    _.isString(context) &&
    _.isString(relayState) &&
    _.isString(entityEndpoint) &&
    _.isEqual(type, 'SAMLRequest')
    ? t.pass() : t.fail();
});

test('create login response with undefined binding', async t => {
  const error = await t.throws(idp.createLoginResponse(sp, {}, 'undefined', { email: 'user@esaml2.com' }));
  t.is(error.message, 'this binding is not supported');
});

test('create post login response', async t => {
  const { id, context } = await idp.createLoginResponse(sp, null, 'post', { email: 'user@esaml2.com' });
  _.isString(id) && _.isString(context) ? t.pass() : t.fail();
});

test('create logout request with redirect binding', t => {
  const { id, context } = sp.createLogoutRequest(idp, 'redirect', { email: 'user@esaml2' });
  _.isString(id) && _.isString(context) ? t.pass() : t.fail();
});

test('create logout request with post binding', t => {
  const { relayState, type, entityEndpoint, id, context } = sp.createLogoutRequest(idp, 'post', { email: 'user@esaml2' }) as PostRequestInfo;
  _.isString(id) && _.isString(context) && _.isString(entityEndpoint) && _.isEqual(type, 'SAMLRequest') ? t.pass() : t.fail();
});

test('create logout response with undefined binding', t => {
  try {
    const { id, context } = idp.createLogoutResponse(sp, {}, 'undefined');
    t.fail();
  } catch (e) {
    t.is(e.message, 'this binding is not supported');
  }
});

test('create logout response with redirect binding', t => {
  const { id, context } = idp.createLogoutResponse(sp, {}, 'redirect');
  _.isString(id) && _.isString(context) ? t.pass() : t.fail();
});

test('create logout response with post binding', t => {
  const { relayState, type, entityEndpoint, id, context } = idp.createLogoutResponse(sp, {}, 'post') as PostRequestInfo;
  _.isString(id) && _.isString(context) && _.isString(entityEndpoint) && _.isEqual(type, 'SAMLResponse') ? t.pass() : t.fail();
});

// Check if the response data parsing is correct
// All test cases are using customize template

// simulate idp-initiated sso
test('send response with signed assertion and parse it', async t => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(sp, { extract: { authnrequest: { id: 'request_id' } } }, 'post', { email: 'user@esaml2.com' });
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await sp.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse } });
  // test phrase 1: samlContent is a string (parsed version)
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  // test phrase 2: useful information is included in extract object
  t.is(extract.nameid, 'user@esaml2.com');
  t.is(typeof extract.signature, 'string');
  t.pass();
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
  t.pass();
});

test('send response with signed message and parse it', async t => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const spNoAssertSign = serviceProvider({
    ...defaultSpConfig,
    metadata: spmetaNoAssertSign,
  });
  const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(spNoAssertSign, { extract: { authnrequest: { id: 'request_id' } } }, 'post', { email: 'user@esaml2.com' });
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spNoAssertSign.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse } });
  // test phrase 1: samlContent is a string (parsed version)
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  // test phrase 2: useful information is included in extract object
  t.is(extract.nameid, 'user@esaml2.com');
  t.is(typeof extract.signature, 'string');
  t.pass();
});

test('send response with [custom template] and signed message and parse it', async t => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const spNoAssertSign = serviceProvider({
    ...defaultSpConfig,
    metadata: spmetaNoAssertSign,
  });
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
  t.pass();
});

test('send login response with signed assertion + signed message and parse it', async t => {
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });
  const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(spWantMessageSign, { extract: { authnrequest: { id: 'request_id' } } }, 'post', { email: 'user@esaml2.com' });
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spWantMessageSign.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse } });
  // test phrase 1: samlContent is a string (parsed version)
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  // test phrase 2: useful information is included in extract object
  t.is(extract.nameid, 'user@esaml2.com');
  t.is(typeof extract.signature, 'object');
  t.pass();
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
  t.pass();
});

test('send login response with encrypted signed assertion and parse it', async t => {
  const { id, context: SAMLResponse } = await idp.createLoginResponse(sp, { extract: { authnrequest: { id: 'request_id' } } }, 'post', { email: 'user@esaml2.com' });
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await sp.parseLoginResponse(idp, 'post', { body: { SAMLResponse } });
  // test phrase 1: samlContent is a string (parsed version)
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  // test phrase 2: useful information is included in extract object
  t.is(extract.nameid, 'user@esaml2.com');
  t.is(typeof extract.signature, 'string');
  t.pass();
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
  t.pass();
});

test('send login response with encrypted signed assertion + signed message and parse it', async t => {
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });
  const { id, context: SAMLResponse } = await idp.createLoginResponse(spWantMessageSign, { extract: { authnrequest: { id: 'request_id' } } }, 'post', { email: 'user@esaml2.com' });
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spWantMessageSign.parseLoginResponse(idp, 'post', { body: { SAMLResponse } });
  // test phrase 1: samlContent is a string (parsed version)
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  // test phrase 2: useful information is included in extract object
  t.is(extract.nameid, 'user@esaml2.com');
  t.is(typeof extract.signature, 'object');
  t.pass();
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
  t.pass();
});
