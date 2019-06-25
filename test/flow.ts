import esaml2 = require('../index');
import { readFileSync, writeFileSync } from 'fs';
import test from 'ava';
import { PostBindingContext } from '../src/entity';
import * as uuid from 'uuid';
import * as url from 'url';
import util from '../src/utility';

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

const createTemplateCallback = (_idp, _sp, user) => template => {
  const _id =  '_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6';
  const now = new Date();
  const spEntityID = _sp.entityMeta.getEntityID();
  const idpSetting = _idp.entitySetting;
  const fiveMinutesLater = new Date(now.getTime());
  fiveMinutesLater.setMinutes(fiveMinutesLater.getMinutes() + 5);
  const tvalue = {
    ID: _id,
    AssertionID: idpSetting.generateID ? idpSetting.generateID() : `${uuid.v4()}`,
    Destination: _sp.entityMeta.getAssertionConsumerService(binding.post),
    Audience: spEntityID,
    SubjectRecipient: spEntityID,
    NameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    NameID: user.email,
    Issuer: idp.entityMeta.getEntityID(),
    IssueInstant: now.toISOString(),
    ConditionsNotBefore: now.toISOString(),
    ConditionsNotOnOrAfter: fiveMinutesLater.toISOString(),
    SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater.toISOString(),
    AssertionConsumerServiceURL: _sp.entityMeta.getAssertionConsumerService(binding.post),
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
  const octetString = Object.keys(originalURL.query).map(q => q + '=' + encodeURIComponent(originalURL.query[q] as string)).join('&');
  const { samlContent, extract } = await idp.parseLoginRequest(sp, 'redirect', { query: { SAMLRequest, Signature, SigAlg }, octetString});
  t.is(extract.issuer, 'https://sp.example.org/metadata');
  t.is(typeof extract.request.id, 'string');
  t.is(extract.nameIDPolicy.format, 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
  t.is(extract.nameIDPolicy.allowCreate, 'false');
});

test('create login request with post binding using default template and parse it', async t => {
  const { relayState, type, entityEndpoint, id, context: SAMLRequest } = sp.createLoginRequest(idp, 'post') as PostBindingContext;
  t.is(typeof id, 'string');
  t.is(typeof SAMLRequest, 'string');
  t.is(typeof entityEndpoint, 'string');
  t.is(type, 'SAMLRequest');
  const { extract } = await idp.parseLoginRequest(sp, 'post', { body: { SAMLRequest }});
  t.is(extract.issuer, 'https://sp.example.org/metadata');
  t.is(typeof extract.request.id, 'string');
  t.is(extract.nameIDPolicy.format, 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
  t.is(extract.nameIDPolicy.allowCreate, 'false');
  t.is(typeof extract.signature, 'string');
});

test('signed in sp is not matched with the signed notation in idp with post request', t => {
  const _idp = identityProvider({ ...defaultIdpConfig, metadata: noSignedIdpMetadata });
  try {
    const { id, context } = sp.createLoginRequest(_idp, 'post');
    t.fail();
  } catch (e) {
    t.is(e.message, 'ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG');
  }
});

test('signed in sp is not matched with the signed notation in idp with redirect request', t => {
  const _idp = identityProvider({ ...defaultIdpConfig, metadata: noSignedIdpMetadata });
  try {
    const { id, context } = sp.createLoginRequest(_idp, 'redirect');
    t.fail();
  } catch (e) {
    t.is(e.message, 'ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG');
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
  (id === 'exposed_testing_id' && isString(context)) ? t.pass() : t.fail();
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
    isString(context) &&
    isString(relayState) &&
    isString(entityEndpoint) &&
    type === 'SAMLRequest'
    ? t.pass() : t.fail();
});

test('create login response with undefined binding', async t => {
  const user = { email: 'user@esaml2.com' };
  const error = await t.throwsAsync(() => idp.createLoginResponse(sp, {}, 'undefined', user, createTemplateCallback(idp, sp, user)));
  t.is(error.message, 'ERR_CREATE_RESPONSE_UNDEFINED_BINDING');
});

test('create post login response', async t => {
  const user = { email: 'user@esaml2.com' };
  const { id, context } = await idp.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idp, sp, user));
  isString(id) && isString(context) ? t.pass() : t.fail();
});

test('create logout request with redirect binding', t => {
  const { id, context } = sp.createLogoutRequest(idp, 'redirect', { logoutNameID: 'user@esaml2' });
  isString(id) && isString(context) ? t.pass() : t.fail();
});

test('create logout request with post binding', t => {
  const { relayState, type, entityEndpoint, id, context } = sp.createLogoutRequest(idp, 'post', { logoutNameID: 'user@esaml2' }) as PostBindingContext;
  isString(id) && isString(context) && isString(entityEndpoint) && type === 'SAMLRequest' ? t.pass() : t.fail();
});

test('create logout request when idp only has one binding', t => {
  const testIdp = identityProvider(oneloginIdpConfig);
  const { id, context } = sp.createLogoutRequest(testIdp, 'redirect', { logoutNameID: 'user@esaml2' });
  isString(id) && isString(context) ? t.pass() : t.fail();
});

test('create logout response with undefined binding', t => {
  try {
    const { id, context } = idp.createLogoutResponse(sp, {}, 'undefined', '', createTemplateCallback(idp, sp, {}));
    t.fail();
  } catch (e) {
    t.is(e.message, 'ERR_CREATE_LOGOUT_RESPONSE_UNDEFINED_BINDING');
  }
});

test('create logout response with redirect binding', t => {
  const { id, context } = idp.createLogoutResponse(sp, {}, 'redirect', '', createTemplateCallback(idp, sp, {}));
  isString(id) && isString(context) ? t.pass() : t.fail();
});

test('create logout response with post binding', t => {
  const { relayState, type, entityEndpoint, id, context } = idp.createLogoutResponse(sp, {}, 'post', '', createTemplateCallback(idp, sp, {})) as PostBindingContext;
  isString(id) && isString(context) && isString(entityEndpoint) && type === 'SAMLResponse' ? t.pass() : t.fail();
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
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  t.is(extract.nameID, 'user@esaml2.com');
  t.is(extract.response.inResponseTo, 'request_id');
});

test('send response with signed assertion + custom transformation algorithms and parse it', async t => {
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
  const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(signedAssertionSp, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, sp, user));
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await sp.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse } });
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  t.is(extract.nameID, 'user@esaml2.com');
  t.is(extract.response.inResponseTo, 'request_id');

  // Verify xmldsig#enveloped-signature is included in the response
  if (samlContent.indexOf('http://www.w3.org/2000/09/xmldsig#enveloped-signature') === -1) {
    t.fail();
  }
});

test('send response with [custom template] signed assertion and parse it', async t => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const requestInfo = { extract: { request: { id: 'request_id' } } };
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
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  t.is(extract.nameID, 'user@esaml2.com');
  t.is(extract.attributes.name, 'mynameinsp');
  t.is(extract.attributes.mail, 'myemailassociatedwithsp@sp.com');
  t.is(extract.response.inResponseTo, '_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});

test('send response with signed message and parse it', async t => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(spNoAssertSign, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, spNoAssertSign, user));
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spNoAssertSign.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse } });
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  t.is(extract.nameID, 'user@esaml2.com');
  t.is(extract.response.inResponseTo, 'request_id');
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
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  t.is(extract.nameID, 'user@esaml2.com');
  t.is(extract.attributes.name, 'mynameinsp');
  t.is(extract.attributes.mail, 'myemailassociatedwithsp@sp.com');
  t.is(extract.response.inResponseTo, '_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});

test('send login response with signed assertion + signed message and parse it', async t => {
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(spWantMessageSign, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, spWantMessageSign, user));
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spWantMessageSign.parseLoginResponse (idpNoEncrypt, 'post', { body: { SAMLResponse } });
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  t.is(extract.nameID, 'user@esaml2.com');
  t.is(extract.response.inResponseTo, 'request_id');
});

test('send login response with [custom template] and signed assertion + signed message and parse it', async t => {
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });
  const user = { email: 'user@esaml2.com'};
  const { id, context: SAMLResponse } = await idpcustomNoEncrypt.createLoginResponse(
    spWantMessageSign,
    { extract: { authnrequest: { id: 'request_id' } } }, 'post',
    { email: 'user@esaml2.com' },
    createTemplateCallback(idpcustomNoEncrypt, spWantMessageSign, user),
  );
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spWantMessageSign.parseLoginResponse(idpcustomNoEncrypt, 'post', { body: { SAMLResponse } });
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  t.is(extract.nameID, 'user@esaml2.com');
  t.is(extract.attributes.name, 'mynameinsp');
  t.is(extract.attributes.mail, 'myemailassociatedwithsp@sp.com');
  t.is(extract.response.inResponseTo, '_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});

test('send login response with encrypted non-signed assertion and parse it', async t => {
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idp.createLoginResponse(spNoAssertSign, sampleRequestInfo, 'post', user, createTemplateCallback(idp, spNoAssertSign, user));
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await spNoAssertSign.parseLoginResponse(idp, 'post', { body: { SAMLResponse } });
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  t.is(extract.nameID, 'user@esaml2.com');
  t.is(extract.response.inResponseTo, 'request_id');
});

test('send login response with encrypted signed assertion and parse it', async t => {
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idp.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idp, sp, user));
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await sp.parseLoginResponse(idp, 'post', { body: { SAMLResponse } });
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  t.is(extract.nameID, 'user@esaml2.com');
  t.is(extract.response.inResponseTo, 'request_id');
});

test('send login response with [custom template] and encrypted signed assertion and parse it', async t => {
  const user = { email: 'user@esaml2.com'};
  const { id, context: SAMLResponse } = await idpcustom.createLoginResponse(
    sp,
    { extract: { request: { id: 'request_id' } } }, 'post',
    { email: 'user@esaml2.com' },
    createTemplateCallback(idpcustom, sp, user),
  );
  // receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const { samlContent, extract } = await sp.parseLoginResponse(idpcustom, 'post', { body: { SAMLResponse } });
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  t.is(extract.nameID, 'user@esaml2.com');
  t.is(extract.attributes.name, 'mynameinsp');
  t.is(extract.attributes.mail, 'myemailassociatedwithsp@sp.com');
  t.is(extract.response.inResponseTo, '_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
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

  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  t.is(extract.nameID, 'user@esaml2.com');
  t.is(extract.response.inResponseTo, 'request_id');
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
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  t.is(extract.nameID, 'user@esaml2.com');
  t.is(extract.attributes.name, 'mynameinsp');
  t.is(extract.attributes.mail, 'myemailassociatedwithsp@sp.com');
  t.is(extract.response.inResponseTo, '_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});

// simulate idp-init slo
test('idp sends a redirect logout request without signature and sp parses it', async t => {
  const { id, context } = idp.createLogoutRequest(sp, 'redirect', { logoutNameID: 'user@esaml2.com' });
  const query = url.parse(context).query;
  t.is(query!.includes('SAMLRequest='), true);
  t.is(typeof id, 'string');
  t.is(typeof context, 'string');
  const originalURL = url.parse(context, true);
  const SAMLRequest = encodeURIComponent(originalURL.query.SAMLRequest as string);
  let result;
  const { samlContent, extract } = result = await sp.parseLogoutRequest(idp, 'redirect', { query: { SAMLRequest }});
  t.is(result.sigAlg, null);
  t.is(typeof samlContent, 'string');
  t.is(extract.nameID, 'user@esaml2.com');
  t.is(extract.signature, null);
  t.is(typeof extract.request.id, 'string');
  t.is(extract.request.destination, 'https://sp.example.org/sp/slo');
  t.is(extract.issuer, 'https://idp.example.com/metadata');
});

test('idp sends a redirect logout request with signature and sp parses it', async t => {
  const { id, context } = idp.createLogoutRequest(spWantLogoutReqSign, 'redirect', { logoutNameID: 'user@esaml2.com' });
  const query = url.parse(context).query;
  t.is(query!.includes('SAMLRequest='), true);
  t.is(query!.includes('SigAlg='), true);
  t.is(query!.includes('Signature='), true);
  t.is(typeof id, 'string');
  t.is(typeof context, 'string');
  const originalURL = url.parse(context, true);
  const SAMLRequest = originalURL.query.SAMLRequest;
  const Signature = originalURL.query.Signature;
  const SigAlg = originalURL.query.SigAlg;
  delete originalURL.query.Signature;
  const octetString = Object.keys(originalURL.query).map(q => q + '=' + encodeURIComponent(originalURL.query[q] as string)).join('&');
  const { extract } = await spWantLogoutReqSign.parseLogoutRequest(idp, 'redirect', { query: { SAMLRequest, Signature, SigAlg }, octetString});
  t.is(extract.nameID, 'user@esaml2.com');
  t.is(extract.issuer, 'https://idp.example.com/metadata');
  t.is(typeof extract.request.id, 'string');
  t.is(extract.request.destination, 'https://sp.example.org/sp/slo');
  t.is(extract.signature, null); // redirect binding doesn't embed the signature
});

test('idp sends a post logout request without signature and sp parses it', async t => {
  const { relayState, type, entityEndpoint, id, context } = idp.createLogoutRequest(sp, 'post', { logoutNameID: 'user@esaml2.com' }) as PostBindingContext;
  t.is(typeof id, 'string');
  t.is(typeof context, 'string');
  t.is(typeof entityEndpoint, 'string');
  t.is(type, 'SAMLRequest');
  const { extract } = await sp.parseLogoutRequest(idp, 'post', { body: { SAMLRequest: context } });
  t.is(extract.nameID, 'user@esaml2.com');
  t.is(extract.issuer, 'https://idp.example.com/metadata');
  t.is(typeof extract.request.id, 'string');
  t.is(extract.request.destination, 'https://sp.example.org/sp/slo');
  t.is(extract.signature, null);
});

test('idp sends a post logout request with signature and sp parses it', async t => {
  const { relayState, type, entityEndpoint, id, context } = idp.createLogoutRequest(spWantLogoutReqSign, 'post', { logoutNameID: 'user@esaml2.com' }) as PostBindingContext;
  t.is(typeof id, 'string');
  t.is(typeof context, 'string');
  t.is(typeof entityEndpoint, 'string');
  t.is(type, 'SAMLRequest');
  const { extract } = await spWantLogoutReqSign.parseLogoutRequest(idp, 'post', { body: { SAMLRequest: context } });
  t.is(extract.nameID, 'user@esaml2.com');
  t.is(extract.issuer, 'https://idp.example.com/metadata');
  t.is(extract.request.destination, 'https://sp.example.org/sp/slo');
  t.is(typeof extract.request.id, 'string');
  t.is(typeof extract.signature, 'string');
});

// simulate init-slo
test('sp sends a post logout response without signature and parse', async t => {
  const { context: SAMLResponse } = sp.createLogoutResponse(idp, null, 'post', '', createTemplateCallback(idp, sp, {})) as PostBindingContext;
  const { samlContent, extract } = await idp.parseLogoutResponse(sp, 'post', { body: { SAMLResponse }});
  t.is(extract.signature, null);
  t.is(extract.issuer, 'https://sp.example.org/metadata');
  t.is(typeof extract.response.id, 'string');
  t.is(extract.response.destination, 'https://idp.example.org/sso/SingleLogoutService');
});

test('sp sends a post logout response with signature and parse', async t => {
  const { relayState, type, entityEndpoint, id, context: SAMLResponse } = sp.createLogoutResponse(idpWantLogoutResSign, sampleRequestInfo, 'post', '', createTemplateCallback(idpWantLogoutResSign, sp, {})) as PostBindingContext;
  const { samlContent, extract } = await idpWantLogoutResSign.parseLogoutResponse(sp, 'post', { body: { SAMLResponse }});
  t.is(typeof extract.signature, 'string');
  t.is(extract.issuer, 'https://sp.example.org/metadata');
  t.is(typeof extract.response.id, 'string');
  t.is(extract.response.destination, 'https://idp.example.org/sso/SingleLogoutService');
});

test('send login response with encrypted non-signed assertion with EncryptThenSign and parse it', async t => {
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idpEncryptThenSign.createLoginResponse(spNoAssertSignCustomConfig, sampleRequestInfo, 'post', user, createTemplateCallback(idpEncryptThenSign, spNoAssertSignCustomConfig, user), true);
  const { samlContent, extract } = await spNoAssertSignCustomConfig.parseLoginResponse(idpEncryptThenSign, 'post', { body: { SAMLResponse } });
  t.is(typeof id, 'string');
  t.is(samlContent.startsWith('<samlp:Response'), true);
  t.is(samlContent.endsWith('/samlp:Response>'), true);
  t.is(extract.nameID, 'user@esaml2.com');
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

test('avoid malformatted response', async t => {
  // sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
  const user = { email: 'user@email.com' };
  const { context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, sp, user));
  const rawResponse = String(utility.base64Decode(SAMLResponse, true));
  const attackResponse = `<NameID>evil@evil.com${rawResponse}</NameID>`;
  try {
    await sp.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse: utility.base64Encode(attackResponse) } });
  } catch (e) {
    // it must throw an error
    t.is(true, true);
  }
});

test('should reject signature wrapped response - case 1', async t => {
  // 
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, sp, user));
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
  try {
    await sp.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse: wrappedResponse } });
  } catch (e) {
    t.is(e.message, 'ERR_POTENTIAL_WRAPPING_ATTACK');
  }
});

test('should reject signature wrapped response - case 2', async t => {
  // 
  const user = { email: 'user@esaml2.com' };
  const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idpNoEncrypt, sp, user));
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
  const xmlWrapped = outer.replace(/<\/saml:Conditions>/, '</saml:Conditions><saml:Advice>' + stripped.replace('<?xml version="1.0" encoding="UTF-8"?>', '') + '</saml:Advice>');
  const wrappedResponse = new Buffer(xmlWrapped).toString('base64');
  try {
    const result = await sp.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse: wrappedResponse } });
  } catch (e) {
    t.is(e.message, 'ERR_POTENTIAL_WRAPPING_ATTACK');
  }
});

test('should throw two-tiers code error when the response does not return success status', async t => {
  const failedResponse: string = String(readFileSync('./test/misc/failed_response.xml'));
  try {
    const _result = await sp.parseLoginResponse(idpNoEncrypt, 'post', { body: { SAMLResponse: utility.base64Encode(failedResponse) } });
  } catch (e) {
    t.is(e.message, 'ERR_FAILED_STATUS with top tier code: urn:oasis:names:tc:SAML:2.0:status:Requester, second tier code: urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy');
  }
});