import esaml2 = require('../index');
import { readFileSync, writeFileSync } from 'fs';
import test from 'ava';
import { assign } from 'lodash';
import xpath from 'xpath';
import { DOMParser as dom } from 'xmldom';
import { xpath as select } from 'xml-crypto';
import * as _ from 'lodash';
import { PostRequestInfo } from '../src/entity';

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
  metadata: readFileSync('./test/misc/IDPMetadata.xml'),
};

const defaultSpConfig = {
  privateKey: readFileSync('./test/key/sp/privkey.pem'),
  privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
  isAssertionEncrypted: true, // for logout purpose
  encPrivateKey: readFileSync('./test/key/sp/encryptKey.pem'),
  encPrivateKeyPass: 'BXFNKpxrsjrCkGA8cAu5wUVHOSpci1RU',
  metadata: readFileSync('./test/misc/SPMetadata.xml'),
};

// Define an identity provider
const idp = identityProvider(defaultIdpConfig);
const sp = serviceProvider(defaultSpConfig);

// Define metadata
const IdPMetadata = idpMetadata(readFileSync('./test/misc/IDPMetadata.xml'));
const SPMetadata = spMetadata(readFileSync('./test/misc/SPMetadata.xml'));
const sampleSignedResponse = readFileSync('./test/misc/SignSAMLResponse.xml').toString();
const wrongResponse = readFileSync('./test/misc/wrongResponse.xml').toString();
const spCertKnownGood = readFileSync('./test/key/sp/knownGoodCert.cer').toString().trim();
const spPemKnownGood = readFileSync('./test/key/sp/knownGoodEncryptKey.pem').toString().trim();
const noSignedIdpMetadata = readFileSync('./test/misc/NoSignIDPMetadata.xml').toString().trim();

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

test('create login request with redirect binding using custom template', t => {
  const _sp = serviceProvider({ ...defaultSpConfig, loginRequestTemplate: {
    context: '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="{AllowCreate}"/></samlp:AuthnRequest>',
  }});
  const { id, context } = _sp.createLoginRequest(idp, 'redirect', template => {
    return {
      id: 'exposed_testing_id',
      context: template, // all the tags are supposed to be replaced
    };
  });
  (id === 'exposed_testing_id' && _.isString(context)) ? t.pass() : t.fail();
});

test('create login request with post binding using custom template', t => {
  const _sp = serviceProvider({ ...defaultSpConfig, loginRequestTemplate: {
    context: '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="{AllowCreate}"/></samlp:AuthnRequest>',
  }});
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
  _.isString(id)  && _.isString(context) ? t.pass() : t.fail();
});
