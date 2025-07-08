import * as esaml2 from '../index.js';
import {readFileSync, writeFileSync} from 'fs';
import {describe, test, expect} from 'vitest';
import {PostBindingContext, SimpleSignBindingContext} from '../src/entity.js';
import * as uuid from 'uuid';
import * as url from 'url';
import xmlEscape from './xmlEscape.js'
import util from '../src/utility.js';
import  *  as tk from 'timekeeper'
function escapeTag(text) {
  return function (match, quote) {
    if (quote) {
      text = xmlEscape(text);
      return quote ? `${quote}${xmlEscape(text || '')}` : text;
    } else {
      return text;
    }
  }
}

export interface BindingContext {
  context: string;
  id: string;
}

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
    {
      name: 'mail',
      valueTag: 'user.email',
      nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
      valueXsiType: 'xs:string'
    },
    {
      name: 'name',
      valueTag: 'user.name',
      nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
      valueXsiType: 'xs:string'
    },
  ],
};

const failedResponse: string = String(readFileSync('./test/misc/failed_response.xml'));

function replaceTagsByValue(rawXML, tagValues) {
  Object.keys(tagValues).forEach(t => {
    rawXML = rawXML.replace(new RegExp(`("?)\\{${t}\\}`, 'g'), escapeTag(tagValues[t]));
  });
  return rawXML;
}

function createTemplateCallback({
                                  requestInfo = {}, entity, user = {
    NameID: "myemailassociatedwithsp@sp.com"
  }, relayState = "", context = {}, binding = "binding", AttributeStatement = []
                                }) {

  const idpSetting = entity.idp.entitySetting;
  const spSetting = entity.sp.entitySetting;
  /*  const id = idpSetting.generateID();*/
  const _id = '_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6';
  const metadata = {
    idp: entity.idp.entityMeta, sp: entity.sp.entityMeta,
  };
  const nameIDFormat = idpSetting.nameIDFormat;
  const selectedNameIDFormat = Array.isArray(nameIDFormat) ? nameIDFormat[0] : nameIDFormat;
  if (metadata && metadata.idp && metadata.sp) {
    const base = metadata.sp.getAssertionConsumerService(binding);
    let SamlResponse;
    const nowTime = new Date();
    const spEntityID = metadata.sp.getEntityID();
    const oneMinutesLaterTime = new Date(nowTime.getTime());
    oneMinutesLaterTime.setMinutes(oneMinutesLaterTime.getMinutes() + 5);
    const OneMinutesLater = oneMinutesLaterTime.toISOString();
    const now = nowTime.toISOString();

    const acl = metadata.sp.getAssertionConsumerService(binding);
    /*    const sessionIndex = 'Index_' + customId(64); // 这个是当前系统的会话索引，用于单点注销*/
    const tenHoursLaterTime = new Date(nowTime.getTime());
    tenHoursLaterTime.setHours(tenHoursLaterTime.getHours() + 10);
    const tenHoursLater = tenHoursLaterTime.toISOString();
    const tvalue = {
      ID: _id,
      AssertionID: idpSetting.generateID ? idpSetting.generateID() : `${uuid.v4()}`,
      Destination: base,
      Audience: spEntityID,
      EntityID: spEntityID,
      SubjectRecipient: acl,
      Issuer: metadata.idp.getEntityID(),
      IssueInstant: now,
      AssertionConsumerServiceURL: acl,
      StatusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',
      ConditionsNotBefore: now,
      ConditionsNotOnOrAfter: OneMinutesLater,
      SubjectConfirmationDataNotOnOrAfter: OneMinutesLater,
      NameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      NameID: user?.NameID ?? '',
      InResponseTo: '_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4',
      // AuthnStatement: `<saml:AuthnStatement AuthnInstant="${now}" SessionNotOnOrAfter="${tenHoursLater}" SessionIndex="${sessionIndex}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`,
      AttributeStatement: AttributeStatement ?? [],
      ...context
    };

    SamlResponse = replaceTagsByValue(idpSetting.loginResponseTemplate.context, tvalue);

    return {
      id: _id, context: SamlResponse,
    }
  }
}


// Parse Redirect Url context
const parseRedirectUrlContextCallBack = (_context: string) => {
  const originalURL = url.parse(_context, true);
  const _SAMLResponse = originalURL.query.SAMLResponse;
  const _Signature = originalURL.query.Signature;
  const _SigAlg = originalURL.query.SigAlg;
  delete originalURL.query.Signature;
  const _octetString = Object.keys(originalURL.query).map(q => q + '=' + encodeURIComponent(originalURL.query[q] as string)).join('&');
  console.log({
    query: {
      SAMLResponse: _SAMLResponse,
      Signature: _Signature,
      SigAlg: _SigAlg,
    },
    octetString: _octetString,
  })
  console.log("看下对象----------------------")
  return {
    query: {
      SAMLResponse: _SAMLResponse,
      Signature: _Signature,
      SigAlg: _SigAlg,
    },
    octetString: _octetString,
  };
};

// Build SimpleSign octetString
const buildSimpleSignOctetString = (type: string, context: string, sigAlg: string | undefined, relayState: string | undefined, signature: string | undefined) => {
  const rawRequest = String(utility.base64Decode(context, true));
  let octetString: string = '';
  octetString += type + '=' + rawRequest;
  if (relayState !== undefined && relayState.length > 0) {
    octetString += '&RelayState=' + relayState;
  }
  if (signature !== undefined && signature.length > 0 && sigAlg && sigAlg.length > 0) {
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

const sampleRequestInfo = {extract: {request: {id: 'request_id'}}};

// Define entities
const idp = identityProvider(defaultIdpConfig);
const sp = serviceProvider(defaultSpConfig);
const idpNoEncrypt = identityProvider({...defaultIdpConfig, isAssertionEncrypted: false});
const idpcustomNoEncrypt = identityProvider({...defaultIdpConfig, isAssertionEncrypted: false, loginResponseTemplate});
const idpcustom = identityProvider({...defaultIdpConfig, loginResponseTemplate});
const idpEncryptThenSign = identityProvider({...defaultIdpConfig, messageSigningOrder: 'encrypt-then-sign'});
const spWantLogoutReqSign = serviceProvider({...defaultSpConfig, wantLogoutRequestSigned: true});
const idpWantLogoutResSign = identityProvider({...defaultIdpConfig, wantLogoutResponseSigned: true});
const spNoAssertSign = serviceProvider({...defaultSpConfig, metadata: spmetaNoAssertSign, wantMessageSigned: false});
const spNoAssertSignCustomConfig = serviceProvider({
  ...defaultSpConfig,
  metadata: spmetaNoAssertSign,
  signatureConfig: {
    prefix: 'ds',
    location: {reference: "/*[local-name(.)='Response']/*[local-name(.)='Issuer']", action: 'after'},
  },
});
const spWithClockDrift = serviceProvider({...defaultSpConfig, clockDrifts: [-2000, 2000]});

function writer(str: string) {
  writeFileSync('test.txt', str);
}

describe('SAML Login Request Tests', () => {
  test('create login request with redirect binding using default template and parse it', async () => {
    const { id, context } = sp.createLoginRequest(idp, 'redirect');
    expect(typeof id).toBe('string');
    expect(typeof context).toBe('string');

    const originalURL = url.parse(context, true);
    const SAMLRequest = originalURL.query.SAMLRequest;
    const Signature = originalURL.query.Signature;
    const SigAlg = originalURL.query.SigAlg;
    delete originalURL.query.Signature;

    const octetString = Object.keys(originalURL.query)
      .map(q => `${q}=${encodeURIComponent(originalURL.query[q] as string)}`)
      .join('&');
    const { extract } = await idp.parseLoginRequest(sp, 'redirect', {
      query: { SAMLRequest, Signature, SigAlg },
      octetString
    });
    expect(extract.issuer).toBe('https://sp.example.org/metadata');
    expect(typeof extract.request.id).toBe('string');
    expect(extract.nameIDPolicy.format).toBe('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
    expect(extract.nameIDPolicy.allowCreate).toBe('false');
  });

  test('create login request with post simpleSign binding using default template and parse it', async () => {
    const {
      relayState,
      id,
      context: SAMLRequest,
      type,
      sigAlg,
      signature
    } = sp.createLoginRequest(idp, 'simpleSign') as SimpleSignBindingContext;

    expect(typeof id).toBe('string');
    expect(typeof SAMLRequest).toBe('string');

    const octetString = buildSimpleSignOctetString(
      type,
      SAMLRequest,
      sigAlg,
      relayState,
      signature
    );

    const { extract } = await idp.parseLoginRequest(sp, 'simpleSign', {
      body: { SAMLRequest, Signature: signature, SigAlg: sigAlg },
      octetString
    });

    expect(extract.issuer).toBe('https://sp.example.org/metadata');
    expect(typeof extract.request.id).toBe('string');
    expect(extract.nameIDPolicy.format).toBe('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
    expect(extract.nameIDPolicy.allowCreate).toBe('false');
  });
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

  expect(() => {
    sp.createLoginRequest(_idp, 'post');
  }).toThrowError('ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG');
});

test('signed in sp is not matched with the signed notation in idp with redirect request', () => {
  const _idp = identityProvider({ ...defaultIdpConfig, metadata: noSignedIdpMetadata });

  expect(() => {
    sp.createLoginRequest(_idp, 'redirect');
  }).toThrowError('ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG');
});

test('signed in sp is not matched with the signed notation in idp with post simpleSign request', () => {
  const _idp = identityProvider({ ...defaultIdpConfig, metadata: noSignedIdpMetadata });

  expect(() => {
    sp.createLoginRequest(_idp, 'simpleSign');
  }).toThrowError('ERR_METADATA_CONFLICT_REQUEST_SIGNED_FLAG');
});

test('create login request with redirect binding using custom template', () => {
  const _sp = serviceProvider({
    ...defaultSpConfig,
    loginRequestTemplate: {
      context: '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="{AllowCreate}"/></samlp:AuthnRequest>',
    },
  });

  const result = _sp.createLoginRequest(idp, 'redirect', template => ({
    id: 'exposed_testing_id',
    context: template,
  }));

  expect(result.id).toBe('exposed_testing_id');
  expect(isString(result.context)).toBe(true);
});

test('create login request with redirect binding signing with unencrypted PKCS#8', () => {
  const _sp = serviceProvider({
    authnRequestsSigned: true,
    signingCert: readFileSync('./test/key/sp/cert.unencrypted.pkcs8.cer', 'utf-8'),
    privateKey: readFileSync('./test/key/sp/privkey.unencrypted.pkcs8.pem', 'utf-8'),
    privateKeyPass: undefined,
  });

  const { context } = _sp.createLoginRequest(idp, 'redirect');
  const parsed = parseRedirectUrlContextCallBack(context);
  const signature = Buffer.from(parsed.query.Signature as string, 'base64');

  const valid = libsaml.verifyMessageSignature(
    _sp.entityMeta,
    parsed.octetString,
    signature,
    parsed.query.SigAlg as string
  );

  expect(valid).toBe(true);
});

test('create login request with redirect binding signing with encrypted PKCS#8', () => {
  const _sp = serviceProvider({
    authnRequestsSigned: true,
    signingCert: readFileSync('./test/key/sp/cert.encrypted.pkcs8.cer', 'utf-8'),
    privateKey: readFileSync('./test/key/sp/privkey.encrypted.pkcs8.pem', 'utf-8'),
    privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
  });

  const { context } = _sp.createLoginRequest(idp, 'redirect');
  const parsed = parseRedirectUrlContextCallBack(context);
  const signature = Buffer.from(parsed.query.Signature as string, 'base64');

  const valid = libsaml.verifyMessageSignature(
    _sp.entityMeta,
    parsed.octetString,
    signature,
    parsed.query.SigAlg as string
  );

  expect(valid).toBe(true);
});

test('create login request with post binding using custom template', () => {
  const _sp = serviceProvider({
    ...defaultSpConfig,
    loginRequestTemplate: {
      context: '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="{AllowCreate}"/></samlp:AuthnRequest>',
    },
  });

  const result = _sp.createLoginRequest(idp, 'post', template => ({
    id: 'exposed_testing_id',
    context: template,
  })) as PostBindingContext;

  expect(result.id).toBe('exposed_testing_id');
  expect(isString(result.context)).toBe(true);
  expect(isString(result.relayState)).toBe(true);
  expect(isString(result.entityEndpoint)).toBe(true);
  expect(result.type).toBe('SAMLRequest');
});

test('create login request with post simpleSign binding using custom template', () => {
  const _sp = serviceProvider({
    ...defaultSpConfig,
    loginRequestTemplate: {
      context: '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="{AllowCreate}"/></samlp:AuthnRequest>',
    },
  });

  const result = _sp.createLoginRequest(idp, 'simpleSign', template => ({
    id: 'exposed_testing_id',
    context: template,
  })) as SimpleSignBindingContext;

  expect(result.id).toBe('exposed_testing_id');
  expect(isString(result.context)).toBe(true);
  expect(isString(result.relayState)).toBe(true);
  expect(isString(result.entityEndpoint)).toBe(true);
  expect(isString(result.signature)).toBe(true);
  expect(isString(result.sigAlg)).toBe(true);
  expect(result.type).toBe('SAMLRequest');
});


test('create login response with undefined binding', async () => {
  const user = { NameID: 'user@esaml2.com' ,userName:"test@163.com"};
  await expect(idp.createLoginResponse({
    sp: sp,
    requestInfo: {},
    binding: 'undefined' as any,
    user: user,
    customTagReplacement(template){
    return  createTemplateCallback({
        entity: {
          idp: idp,
          sp: sp
        },
        user: user,
        binding: binding.post
      });
    }
  })).rejects.toThrowError('ERR_CREATE_RESPONSE_UNDEFINED_BINDING');
});

test('create redirect login response', async () => {
  const user = { NameID: 'user@esaml2.com' };

  const result = await idp.createLoginResponse({
    sp: sp,
    requestInfo: sampleRequestInfo,
    binding: 'redirect',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idp,
        sp: sp
      },
      user: user,
      binding: 'redirect',
      requestInfo: sampleRequestInfo
    }),
    relayState: 'relaystate'
  });

  expect(isString(result.id)).toBe(true);
  expect(isString(result.context)).toBe(true);
});

test('create post simpleSign login response', async () => {
  const user = { NameID: 'user@esaml2.com' };

  const result = await idp.createLoginResponse({
    sp: sp,
    requestInfo: sampleRequestInfo,
    binding: 'simpleSign',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idp,
        sp: sp
      },
      user: user,
      binding: 'simpleSign',
      requestInfo: sampleRequestInfo
    }),
    relayState: 'relaystate'
  }) as SimpleSignBindingContext;

  expect(isString(result.id)).toBe(true);
  expect(isString(result.context)).toBe(true);
  expect(isString(result.entityEndpoint)).toBe(true);
  expect(isString(result.signature)).toBe(true);
  expect(isString(result.sigAlg)).toBe(true);
});

test('create post login response', async () => {
  const user = { NameID: 'user@esaml2.com' };

  const result = await idp.createLoginResponse({
    sp: sp,
    requestInfo: sampleRequestInfo,
    binding: 'post',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idp,
        sp: sp
      },
      user: user,
      binding: 'post',
      requestInfo: sampleRequestInfo
    })
  });

  expect(isString(result.id)).toBe(true);
  expect(isString(result.context)).toBe(true);
});
test('create logout request with redirect binding', () => {
  const result = sp.createLogoutRequest(idp, 'redirect', { NameID: 'user@esaml2' });
  expect(isString(result.id)).toBe(true);
  expect(isString(result.context)).toBe(true);
});

test('create logout request with post binding', () => {
  const result = sp.createLogoutRequest(idp, 'post', { NameID: 'user@esaml2' }) as PostBindingContext;
  expect(isString(result.id)).toBe(true);
  expect(isString(result.context)).toBe(true);
  expect(isString(result.entityEndpoint)).toBe(true);
  expect(result.type).toBe('SAMLRequest');
});

test('create logout request when idp only has one binding', () => {
  const testIdp = identityProvider(oneloginIdpConfig);
  const { id, context } = sp.createLogoutRequest(testIdp, 'redirect', { NameID: 'user@esaml2' });

  expect(isString(id) && isString(context)).toBe(true);
});

test('create logout response with undefined binding', () => {
  expect(() => {
    idp.createLogoutResponse(
      sp,
      {},
      'undefined' as any,
      '',
      () => createTemplateCallback({
        entity: {
          idp: idp,
          sp: sp
        },
        binding: binding.post
      })
    );
  }).toThrowError('ERR_CREATE_LOGOUT_RESPONSE_UNDEFINED_BINDING');
});

test('create logout response with redirect binding', function() {
  const { id, context } = idp.createLogoutResponse(
    sp,
    {},
    'redirect',
    '',
    function() {
      return createTemplateCallback({
        entity: {
          idp: idp,
          sp: sp
        },
        binding: 'redirect'
      });
    }
  );

  expect(isString(id)).toBe(true);
  expect(isString(context)).toBe(true);
});

test('create logout response with post binding', function() {
  const result = idp.createLogoutResponse(
    sp,
    {},
    'post',
    '',
    function() {
      return createTemplateCallback({
        entity: {
          idp: idp,
          sp: sp
        },
        binding: 'post'
      });
    }
  ) as PostBindingContext;

  const { relayState, type, entityEndpoint, id, context } = result;

  expect(isString(id)).toBe(true);
  expect(isString(context)).toBe(true);
  expect(isString(entityEndpoint)).toBe(true);
  expect(type).toBe('SAMLResponse');
});

// Check if the response data parsing is correct
// All test cases are using customize template

// simulate idp-initiated sso
test('send response with signed assertion and parse it', async function() {
  const user = { NameID: 'user@esaml2.com'};

  const result = await idpNoEncrypt.createLoginResponse({
    sp: sp,
    requestInfo: sampleRequestInfo,
    binding: 'post',
    user: user,
    customTagReplacement: function(template) {
      console.log(template)
      console.log("这就是元婴-------------------------------")
      return createTemplateCallback({
        entity: {
          idp: idpNoEncrypt,
          sp: sp
        },
        user: user,
        binding: 'post',
        requestInfo: sampleRequestInfo
      }) as BindingContext;
    }
  });

  const { id, context: SAMLResponse } = result;



  const { samlContent, extract } = await sp.parseLoginResponse(
    idpNoEncrypt,
    'post',
    { body: { SAMLResponse } }
  );
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

// + REDIRECT
test('send response with signed assertion and parse it', async function() {
  const user = { NameID: 'user@esaml2.com' };

  const result = await idpNoEncrypt.createLoginResponse({
    sp: sp,
    requestInfo: sampleRequestInfo,
    binding: 'post',
    user: user,
    customTagReplacement: function() {
      return createTemplateCallback({
        entity: {
          idp: idpNoEncrypt,
          sp: sp
        },
        user: user,
        binding: 'post',
        requestInfo: sampleRequestInfo
      }) as BindingContext;
    }
  });

  const { id, context: SAMLResponse } = result;

  const { samlContent, extract } = await sp.parseLoginResponse(
    idpNoEncrypt,
    'post',
    { body: { SAMLResponse } }
  );

  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

// SimpleSign
test('send response with signed assertion by post simplesign and parse it', async function() {
  const user = { NameID: 'user@esaml2.com' };

  const result = await idpNoEncrypt.createLoginResponse({
    sp: sp,
    requestInfo: sampleRequestInfo,
    binding: 'simpleSign',
    user: user,
    customTagReplacement: function() {
      return createTemplateCallback({
        entity: {
          idp: idpNoEncrypt,
          sp: sp
        },
        user: user,
        binding: 'simpleSign',
        requestInfo: sampleRequestInfo
      }) as BindingContext;
    },
    relayState: 'relaystate'
  }) as SimpleSignBindingContext;

  const { id, context: SAMLResponse, type, sigAlg, signature, relayState } = result;

  const octetString = buildSimpleSignOctetString(type, SAMLResponse, sigAlg, relayState, signature);
  const { samlContent, extract } = await sp.parseLoginResponse(
    idpNoEncrypt,
    'simpleSign',
    {
      body: { SAMLResponse, Signature: signature, SigAlg: sigAlg },
      octetString
    }
  );

  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send response with signed assertion + custom transformation algorithms and parse it', async function() {
  const user = { NameID: 'user@esaml2.com' };

  // 创建使用自定义转换算法的SP
  const signedAssertionSp = serviceProvider({
    ...defaultSpConfig,
    transformationAlgorithms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#'
    ]
  });

  // 创建登录响应
  const result = await idpNoEncrypt.createLoginResponse({
    sp: signedAssertionSp,
    requestInfo: sampleRequestInfo,
    binding: 'post',
    user: user,
    customTagReplacement: function() {
      return createTemplateCallback({
        entity: {
          idp: idpNoEncrypt,
          sp: signedAssertionSp
        },
        user: user,
        binding: 'post',
        requestInfo: sampleRequestInfo
      }) as BindingContext;
    }
  });

  const { id, context: SAMLResponse } = result;

  // 解析登录响应
  const { samlContent, extract } = await sp.parseLoginResponse(
    idpNoEncrypt,
    'post',
    { body: { SAMLResponse } }
  );

  // 验证结果
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.response.inResponseTo).toBe('request_id');

  // 验证自定义转换算法是否包含在响应中
  expect(samlContent).toContain('http://www.w3.org/2000/09/xmldsig#enveloped-signature');
});

test('send response with signed assertion + custom transformation algorithms by redirect and parse it', async function() {
  const user = { NameID: 'user@esaml2.com' };

  // 创建使用自定义转换算法的SP
  const signedAssertionSp = serviceProvider({
    ...defaultSpConfig,
    transformationAlgorithms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#'
    ]
  });

  // 创建登录响应
  const result = await idpNoEncrypt.createLoginResponse({
    sp: signedAssertionSp,
    requestInfo: sampleRequestInfo,
    binding: 'redirect',
    user: user,
    customTagReplacement: function() {
      return createTemplateCallback({
        entity: {
          idp: idpNoEncrypt,
          sp: signedAssertionSp
        },
        user: user,
        binding: 'redirect',
        requestInfo: sampleRequestInfo
      });
    },
    relayState: 'relaystate'
  });

  const { id, context } = result;

  // 解析URL查询参数
  const query = url.parse(context, true).query;

  // 验证URL参数
  expect(query.SAMLResponse).toBeDefined();
  expect(query.SigAlg).toBeDefined();
  expect(query.Signature).toBeDefined();
  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');

  // 解析登录响应
  const { samlContent, extract } = await signedAssertionSp.parseLoginResponse(
    idpNoEncrypt,
    'redirect',
    parseRedirectUrlContextCallBack(context)
  );

  // 验证响应内容
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('/samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.response.inResponseTo).toBe('request_id');

  // 验证自定义转换算法是否包含在响应中
  expect(samlContent).toContain('http://www.w3.org/2000/09/xmldsig#enveloped-signature');
});

test('send response with signed assertion + custom transformation algorithms by post simplesign and parse it', async () => {
  // 创建使用自定义转换算法的SP
  const signedAssertionSp = serviceProvider({
    ...defaultSpConfig,
    transformationAlgorithms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#'
    ]
  });

  const user = { NameID: 'user@esaml2.com' };

  // 创建登录响应
  const result = await idpNoEncrypt.createLoginResponse({
    sp: signedAssertionSp,
    requestInfo: sampleRequestInfo,
    binding: 'simpleSign',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpNoEncrypt,
        sp: signedAssertionSp
      },
      user: user,
      binding: 'simpleSign',
      requestInfo: sampleRequestInfo
    }) as BindingContext,
    relayState: 'relaystate'
  }) as SimpleSignBindingContext;

  const {
    id,
    context: SAMLResponse,
    type,
    sigAlg,
    signature,
    relayState
  } = result;

  // 构建 SimpleSign 八位字节字符串
  const octetString = buildSimpleSignOctetString(type, SAMLResponse, sigAlg, relayState, signature);

  // 解析登录响应
  const { samlContent, extract: extractedData } = await signedAssertionSp.parseLoginResponse(
    idpNoEncrypt,
    'simpleSign',
    {
      body: { SAMLResponse, Signature: signature, SigAlg: sigAlg },
      octetString
    }
  );

  // 验证结果
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.response.inResponseTo).toBe('request_id');

  // 验证自定义转换算法是否包含在响应中
  expect(samlContent).toContain('http://www.w3.org/2000/09/xmldsig#enveloped-signature');
});

test('send response with [custom template] signed assertion and parse it', async () => {
  const requestInfo = { extract: { request: { id: 'request_id' } } };
  const user = { NameID: 'user@esaml2.com' };

  // 创建登录响应
  const result = await idpcustomNoEncrypt.createLoginResponse({
    sp: sp,
    requestInfo: requestInfo,
    binding: 'post',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpcustomNoEncrypt,
        sp: sp
      },
      user: user,
      binding: 'post',
      requestInfo: requestInfo,
      AttributeStatement:libsaml.attributeStatementBuilder([
        {
          Name: 'mail',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'myemailassociatedwithsp@sp.com'
          } ],
          FriendlyName: 'mail'
        },
        {
          Name: 'name',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'mynameinsp'
          }],
          FriendlyName: 'name'
        }
      ])
    }) as BindingContext
  });

  const { id, context: SAMLResponse } = result;

  // 解析登录响应
  const { samlContent, extract: extractedData } = await sp.parseLoginResponse(
    idpcustomNoEncrypt,
    'post',
    { body: { SAMLResponse } }
  );

  // 验证结果
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.attributes.name).toBe('mynameinsp');
  expect(extractedData.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extractedData.response.inResponseTo).toBe('_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});



test('send response with [custom template] signed assertion by redirect and parse it', async () => {
  const requestInfo = { extract: { request: { id: 'request_id' } } };
  const user = { NameID: 'user@esaml2.com' };

  // 创建登录响应
  const result = await idpcustomNoEncrypt.createLoginResponse({
    sp: sp,
    requestInfo: requestInfo,
    binding: 'redirect',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpcustomNoEncrypt,
        sp: sp
      },
      user: user,
      binding: 'redirect',
      requestInfo: requestInfo,
      AttributeStatement:libsaml.attributeStatementBuilder([
        {
          Name: 'mail',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'myemailassociatedwithsp@sp.com'
          } ],
          FriendlyName: 'mail'
        },
        {
          Name: 'name',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'mynameinsp'
          }],
          FriendlyName: 'name'
        }
      ])
    }) as BindingContext,
    relayState: 'relaystate'
  });

  const { id, context } = result;

  // 解析URL查询参数
  const query = url.parse(context, true).query;

  // 验证URL参数
  expect(query.SAMLResponse).toBeDefined();
  expect(query.SigAlg).toBeDefined();
  expect(query.Signature).toBeDefined();
  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');

  // 解析登录响应
  const { samlContent, extract: extractedData } = await sp.parseLoginResponse(
    idpcustomNoEncrypt,
    'redirect',
    parseRedirectUrlContextCallBack(context)
  );

  // 验证响应内容
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.attributes.name).toBe('mynameinsp');
  expect(extractedData.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extractedData.response.inResponseTo).toBe('_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});

test('send response with [custom template] signed assertion by post simpleSign and parse it', async () => {
  const requestInfo = { extract: { request: { id: 'request_id' } } };
  const user = { NameID: 'user@esaml2.com' };

  // 创建登录响应
  const result = await idpcustomNoEncrypt.createLoginResponse({
    sp: sp,
    requestInfo: requestInfo,
    binding: 'simpleSign',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpcustomNoEncrypt,
        sp: sp
      },
      user: user,
      binding: 'simpleSign',
      requestInfo: requestInfo,
      AttributeStatement:libsaml.attributeStatementBuilder([
        {
          Name: 'mail',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'myemailassociatedwithsp@sp.com'
          } ],
          FriendlyName: 'mail'
        },
        {
          Name: 'name',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'mynameinsp'
          }],
          FriendlyName: 'name'
        }
      ])

    }) as BindingContext,
    relayState: 'relaystate',
  }) as SimpleSignBindingContext;

  const {
    id,
    context: SAMLResponse,
    type,
    sigAlg,
    signature,
    entityEndpoint,
    relayState
  } = result;

  // 构建 SimpleSign 八位字节字符串
  const octetString = buildSimpleSignOctetString(type, SAMLResponse, sigAlg, relayState, signature);

  // 解析登录响应
  const { samlContent, extract: extractedData } = await sp.parseLoginResponse(
    idpcustomNoEncrypt,
    'simpleSign',
    {
      body: { SAMLResponse, Signature: signature, SigAlg: sigAlg },
      octetString
    }
  );

  // 验证结果
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(entityEndpoint).toBe('https://sp.example.org/sp/sso');
  expect(extractedData.nameID).toBe('user@esaml2.com');

  console.log(extractedData.attributes)
  console.log("--------------给我看一下----------------")
  expect(extractedData.attributes.name).toBe('mynameinsp');
  expect(extractedData.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extractedData.response.inResponseTo).toBe('_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});

test('send response with signed message and parse it', async () => {
  const user = { NameID: 'user@esaml2.com' };

  // 创建登录响应
  const result = await idpNoEncrypt.createLoginResponse({
    sp: spNoAssertSign,
    requestInfo: sampleRequestInfo,
    binding: 'post',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpNoEncrypt,
        sp: spNoAssertSign
      },
      user: user,
      binding: 'post',
      requestInfo: sampleRequestInfo
    }) as BindingContext
  });

  const { id, context: SAMLResponse } = result;

  // 解析登录响应
  const { samlContent, extract: extractedData } = await spNoAssertSign.parseLoginResponse(
    idpNoEncrypt,
    'post',
    { body: { SAMLResponse } }
  );

  // 验证结果
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.response.inResponseTo).toBe('request_id');
});

test('send response with signed message by redirect and parse it', async () => {
  const requestInfo = { extract: { request: { id: 'request_id' } } };
  const user = { NameID: 'user@esaml2.com' };

  // 创建登录响应
  const result = await idpNoEncrypt.createLoginResponse({
    sp: spNoAssertSign,
    requestInfo: requestInfo,
    binding: 'redirect',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpNoEncrypt,
        sp: spNoAssertSign
      },
      user: user,
      binding: 'redirect',
      requestInfo: requestInfo
    }) as BindingContext,
    relayState: 'relaystate'
  });

  const { id, context } = result;

  // 解析URL查询参数
  const query = url.parse(context, true).query;

  // 验证URL参数
  expect(query.SAMLResponse).toBeDefined();
  expect(query.SigAlg).toBeDefined();
  expect(query.Signature).toBeDefined();
  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');
console.log('===================开始解码上下文===================')
  console.log('===================开始解码上下文===================')
  // 解析登录响应
  const { samlContent, extract: extractedData } = await spNoAssertSign.parseLoginResponse(
    idpNoEncrypt,
    'redirect',
    parseRedirectUrlContextCallBack(context)
  );
console.log(extractedData)
  console.log('===================222222222222222222开始解码上下文===================')
  // 验证响应内容
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.response.inResponseTo).toBe('request_id');
});

test('send response with signed message by post simplesign and parse it', async () => {
  const user = { NameID: 'user@esaml2.com' };

  // 创建登录响应
  const result = await idpNoEncrypt.createLoginResponse({
    sp: spNoAssertSign,
    requestInfo: sampleRequestInfo,
    binding: 'simpleSign',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpNoEncrypt,
        sp: spNoAssertSign
      },
      user: user,
      binding: 'simpleSign',
      requestInfo: sampleRequestInfo
    }),
    relayState: 'relaystate'
  }) as SimpleSignBindingContext;

  const { id, context: SAMLResponse, type, sigAlg, signature, relayState } = result;

  // 构建 SimpleSign 八位字节字符串
  const octetString = buildSimpleSignOctetString(type, SAMLResponse, sigAlg, relayState, signature);

  // 解析登录响应
  const { samlContent, extract } = await spNoAssertSign.parseLoginResponse(
    idpNoEncrypt,
    'simpleSign',
    {
      body: { SAMLResponse, Signature: signature, SigAlg: sigAlg },
      octetString
    }
  );

  // 验证结果
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(extract.nameID).toBe('user@esaml2.com');
  expect(extract.response.inResponseTo).toBe('request_id');
});

test('send response with [custom template] and signed message and parse it', async () => {
  const requestInfo = { extract: { authnrequest: { id: 'request_id' } } };
  const user = { NameID: 'user@esaml2.com' };

  // 创建登录响应
  const result = await idpcustomNoEncrypt.createLoginResponse({
    sp: spNoAssertSign,
    requestInfo: { extract: { authnrequest: { id: 'request_id' } } },
    binding: 'post',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpcustomNoEncrypt,
        sp: spNoAssertSign
      },
      user: user,
      binding: 'post',
      requestInfo: requestInfo,
      AttributeStatement:libsaml.attributeStatementBuilder([
        {
          Name: 'mail',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'myemailassociatedwithsp@sp.com'
          } ],
          FriendlyName: 'mail'
        },
        {
          Name: 'name',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'mynameinsp'
          }],
          FriendlyName: 'name'
        }
      ])
    })
  });

  const { id, context: SAMLResponse } = result;

  // 解析登录响应
  const { samlContent, extract: extractedData } = await spNoAssertSign.parseLoginResponse(
    idpcustomNoEncrypt,
    'post',
    { body: { SAMLResponse } }
  );

  // 验证结果
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.attributes.name).toBe('mynameinsp');
  expect(extractedData.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extractedData.response.inResponseTo).toBe('_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});
test('send response with [custom template] and signed message by redirect and parse it', async () => {
  const requestInfo = { extract: { request: { id: 'request_id' } } };
  const user = { NameID: 'user@esaml2.com' };

  // 创建登录响应
  const result = await idpcustomNoEncrypt.createLoginResponse({
    sp: spNoAssertSign,
    requestInfo: requestInfo,
    binding: 'redirect',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpcustomNoEncrypt,
        sp: spNoAssertSign
      },
      user: user,
      binding: 'redirect',
      requestInfo: requestInfo,
      AttributeStatement:libsaml.attributeStatementBuilder([
        {
          Name: 'mail',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'myemailassociatedwithsp@sp.com'
          } ],
          FriendlyName: 'mail'
        },
        {
          Name: 'name',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'mynameinsp'
          }],
          FriendlyName: 'name'
        }
      ])
    }),
    relayState: 'relaystate'
  });

  const { id, context } = result;

  // 解析URL查询参数
  const query = url.parse(context, true).query;

  // 验证URL参数
  expect(query.SAMLResponse).toBeDefined();
  expect(query.SigAlg).toBeDefined();
  expect(query.Signature).toBeDefined();
  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');

  // 解析登录响应
  const { samlContent, extract: extractedData } = await spNoAssertSign.parseLoginResponse(
    idpcustomNoEncrypt,
    'redirect',
    parseRedirectUrlContextCallBack(context)
  );

  // 验证响应内容
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.attributes.name).toBe('mynameinsp');
  expect(extractedData.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extractedData.response.inResponseTo).toBe('_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});
/** 错误了五个------------------*/
test('send response with [custom template] and signed message by post simplesign and parse it', async () => {
  const requestInfo = { extract: { authnrequest: { id: 'request_id' } } };
  const user = { NameID: 'user@esaml2.com' };

  // 创建登录响应
  const result = await idpcustomNoEncrypt.createLoginResponse({
    sp: spNoAssertSign,
    requestInfo: requestInfo,
    binding: 'simpleSign',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpcustomNoEncrypt,
        sp: spNoAssertSign
      },
      user: user,
      binding: 'simpleSign',
      requestInfo: requestInfo,
      AttributeStatement:libsaml.attributeStatementBuilder([
        {
          Name: 'mail',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'myemailassociatedwithsp@sp.com'
          } ],
          FriendlyName: 'mail'
        },
        {
          Name: 'name',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'mynameinsp'
          }],
          FriendlyName: 'name'
        }
      ])
    }),
    relayState: 'relaystate'
  }) as SimpleSignBindingContext;

  const {
    id,
    context: SAMLResponse,
    type,
    sigAlg,
    signature,
    relayState
  } = result;

  // 构建 SimpleSign 八位字节字符串
  const octetString = buildSimpleSignOctetString(type, SAMLResponse, sigAlg, relayState, signature);

  // 解析登录响应
  const { samlContent, extract: extractedData } = await spNoAssertSign.parseLoginResponse(
    idpcustomNoEncrypt,
    'simpleSign',
    {
      body: { SAMLResponse, Signature: signature, SigAlg: sigAlg },
      octetString
    }
  );

  // 验证结果
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(extractedData.nameID).toBe('user@esaml2.com');
  console.log(extractedData.attributes)
  console.log("=====================看下================")
  expect(extractedData.attributes.name).toBe('mynameinsp');
  expect(extractedData.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extractedData.response.inResponseTo).toBe('_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});


test('send login response with signed assertion + signed message and parse it', async () => {
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });

  const user = { NameID: 'user@esaml2.com' };

  const result = await idp.createLoginResponse({
    sp: spWantMessageSign,
    requestInfo: sampleRequestInfo,
    binding: 'post',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idp,
        sp: spWantMessageSign
      },
      user: user,
      binding: 'post',
      requestInfo: sampleRequestInfo,
    }),
    encryptThenSign: true
  });

  const { id, context: SAMLResponse } = result;

  const { samlContent, extract: extractedData } = await spWantMessageSign.parseLoginResponse(
    idpNoEncrypt,
    'post',
    { body: { SAMLResponse } }
  );

  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.response.inResponseTo).toBe('request_id');
});

test('send response with signed assertion + signed message by redirect and parse it', async () => {
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });

  const requestInfo = { extract: { request: { id: 'request_id' } } };
  const user = { NameID: 'user@esaml2.com' };

  const result = await idpNoEncrypt.createLoginResponse({
    sp: spWantMessageSign,
    requestInfo: requestInfo,
    binding: 'redirect',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpNoEncrypt,
        sp: spWantMessageSign
      },
      user: user,
      binding: 'redirect',
      requestInfo: requestInfo,
      AttributeStatement:libsaml.attributeStatementBuilder([
        {
          Name: 'mail',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'myemailassociatedwithsp@sp.com'
          } ],
          FriendlyName: 'mail'
        },
        {
          Name: 'name',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'mynameinsp'
          }],
          FriendlyName: 'name'
        }
      ])
    }),
    relayState: 'relaystate'
  });

  const { id, context } = result;

  const query = url.parse(context, true).query;

  expect(query.SAMLResponse).toBeDefined();
  expect(query.SigAlg).toBeDefined();
  expect(query.Signature).toBeDefined();
  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');

  const { samlContent, extract: extractedData } = await spWantMessageSign.parseLoginResponse(
    idpNoEncrypt,
    'redirect',
    parseRedirectUrlContextCallBack(context)
  );

  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.response.inResponseTo).toBe('request_id');
});

test('send login response with signed assertion + signed message by post simplesign and parse it', async () => {
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });

  const user = { NameID: 'user@esaml2.com' };

  const result = await idpNoEncrypt.createLoginResponse({
    sp: spWantMessageSign,
    requestInfo: sampleRequestInfo,
    binding: 'simpleSign',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpNoEncrypt,
        sp: spWantMessageSign
      },
      user: user,
      binding: 'simpleSign',
      requestInfo: sampleRequestInfo,
      AttributeStatement:libsaml.attributeStatementBuilder([
        {
          Name: 'mail',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'myemailassociatedwithsp@sp.com'
          } ],
          FriendlyName: 'mail'
        },
        {
          Name: 'name',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'mynameinsp'
          }],
          FriendlyName: 'name'
        }
      ])
    }),
    relayState: 'relaystate'
  }) as SimpleSignBindingContext;

  const {
    id,
    context: SAMLResponse,
    type,
    sigAlg,
    signature,
    relayState
  } = result;

  const octetString = buildSimpleSignOctetString(type, SAMLResponse, sigAlg, relayState, signature);

  const { samlContent, extract: extractedData } = await spWantMessageSign.parseLoginResponse(
    idpNoEncrypt,
    'simpleSign',
    {
      body: { SAMLResponse, Signature: signature, SigAlg: sigAlg },
      octetString
    }
  );

  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.response.inResponseTo).toBe('request_id');
});

test('send login response with [custom template] and signed assertion + signed message and parse it', async () => {
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });

  const user = { NameID: 'user@esaml2.com' };

  // 创建登录响应
  const result = await idpcustomNoEncrypt.createLoginResponse({
    sp: spWantMessageSign,
    requestInfo: { extract: { authnrequest: { id: 'request_id' } } },
    binding: 'post',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpcustomNoEncrypt,
        sp: spWantMessageSign
      },
      user: user,
      binding: 'post',
      requestInfo: { extract: { authnrequest: { id: 'request_id' } } },
      AttributeStatement:libsaml.attributeStatementBuilder([
        {
          Name: 'mail',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'myemailassociatedwithsp@sp.com'
          } ],
          FriendlyName: 'mail'
        },
        {
          Name: 'name',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'mynameinsp'
          }],
          FriendlyName: 'name'
        }
      ]),
    })
  });

  const { id, context: SAMLResponse } = result;

  // 解析登录响应
  const { samlContent, extract: extractedData } = await spWantMessageSign.parseLoginResponse(
    idpcustomNoEncrypt,
    'post',
    { body: { SAMLResponse } }
  );

  // 验证结果
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.attributes.name).toBe('mynameinsp');
  expect(extractedData.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extractedData.response.inResponseTo).toBe('_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});

test('send response with [custom template] and signed assertion + signed message by redirect and parse it', async () => {
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });

  const requestInfo = { extract: { request: { id: 'request_id' } } };
  const user = { NameID: 'user@esaml2.com' };

  // 创建登录响应
  const result = await idpcustomNoEncrypt.createLoginResponse({
    sp: spWantMessageSign,
    requestInfo: requestInfo,
    binding: 'redirect',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpcustomNoEncrypt,
        sp: spWantMessageSign
      },
      AttributeStatement:libsaml.attributeStatementBuilder([
        {
          Name: 'mail',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'myemailassociatedwithsp@sp.com'
          } ],
          FriendlyName: 'mail'
        },
        {
          Name: 'name',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'mynameinsp'
          }],
          FriendlyName: 'name'
        }
      ]),
      user: user,
      binding: 'redirect',
      requestInfo: requestInfo
    }),
    relayState: 'relaystate'
  });

  const { id, context } = result;

  // 解析URL查询参数
  const query = url.parse(context, true).query;

  // 验证URL参数
  expect(query.SAMLResponse).toBeDefined();
  expect(query.SigAlg).toBeDefined();
  expect(query.Signature).toBeDefined();
  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');

  // 解析登录响应
  const { samlContent, extract: extractedData } = await spWantMessageSign.parseLoginResponse(
    idpcustomNoEncrypt,
    'redirect',
    parseRedirectUrlContextCallBack(context)
  );

  // 验证响应内容
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.attributes.name).toBe('mynameinsp');
  expect(extractedData.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extractedData.response.inResponseTo).toBe('_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});

test('send login response with [custom template] and signed assertion + signed message by post simplesign and parse it', async () => {
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });

  const user = { NameID: 'user@esaml2.com' };

  // 创建登录响应
  const result = await idpcustomNoEncrypt.createLoginResponse({
    sp: spWantMessageSign,
    requestInfo: { extract: { authnrequest: { id: 'request_id' } } },
    binding: 'simpleSign',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpcustomNoEncrypt,
        sp: spWantMessageSign
      },
      user: user,
      binding: 'simpleSign',
      AttributeStatement:libsaml.attributeStatementBuilder([
        {
          Name: 'mail',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'myemailassociatedwithsp@sp.com'
          } ],
          FriendlyName: 'mail'
        },
        {
          Name: 'name',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'mynameinsp'
          }],
          FriendlyName: 'name'
        }
      ]),
      requestInfo: { extract: { authnrequest: { id: 'request_id' } } }
    }),
    relayState: 'relaystate'
  }) as SimpleSignBindingContext;

  const {
    id,
    context: SAMLResponse,
    type,
    sigAlg,
    signature,
    relayState
  } = result;

  // 构建 SimpleSign 八位字节字符串
  const octetString = buildSimpleSignOctetString(type, SAMLResponse, sigAlg, relayState, signature);

  // 解析登录响应
  const { samlContent, extract: extractedData } = await spWantMessageSign.parseLoginResponse(
    idpcustomNoEncrypt,
    'simpleSign',
    {
      body: { SAMLResponse, Signature: signature, SigAlg: sigAlg },
      octetString
    }
  );

  // 验证结果
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.attributes.name).toBe('mynameinsp');
  expect(extractedData.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extractedData.response.inResponseTo).toBe('_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});

test('send login response with encrypted non-signed assertion and parse it', async () => {
  const user = { NameID: 'user@esaml2.com' };

  // 创建登录响应
  const result = await idp.createLoginResponse({
    sp: spNoAssertSign,
    requestInfo: sampleRequestInfo,
    binding: 'post',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idp,
        sp: spNoAssertSign
      },
      user: user,
      binding: 'post',
      requestInfo: sampleRequestInfo
    })
  });

  const { id, context: SAMLResponse } = result;

  // 解析登录响应
  const { samlContent, extract: extractedData } = await spNoAssertSign.parseLoginResponse(
    idp,
    'post',
    { body: { SAMLResponse } }
  );
console.log(extractedData)
  console.log("解析数据--------------------")
  // 验证结果
  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.response.inResponseTo).toBe('request_id');
})


// 测试：发送带有加密非签名断言的登录响应并解析
test('send login response with encrypted non-signed assertion and parse it', async () => {
  const user = { NameID: 'user@esaml2.com' };

  const result = await idp.createLoginResponse({
    sp: spNoAssertSign,
    requestInfo: sampleRequestInfo,
    binding: 'post',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idp,
        sp: spNoAssertSign
      },
      user: user,
      binding: 'post',
    })
  });

  const { id, context: SAMLResponse } = result;
console.log(SAMLResponse)
  console.log("加密后的相应===================================")
  const { samlContent, extract: extractedData } = await sp.parseLoginResponse(
    idp,
    'post',
    { body: { SAMLResponse } }
  );

  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.response.inResponseTo).toBe('request_id');
});

// 测试：发送带有自定义模板和加密签名断言的登录响应并解析
test('send login response with [custom template] and encrypted signed assertion and parse it', async () => {
  const user = { NameID: 'user@esaml2.com' };

  const result = await idpcustom.createLoginResponse({
    sp: sp,
    requestInfo: { extract: { request: { id: 'request_id' } } },
    binding: 'post',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpcustom,
        sp: sp
      },
      user: user,
      binding: 'post',
      AttributeStatement:libsaml.attributeStatementBuilder([
        {
          Name: 'mail',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'myemailassociatedwithsp@sp.com'
          } ],
          FriendlyName: 'mail'
        },
        {
          Name: 'name',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [ {
            value:'mynameinsp'
          }],
          FriendlyName: 'name'
        }
      ]),
      requestInfo: { extract: { request: { id: 'request_id' } } }
    })
  });

  const { id, context: SAMLResponse } = result;

  const { samlContent, extract: extractedData } = await sp.parseLoginResponse(
    idpcustom,
    'post',
    { body: { SAMLResponse } }
  );

  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.attributes.name).toBe('mynameinsp');
  expect(extractedData.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extractedData.response.inResponseTo).toBe('_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});

// 测试：发送带有加密签名断言和签名消息的登录响应并解析
test('send login response with encrypted signed assertion + signed message and parse it', async () => {
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });

  const user = {NameID: 'user@esaml2.com'};

  const result = await idp.createLoginResponse({
    sp: spWantMessageSign,
    requestInfo: sampleRequestInfo,
    binding: 'post',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idp,
        sp: spWantMessageSign
      },
      user: user,
      binding: 'post'
    })
  });

  const {id, context: SAMLResponse} = result;
  console.log(SAMLResponse)
  console.log('-------------SAMLResponse-----------------')
  const {samlContent, extract: extractedData} = await spWantMessageSign.parseLoginResponse(
    idp,
    'post',
    {body: {SAMLResponse}}
  );

  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.response.inResponseTo).toBe('request_id');
});

// 测试：发送带有自定义模板的加密签名断言和签名消息的登录响应并解析
test('send login response with [custom template] encrypted signed assertion + signed message and parse it', async () => {
  const spWantMessageSign = serviceProvider({
    ...defaultSpConfig,
    wantMessageSigned: true,
  });

  const requestInfo = {extract: {authnrequest: {id: 'request_id'}}};
  const user = {NameID: 'user@esaml2.com'};

  const result = await idpcustom.createLoginResponse({
    sp: spWantMessageSign,
    requestInfo: requestInfo,
    binding: 'post',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpcustom,
        sp: spWantMessageSign
      },
      user: user,
      binding: 'post',
      AttributeStatement: libsaml.attributeStatementBuilder([
        {
          Name: 'mail',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [{
            value: 'myemailassociatedwithsp@sp.com'
          }],
          FriendlyName: 'mail'
        },
        {
          Name: 'name',
          type: 'attribute',
          ValueType: 1,
          NameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
          valueArray: [{
            value: 'mynameinsp'
          }],
          FriendlyName: 'name'
        }
      ]),
      requestInfo: requestInfo
    })
  });

  const {id, context: SAMLResponse} = result;

  const {samlContent, extract: extractedData} = await spWantMessageSign.parseLoginResponse(
    idpcustom,
    'post',
    {body: {SAMLResponse}}
  );

  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.attributes.name).toBe('mynameinsp');
  expect(extractedData.attributes.mail).toBe('myemailassociatedwithsp@sp.com');
  expect(extractedData.response.inResponseTo).toBe('_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});

// 测试：IDP 发送无签名的重定向注销请求，SP 解析
test('idp sends a redirect logout request without signature and sp parses it', async () => {
  const {id, context} = idp.createLogoutRequest(sp, 'redirect', {NameID: 'user@esaml2.com'});

  const query = url.parse(context, true).query;

  expect(query.SAMLRequest).toBeDefined();
  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');

  const {samlContent, extract: extractedData} = await sp.parseLogoutRequest(
    idp,
    'redirect',
    {query: {SAMLRequest: query.SAMLRequest}}
  );

  expect(typeof samlContent).toBe('string');
  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.signature).toBeNull();
  expect(typeof extractedData.request.id).toBe('string');
  expect(extractedData.request.destination).toBe('https://sp.example.org/sp/slo');
  expect(extractedData.issuer).toBe('https://idp.example.com/metadata');
});

// 测试：IDP 发送带签名的重定向注销请求，SP 解析
test('idp sends a redirect logout request with signature and sp parses it', async () => {
  const {id, context} = idp.createLogoutRequest(spWantLogoutReqSign, 'redirect', {NameID: 'user@esaml2.com'});

  const query = url.parse(context, true).query;

  expect(query.SAMLRequest).toBeDefined();
  expect(query.SigAlg).toBeDefined();
  expect(query.Signature).toBeDefined();
  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');

  const originalURL = url.parse(context, true);
  const SAMLRequest = originalURL.query.SAMLRequest;
  const Signature = originalURL.query.Signature;
  const SigAlg = originalURL.query.SigAlg;

  delete originalURL.query.Signature;
  const octetString = Object.keys(originalURL.query)
    .map(q => q + '=' + encodeURIComponent(originalURL.query[q] as string))
    .join('&');

  const {extract: extractedData} = await spWantLogoutReqSign.parseLogoutRequest(
    idp,
    'redirect',
    {
      query: {SAMLRequest, Signature, SigAlg},
      octetString
    }
  );

  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.issuer).toBe('https://idp.example.com/metadata');
  expect(typeof extractedData.request.id).toBe('string');
  expect(extractedData.request.destination).toBe('https://sp.example.org/sp/slo');
  expect(extractedData.signature).toBeNull(); // 重定向绑定不嵌入签名
});
// 测试：IDP 发送无签名的 POST 注销请求，SP 解析
test('idp sends a post logout request without signature and sp parses it', async () => {
  const result = idp.createLogoutRequest(sp, 'post', {NameID: 'user@esaml2.com'}) as PostBindingContext;

  const {id, context} = result;

  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');
  console.log(context)
  console.log('这是上下文-------------------')
  const {extract: extractedData} = await sp.parseLogoutRequest(
    idp,
    'post',
    {body: {SAMLRequest: context}}
  );

  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.issuer).toBe('https://idp.example.com/metadata');
  expect(typeof extractedData.request.id).toBe('string');
  expect(extractedData.request.destination).toBe('https://sp.example.org/sp/slo');
  expect(extractedData.signature).toBeNull();
});

// 测试：IDP 发送带签名的 POST 注销请求，SP 解析
test('idp sends a post logout request with signature and sp parses it', async () => {
  const result = idp.createLogoutRequest(spWantLogoutReqSign, 'post', { NameID: 'user@esaml2.com' }) as PostBindingContext;

  const { id, context } = result;

  expect(typeof id).toBe('string');
  expect(typeof context).toBe('string');

  const { extract: extractedData } = await spWantLogoutReqSign.parseLogoutRequest(
    idp,
    'post',
    { body: { SAMLRequest: context } }
  );

  expect(extractedData.nameID).toBe('user@esaml2.com');
  expect(extractedData.issuer).toBe('https://idp.example.com/metadata');
  expect(extractedData.request.destination).toBe('https://sp.example.org/sp/slo');
  expect(typeof extractedData.request.id).toBe('string');
  expect(typeof extractedData.signature).toBe('string');
});

// 测试：SP 发送无签名的 POST 注销响应，IDP 解析
test('sp sends a post logout response without signature and parse', async () => {
  const result = sp.createLogoutResponse(idp, sampleRequestInfo, 'post', '', () =>
    createTemplateCallback({
      entity: {
        idp: idp,
        sp: sp
      },
      binding: 'post',
      requestInfo: sampleRequestInfo
    })
  ) as PostBindingContext;

  const { context: SAMLResponse } = result;

  const { extract: extractedData } = await idp.parseLogoutResponse(
    sp,
    'post',
    { body: { SAMLResponse } }
  );

  expect(extractedData.signature).toBeNull();
  expect(extractedData.issuer).toBe('https://sp.example.org/metadata');
  expect(typeof extractedData.response.id).toBe('string');
  expect(extractedData.response.destination).toBe('https://idp.example.org/sso/SingleLogoutService');
});

/*// 测试：SP 发送带签名的 POST 注销响应，IDP 解析
test('sp sends a post logout response with signature and parse', async () => {
  const result = sp.createLogoutResponse(idpWantLogoutResSign, sampleRequestInfo, 'post', '', () =>
    createTemplateCallback({
      entity: {
        idp: idpWantLogoutResSign,
        sp: sp
      },
      binding: 'post',
      requestInfo: sampleRequestInfo
    })
  ) as PostBindingContext;

  const { context: SAMLResponse } = result;

  const { extract: extractedData } = await idpWantLogoutResSign.parseLogoutResponse(
    sp,
    'post',
    { body: { SAMLResponse } }
  );

  expect(typeof extractedData.signature).toBe('string');
  expect(extractedData.issuer).toBe('https://sp.example.org/metadata');
  expect(typeof extractedData.response.id).toBe('string');
  expect(extractedData.response.destination).toBe('https://idp.example.org/sso/SingleLogoutService');
});

// 测试：发送带有加密非签名断言的登录响应（EncryptThenSign）并解析
test('send login response with encrypted non-signed assertion with EncryptThenSign and parse it', async () => {
  const user = { NameID: 'user@esaml2.com' };

  const result = await idpEncryptThenSign.createLoginResponse({
    sp: spNoAssertSignCustomConfig,
    requestInfo: sampleRequestInfo,
    binding: 'post',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpEncryptThenSign,
        sp: spNoAssertSignCustomConfig
      },
      user: user,
      binding: 'post',
      requestInfo: sampleRequestInfo
    }),
    encryptThenSign: true
  });

  const { id, context: SAMLResponse } = result;

  const { samlContent, extract: extractedData } = await spNoAssertSignCustomConfig.parseLoginResponse(
    idpEncryptThenSign,
    'post',
    { body: { SAMLResponse } }
  );

  expect(typeof id).toBe('string');
  expect(samlContent.startsWith('<samlp:Response')).toBe(true);
  expect(samlContent.endsWith('</samlp:Response>')).toBe(true);
  expect(extractedData.nameID).toBe('user@esaml2.com');
});

// 测试：自定义加密断言标签前缀
test('Customize prefix (saml2) for encrypted assertion tag', async () => {
  const user = { NameID: 'test@email.com' };
  const idpCustomizePfx = identityProvider(Object.assign(defaultIdpConfig, {
    tagPrefix: {
      encryptedAssertion: 'saml2',
    }
  }));

  const result = await idpCustomizePfx.createLoginResponse({
    sp: sp,
    requestInfo: sampleRequestInfo,
    binding: 'post',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpCustomizePfx,
        sp: sp
      },
      user: user,
      binding: 'post',
      requestInfo: sampleRequestInfo
    })
  });

  const { context: SAMLResponse } = result;
  const decoded = utility.base64Decode(SAMLResponse, );

  expect(decoded).toContain('saml2:EncryptedAssertion');

  const { samlContent, extract: extractedData } = await sp.parseLoginResponse(
    idpCustomizePfx,
    'post',
    { body: { SAMLResponse } }
  );
});

// 测试：默认加密断言标签前缀
test('Customize prefix (default is saml) for encrypted assertion tag', async () => {
  const user = { NameID: 'test@email.com' };

  const result = await idp.createLoginResponse({
    sp: sp,
    requestInfo: sampleRequestInfo,
    binding: 'post',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idp,
        sp: sp
      },
      user: user,
      binding: 'post',
      requestInfo: sampleRequestInfo
    })
  });

  const { context: SAMLResponse } = result;
  const decoded = utility.base64Decode(SAMLResponse, );

  expect(decoded).toContain('saml:EncryptedAssertion');

  const { samlContent, extract: extractedData } = await sp.parseLoginResponse(
    idp,
    'post',
    { body: { SAMLResponse } }
  );
});

// 测试：避免格式错误的响应
test('avoid malformatted response', async () => {
  const user = { NameID: 'user@email.com' };

  const result = await idpNoEncrypt.createLoginResponse({
    sp: sp,
    requestInfo: sampleRequestInfo,
    binding: 'post',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpNoEncrypt,
        sp: sp
      },
      user: user,
      binding: 'post',
      requestInfo: sampleRequestInfo
    })
  });

  const { context: SAMLResponse } = result;
  const rawResponse = String(utility.base64Decode(SAMLResponse, ));
  const attackResponse = `<NameID>evil@evil.com${rawResponse}</NameID>`;

  await expect(
    sp.parseLoginResponse(
      idpNoEncrypt,
      'post',
      { body: { SAMLResponse: utility.base64Encode(attackResponse) } }
    )
  ).rejects.toThrow();
});
// 测试：避免重定向绑定的格式错误响应
test('avoid malformatted response with redirect binding', async () => {
  const user = { NameID: 'user@email.com' };

  const result = await idpNoEncrypt.createLoginResponse({
    sp: sp,
    requestInfo: sampleRequestInfo,
    binding: 'redirect',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpNoEncrypt,
        sp: sp
      },
      user: user,
      binding: 'redirect',
      requestInfo: sampleRequestInfo
    }),
    relayState: ''
  });

  const { context } = result;
  const query = url.parse(context, true).query;
  const SAMLResponse = query.SAMLResponse;
  const signature = query.Signature;
  const sigAlg = query.SigAlg;

  const rawResponse = utility.inflateString(SAMLResponse as string);
  const attackResponse = `<NameID>evil@evil.com${rawResponse}</NameID>`;
  const octetString = 'SAMLResponse=' + encodeURIComponent(utility.base64Encode(utility.deflateString(attackResponse))) + '&SigAlg=' + encodeURIComponent(sigAlg as string);

  await expect(
    sp.parseLoginResponse(
      idpNoEncrypt,
      'redirect',
      {
        query: { SAMLResponse, SigAlg: sigAlg, Signature: signature },
        octetString
      }
    )
  ).rejects.toThrow();
});

// 测试：避免 SimpleSign 绑定的格式错误响应
test('avoid malformatted response with simplesign binding', async () => {
  const user = { NameID: 'user@email.com' };

  const result = await idpNoEncrypt.createLoginResponse({
    sp: sp,
    requestInfo: sampleRequestInfo,
    binding: 'simpleSign',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpNoEncrypt,
        sp: sp
      },
      user: user,
      binding: 'simpleSign',
      requestInfo: sampleRequestInfo
    }),
    relayState: 'relaystate'
  }) as SimpleSignBindingContext;

  const {
    context: SAMLResponse,
    type,
    sigAlg,
    signature,
    relayState
  } = result;

  const rawResponse = String(utility.base64Decode(SAMLResponse, ));
  const attackResponse = `<NameID>evil@evil.com${rawResponse}</NameID>`;
  const octetString = buildSimpleSignOctetString(type, SAMLResponse, sigAlg, relayState, signature);

  await expect(
    sp.parseLoginResponse(
      idpNoEncrypt,
      'simpleSign',
      {
        body: {
          SAMLResponse: utility.base64Encode(attackResponse),
          Signature: signature,
          SigAlg: sigAlg
        },
        octetString
      }
    )
  ).rejects.toThrow();
});

// 测试：拒绝签名包装的响应 - 案例1
test('should reject signature wrapped response - case 1', async () => {
  const user = { NameID: 'user@esaml2.com' };

  const result = await idpNoEncrypt.createLoginResponse({
    sp: sp,
    requestInfo: sampleRequestInfo,
    binding: 'post',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpNoEncrypt,
        sp: sp
      },
      user: user,
      binding: 'post',
      requestInfo: sampleRequestInfo
    })
  });

  const { context: SAMLResponse } = result;
  const buffer = Buffer.from(SAMLResponse, 'base64');
  const xml = buffer.toString();

  // 创建无签名的版本
  const stripped = xml.replace(/<ds:Signature[\s\S]*ds:Signature>/, '');

  // 创建修改后的版本
  const outer = xml
    .replace(/assertion" ID="_[0-9a-f]{3}/g, 'assertion" ID="_000')
    .replace('user@esaml2.com', 'admin@esaml2.com');

  // 将无签名版本放入修改版本的SubjectConfirmationData中
  const xmlWrapped = outer.replace(
    /<saml:SubjectConfirmationData[^>]*\/>/,
    `<saml:SubjectConfirmationData>${stripped.replace('<?xml version="1.0" encoding="UTF-8"?>', '')}</saml:SubjectConfirmationData>`
  );

  const wrappedResponse = Buffer.from(xmlWrapped).toString('base64');

  await expect(
    sp.parseLoginResponse(
      idpNoEncrypt,
      'post',
      { body: { SAMLResponse: wrappedResponse } }
    )
  ).rejects.toThrow('ERR_POTENTIAL_WRAPPING_ATTACK');
});*/

// 测试：拒绝签名包装的响应 - 案例2
/*test('should reject signature wrapped response - case 2', async () => {
  const user = { NameID: 'user@esaml2.com' };

  const result = await idpNoEncrypt.createLoginResponse({
    sp: sp,
    requestInfo: sampleRequestInfo,
    binding: 'post',
    user: user,
    customTagReplacement: () => createTemplateCallback({
      entity: {
        idp: idpNoEncrypt,
        sp: sp
      },
      user: user,
      binding: 'post',
      requestInfo: sampleRequestInfo
    })
  });

  const { context: SAMLResponse } = result;
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

  await expect(
    sp.parseLoginResponse(
      idpNoEncrypt,
      'post',
      { body: { SAMLResponse: wrappedResponse } }
    )
  ).rejects.toThrow('ERR_POTENTIAL_WRAPPING_ATTACK');
/!*  await expect(
    sp.parseLoginResponse(
      idpNoEncrypt,
      'post',
      { body: { SAMLResponse: wrappedResponse } }
    )
  ).rejects.toThrow('ERR_FAIL_TO_VERIFY_ETS_SIGNATURE');*!/

});*/

// 测试：当响应返回失败状态时抛出两层代码错误
test('should throw two-tiers code error when the response does not return success status', async () => {
  await expect(
    sp.parseLoginResponse(
      idpNoEncrypt,
      'post',
      { body: { SAMLResponse: utility.base64Encode(failedResponse) } }
    )
  ).rejects.toThrow('ERR_FAILED_STATUS with top tier code: urn:oasis:names:tc:SAML:2.0:status:Requester, second tier code: urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy');
});

// 测试：当重定向绑定的响应返回失败状态时抛出两层代码错误
test('should throw two-tiers code error when the response by redirect does not return success status', async () => {
  const SAMLResponse = utility.base64Encode(utility.deflateString(failedResponse));
  const sigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
  const encodedSigAlg = encodeURIComponent(sigAlg);
  const octetString = 'SAMLResponse=' + encodeURIComponent(SAMLResponse) + '&SigAlg=' + encodedSigAlg;

  await expect(
    sp.parseLoginResponse(
      idpNoEncrypt,
      'redirect',
      {
        query: { SAMLResponse, SigAlg: encodedSigAlg },
        octetString
      }
    )
  ).rejects.toThrow('ERR_FAILED_STATUS with top tier code: urn:oasis:names:tc:SAML:2.0:status:Requester, second tier code: urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy');
});

// 测试：当SimpleSign绑定的响应返回失败状态时抛出两层代码错误
test('should throw two-tiers code error when the response over simpleSign does not return success status', async () => {
  await expect(
    sp.parseLoginResponse(
      idpNoEncrypt,
      'simpleSign',
      { body: { SAMLResponse: utility.base64Encode(failedResponse) } }
    )
  ).rejects.toThrow('ERR_FAILED_STATUS with top tier code: urn:oasis:names:tc:SAML:2.0:status:Requester, second tier code: urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy');
});

// 测试：没有时钟漂移设置时，过期的SAML响应应抛出ERR_SUBJECT_UNCONFIRMED错误
test('should throw ERR_SUBJECT_UNCONFIRMED for the expired SAML response without clock drift setup', async () => {
  const now = new Date();
  const fiveMinutesOneSecLater = new Date(now.getTime() + 301_000);
  const user = { NameID: 'user@esaml2.com' };

  try {
    const result = await idp.createLoginResponse({
      sp: sp,
      requestInfo: sampleRequestInfo,
      binding: 'post',
      user: user,
      customTagReplacement: () => createTemplateCallback({
        entity: {
          idp: idp,
          sp: sp
        },
        user: user,
        binding: 'post',
        requestInfo: sampleRequestInfo
      })
    });

    const { context: SAMLResponse } = result;

    tk.freeze(fiveMinutesOneSecLater);
    await sp.parseLoginResponse(
      idp,
      'post',
      { body: { SAMLResponse } }
    );

    expect.fail('Should have thrown ERR_SUBJECT_UNCONFIRMED');
  } catch (e) {
    expect(e).toBe('ERR_SUBJECT_UNCONFIRMED');
  } finally {
    tk.reset();
  }
});

// 测试：没有时钟漂移设置时，过期的重定向绑定的SAML响应应抛出ERR_SUBJECT_UNCONFIRMED错误
test('should throw ERR_SUBJECT_UNCONFIRMED for the expired SAML response by redirect without clock drift setup', async () => {
  const now = new Date();
  const fiveMinutesOneSecLater = new Date(now.getTime() + 301_000);
  const user = { NameID: 'user@esaml2.com' };

  try {
    const result = await idp.createLoginResponse({
      sp: sp,
      requestInfo: sampleRequestInfo,
      binding: 'redirect',
      user: user,
      customTagReplacement: () => createTemplateCallback({
        entity: {
          idp: idp,
          sp: sp
        },
        user: user,
        binding: 'redirect',
        requestInfo: sampleRequestInfo
      }),
      relayState: 'relaystate'
    });

    const { context } = result;

    tk.freeze(fiveMinutesOneSecLater);
    await sp.parseLoginResponse(
      idp,
      'redirect',
      parseRedirectUrlContextCallBack(context)
    );

    expect.fail('Should have thrown ERR_SUBJECT_UNCONFIRMED');
  } catch (e) {
    expect(e).toBe('ERR_SUBJECT_UNCONFIRMED');
  } finally {
    tk.reset();
  }
});

// 测试：没有时钟漂移设置时，过期的SimpleSign绑定的SAML响应应抛出ERR_SUBJECT_UNCONFIRMED错误
test('should throw ERR_SUBJECT_UNCONFIRMED for the expired SAML response by simpleSign without clock drift setup', async () => {
  const now = new Date();
  const fiveMinutesOneSecLater = new Date(now.getTime() + 301_000);
  const user = { NameID: 'user@esaml2.com' };

  try {
    const result = await idp.createLoginResponse({
      sp: sp,
      requestInfo: sampleRequestInfo,
      binding: 'simpleSign',
      user: user,
      customTagReplacement: () => createTemplateCallback({
        entity: {
          idp: idp,
          sp: sp
        },
        user: user,
        binding: 'simpleSign',
        requestInfo: sampleRequestInfo
      }),
      relayState: 'relaystate'
    }) as SimpleSignBindingContext;

    const {
      context: SAMLResponse,
      type,
      sigAlg,
      signature,
      relayState
    } = result;

    const octetString = buildSimpleSignOctetString(type, SAMLResponse, sigAlg, relayState, signature);

    tk.freeze(fiveMinutesOneSecLater);
    await sp.parseLoginResponse(
      idp,
      'simpleSign',
      {
        body: { SAMLResponse, Signature: signature, SigAlg: sigAlg },
        octetString
      }
    );

    expect.fail('Should have thrown ERR_SUBJECT_UNCONFIRMED');
  } catch (e) {
    expect(e).toBe('ERR_SUBJECT_UNCONFIRMED');
  } finally {
    tk.reset();
  }
});

// 测试：有时钟漂移设置时，过期的SAML响应不应抛出ERR_SUBJECT_UNCONFIRMED错误
test('should not throw ERR_SUBJECT_UNCONFIRMED for the expired SAML response with clock drift setup', async () => {
  const now = new Date();
  const fiveMinutesOneSecLater = new Date(now.getTime() + 301_000);
  const user = { NameID: 'user@esaml2.com' };

  try {
    const result = await idp.createLoginResponse({
      sp: spWithClockDrift,
      requestInfo: sampleRequestInfo,
      binding: 'post',
      user: user,
      customTagReplacement: () => createTemplateCallback({
        entity: {
          idp: idp,
          sp: spWithClockDrift
        },
        user: user,
        binding: 'post',
        requestInfo: sampleRequestInfo
      })
    });

    const { context: SAMLResponse } = result;

    tk.freeze(fiveMinutesOneSecLater);
    await spWithClockDrift.parseLoginResponse(
      idp,
      'post',
      { body: { SAMLResponse } }
    );

    expect(true).toBe(true);
  } catch (e) {
    expect.fail('Should not have thrown an error');
  } finally {
    tk.reset();
  }
});

// 测试：有时钟漂移设置时，过期的重定向绑定的SAML响应不应抛出ERR_SUBJECT_UNCONFIRMED错误
test('should not throw ERR_SUBJECT_UNCONFIRMED for the expired SAML response by redirect with clock drift setup', async () => {
  const now = new Date();
  const fiveMinutesOneSecLater = new Date(now.getTime() + 301_000);
  const user = { NameID: 'user@esaml2.com' };

  try {
    const result = await idp.createLoginResponse({
      sp: spWithClockDrift,
      requestInfo: sampleRequestInfo,
      binding: 'redirect',
      user: user,
      customTagReplacement: () => createTemplateCallback({
        entity: {
          idp: idp,
          sp: spWithClockDrift
        },
        user: user,
        binding: 'redirect',
        requestInfo: sampleRequestInfo
      }),
      relayState: ''
    });

    const { context } = result;

    tk.freeze(fiveMinutesOneSecLater);
    await spWithClockDrift.parseLoginResponse(
      idp,
      'redirect',
      parseRedirectUrlContextCallBack(context)
    );

    expect(true).toBe(true);
  } catch (e) {
    expect.fail('Should not have thrown an error');
  } finally {
    tk.reset();
  }
});

// 测试：有时钟漂移设置时，过期的SimpleSign绑定的SAML响应不应抛出ERR_SUBJECT_UNCONFIRMED错误
test('should not throw ERR_SUBJECT_UNCONFIRMED for the expired SAML response by simpleSign with clock drift setup', async () => {
  const now = new Date();
  const fiveMinutesOneSecLater = new Date(now.getTime() + 301_000);
  const user = { NameID: 'user@esaml2.com' };

  try {
    const result = await idp.createLoginResponse({
      sp: spWithClockDrift,
      requestInfo: sampleRequestInfo,
      binding: 'simpleSign',
      user: user,
      customTagReplacement: () => createTemplateCallback({
        entity: {
          idp: idp,
          sp: spWithClockDrift
        },
        user: user,
        binding: 'simpleSign',
        requestInfo: sampleRequestInfo
      }),
      relayState: 'relaystate'
    }) as SimpleSignBindingContext;

    const {
      context: SAMLResponse,
      type,
      signature,
      sigAlg,
      relayState
    } = result;

    const octetString = buildSimpleSignOctetString(type, SAMLResponse, sigAlg, relayState, signature);

    tk.freeze(fiveMinutesOneSecLater);
    await spWithClockDrift.parseLoginResponse(
      idp,
      'simpleSign',
      {
        body: { SAMLResponse, Signature: signature, SigAlg: sigAlg },
        octetString
      }
    );

    expect(true).toBe(true);
  } catch (e) {
    expect.fail('Should not have thrown an error');
  } finally {
    tk.reset();
  }
});

