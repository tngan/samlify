import * as esaml2 from '../index.js';
import { readFileSync } from 'fs';
import { test, expect } from 'vitest';
import * as fs from 'fs';
import * as url from 'url';
import { DOMParser as dom } from '@xmldom/xmldom';
import { extract } from '../src/extractor.js';

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
const wording = ref.wording;
test('#31 query param for sso/slo is SamlRequest', () => {
  expect(getQueryParamByType('SAMLRequest')).toBe(wording.urlParams.samlRequest);
  expect(getQueryParamByType('LogoutRequest')).toBe(wording.urlParams.samlRequest);
});

test('#31 query param for sso/slo is SamlResponse', () => {
  expect(getQueryParamByType('SAMLResponse')).toBe(wording.urlParams.samlResponse);/**/
  expect(getQueryParamByType('LogoutResponse')).toBe(wording.urlParams.samlResponse);
});

test('#31 query param for sso/slo returns error', () => {
  expect(() => getQueryParamByType('samlRequest')).toThrow();
});
const spcfg = {
  entityID: 'sp.example.com',
  nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
  assertionConsumerService: [{
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    Location: 'sp.example.com/acs',
  }, {
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    Location: 'sp.example.com/acs',
  }],
  singleLogoutService: [{
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    Location: 'sp.example.com/slo',
  }, {
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    Location: 'sp.example.com/slo',
  }],
};
const idpcfg = {
  entityID: 'idp.example.com',
  nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
  singleSignOnService: [{
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    Location: 'idp.example.com/sso',
  }, {
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    Location: 'idp.example.com/sso',
  }],
  singleLogoutService: [{
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    Location: 'idp.example.com/sso/slo',
  }, {
    Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    Location: 'idp.example.com/sso/slo',
  }],
};
const idp = identityProvider(idpcfg);
const sp = serviceProvider(spcfg);
const spxml = sp.getMetadata();
const idpxml = idp.getMetadata();
const acs = extract(spxml, [
  {
    key: 'assertionConsumerService',
    localPath: ['EntityDescriptor', 'SPSSODescriptor', 'AssertionConsumerService'],
    attributes: ['Binding', 'Location', 'isDefault', 'index'],
  }
]);
const spslo = extract(spxml, [
  {
    key: 'singleLogoutService',
    localPath: ['EntityDescriptor', 'SPSSODescriptor', 'SingleLogoutService'],
    attributes: ['Binding', 'Location', 'isDefault', 'index'],
  }
]);
const sso = extract(idpxml, [
  {
    key: 'singleSignOnService',
    localPath: ['EntityDescriptor', 'IDPSSODescriptor', 'SingleSignOnService'],
    attributes: ['Binding', 'Location', 'isDefault', 'index'],
  }
]);
const idpslo = extract(idpxml, [
  {
    key: 'singleLogoutService',
    localPath: ['EntityDescriptor', 'IDPSSODescriptor', 'SingleLogoutService'],
    attributes: ['Binding', 'Location', 'isDefault', 'index'],
  }
]);
const sp98 = serviceProvider({ metadata: fs.readFileSync('./test/misc/sp_metadata_98.xml') });

test('#33 sp metadata acs index should be increased by 1', () => {
  expect(acs.assertionConsumerService.length).toBe(2);
  expect(acs.assertionConsumerService[0].index).toBe('0');
  expect(acs.assertionConsumerService[1].index).toBe('1');
});
test('#352 no index attribute for sp SingleLogoutService nodes', () => {
  expect(spslo.singleLogoutService.length).toBe(2);
  expect(spslo.singleLogoutService[0].index).toBeUndefined();
  expect(spslo.singleLogoutService[1].index).toBeUndefined();
});
test('#352 no index attribute for idp SingleSignOnService nodes', () => {
  expect(sso.singleSignOnService.length).toBe(2);
  expect(sso.singleSignOnService[0].index).toBeUndefined();
  expect(sso.singleSignOnService[1].index).toBeUndefined();
});
test('#352 no index attribute for idp SingleLogoutService nodes', () => {
  expect(idpslo.singleLogoutService.length).toBe(2);
  expect(idpslo.singleLogoutService[0].index).toBeUndefined();
  expect(idpslo.singleLogoutService[1].index).toBeUndefined();
});
test('#86 duplicate issuer throws error', () => {
  const xml = readFileSync('./test/misc/dumpes_issuer_response.xml');
  const { issuer } = extract(xml.toString(), [{
    key: 'issuer',
    localPath: [
      ['Response', 'Issuer'],
      ['Response', 'Assertion', 'Issuer']
    ],
    attributes: []
  }]);

  expect(issuer.length).toBe(1);
  expect(issuer.every(i => i === 'http://www.okta.com/dummyIssuer')).toBe(true);
});
/*test('#87 add existence check for signature verification', () => {
  expect(() => {
    libsaml.verifySignature(readFileSync('./test/misc/response.xml').toString(), {});
  }).toThrowError('ERR_ZERO_SIGNATURE');
});*/
test('#91 idp gets single sign on service from the metadata', () => {
  expect(idp.entityMeta.getSingleSignOnService('post')).toBe('idp.example.com/sso');
});
/*test('#98 undefined AssertionConsumerServiceURL with redirect request', () => {
  const { context } = sp98.createLoginRequest(idp, 'redirect');
  const originalURL = url.parse(context, true);
  const request = originalURL.query.SAMLRequest;
  let decode = decodeURIComponent(request as string)
  const rawRequest = utility.inflateString(decodeURIComponent(request as string));
  const xml = new dom().parseFromString(rawRequest, 'application/xml');
// @ts-ignore
  const acsUrl = xml.documentElement.attributes.getNamedItem('AssertionConsumerServiceURL')?.value;

  expect(acsUrl).toBe('https://example.org/response');
});*/






test('#91 idp gets single sign on service from the metadata', () => {
  // 获取 IDP 元数据中的单点登录服务
  const ssoService = idp.entityMeta.getSingleSignOnService('post');

  // 验证获取的服务地址是否正确
  expect(ssoService).toBe('idp.example.com/sso');
});

/*test('#98 undefined AssertionConsumerServiceURL with redirect request', () => {
  // 1. 创建登录请求
  const { context } = sp98.createLoginRequest(idp, 'redirect');

  // 2. 解析 URL
  const parsedUrl = url(context);
  const requestParam = parsedUrl.searchParams.get('SAMLRequest');

  // 3. 解码和处理 SAMLRequest
  const decodedRequest = decodeURIComponent(requestParam);
  const rawRequest = inflateString(decodedRequest);

  // 4. 解析 XML
  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(rawRequest, 'text/xml');

  // 5. 获取属性值并验证
  const acsUrl = xmlDoc.documentElement.getAttribute('AssertionConsumerServiceURL');
  expect(acsUrl).toBe('https://example.org/response');
});*/
