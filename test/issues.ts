import esaml2 = require('../index');
import { readFileSync, writeFileSync } from 'fs';
import test from 'ava';
import * as fs from 'fs';
import * as url from 'url';
import { DOMParser as dom } from '@xmldom/xmldom';
import { xpath as select } from 'xml-crypto';
import { extract } from '../src/extractor';

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

test('#31 query param for sso/slo is SamlRequest', t => {
  t.is(getQueryParamByType('SAMLRequest'), wording.urlParams.samlRequest);
  t.is(getQueryParamByType('LogoutRequest'), wording.urlParams.samlRequest);
});
test('#31 query param for sso/slo is SamlResponse', t => {
  t.is(getQueryParamByType('SAMLResponse'), wording.urlParams.samlResponse);
  t.is(getQueryParamByType('LogoutResponse'), wording.urlParams.samlResponse);
});
test('#31 query param for sso/slo returns error', t => {
  try {
    getQueryParamByType('samlRequest');
    t.fail();
  } catch (e) {
    t.pass();
  }
});

(() => {
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
  test('#33 sp metadata acs index should be increased by 1', t => {
    t.is(acs.assertionConsumerService.length, 2);
    t.is(acs.assertionConsumerService[0].index, '0');
    t.is(acs.assertionConsumerService[1].index, '1');
  });
  test('#352 no index attribute for sp SingleLogoutService nodes', t => {
    t.is(spslo.singleLogoutService.length, 2);
    t.is(spslo.singleLogoutService[0].index, undefined);
    t.is(spslo.singleLogoutService[1].index, undefined);
  });
  test('#352 no index attribute for idp SingleSignOnService nodes', t => {
    t.is(sso.singleSignOnService.length, 2);
    t.is(sso.singleSignOnService[0].index, undefined);
    t.is(sso.singleSignOnService[1].index, undefined);
  });
  test('#352 no index attribute for idp SingleLogoutService nodes', t => {
    t.is(idpslo.singleLogoutService.length, 2);
    t.is(idpslo.singleLogoutService[0].index, undefined);
    t.is(idpslo.singleLogoutService[1].index, undefined);
  });
  test('#86 duplicate issuer throws error', t => {
    const xml = readFileSync('./test/misc/dumpes_issuer_response.xml');
    const { issuer } = extract(xml.toString(), [{
      key: 'issuer',
      localPath: [
        ['Response', 'Issuer'],
        ['Response', 'Assertion', 'Issuer']
      ],
      attributes: []
    }]);
    t.is(issuer.length, 1);
    t.is(issuer.every(i => i === 'http://www.okta.com/dummyIssuer'), true);
  });

  test('#87 add existence check for signature verification', t => {
    try {
      libsaml.verifySignature(readFileSync('./test/misc/response.xml').toString(), {});
      t.fail();
    } catch ({ message }) {
      t.is(message, 'ERR_ZERO_SIGNATURE');
    }
  });

  test('#91 idp gets single sign on service from the metadata', t => {
    t.is(idp.entityMeta.getSingleSignOnService('post'), 'idp.example.com/sso');
  });
  
  test('#98 undefined AssertionConsumerServiceURL with redirect request', t => {
    const { id, context } = sp98.createLoginRequest(idp, 'redirect');
    const originalURL = url.parse(context, true);
    const request = originalURL.query.SAMLRequest as string;
    const rawRequest = utility.inflateString(decodeURIComponent(request));
    const xml = new dom().parseFromString(rawRequest);
    const authnRequest = select(xml, "/*[local-name(.)='AuthnRequest']")[0];
    const index = Object.keys(authnRequest.attributes).find((i: string) => authnRequest.attributes[i].nodeName === 'AssertionConsumerServiceURL') as any;
    t.is(authnRequest.attributes[index].nodeValue, 'https://example.org/response');
  });
})();