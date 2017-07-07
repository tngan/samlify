import esaml2 = require('../index');
import { readFileSync, writeFileSync } from 'fs';
import test from 'ava';
import * as fs from 'fs';
import * as url from 'url';
import { DOMParser as dom } from 'xmldom';
import { xpath as select } from 'xml-crypto';
import * as _ from 'lodash';

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
  const acs = libsaml.extractor(spxml, [{ localName: 'AssertionConsumerService', attributes: ['index'] }])['assertionconsumerservice'];
  const spslo = libsaml.extractor(spxml, [{ localName: 'SingleLogoutService', attributes: ['index'] }])['singlelogoutservice'];
  const sso = libsaml.extractor(idpxml, [{ localName: 'SingleSignOnService', attributes: ['index'] }])['singlesignonservice'];
  const idpslo = libsaml.extractor(idpxml, [{ localName: 'SingleLogoutService', attributes: ['index'] }])['singlelogoutservice'];
  const sp98 = serviceProvider({ metadata: fs.readFileSync('./test/misc/sp_metadata_98.xml') });

  test('#33 sp metadata acs index should be increased by 1', t => {
    t.is(acs.length, 2);
    t.is(acs[0].index, '0');
    t.is(acs[1].index, '1');
  });
  test('#33 sp metadata slo index should be increased by 1', t => {
    t.is(spslo.length, 2);
    t.is(spslo[0].index, '0');
    t.is(spslo[1].index, '1');
  });
  test('#33 idp metadata sso index should be increased by 1', t => {
    t.is(sso.length, 2);
    t.is(sso[0].index, '0');
    t.is(sso[1].index, '1');
  });
  test('#33 idp metadata slo index should be increased by 1', t => {
    t.is(idpslo.length, 2);
    t.is(idpslo[0].index, '0');
    t.is(idpslo[1].index, '1');
  });
  test('#86 duplicate issuer throws error', t => {
    const xml = readFileSync('./test/misc/dumpes_issuer_response.xml');
    const { issuer } = libsaml.extractor(xml.toString(), ['Issuer']);
    t.is(issuer.length, 2);
    t.is((issuer as string[]).every(i => i === 'http://www.okta.com/dummyIssuer'), true);
  });
  test('#87 add existence check for signature verification', t => {
    try {
      libsaml.verifySignature(readFileSync('./test/misc/response.xml').toString(), {});
      t.fail();
    } catch ({ message }) {
      t.is(message, 'no signature is found in the context');
    }
  });
  test('#91 idp gets single sign on service from the metadata', t => {
    t.is(idp.entityMeta.getSingleSignOnService('post'), 'idp.example.com/sso');
  });
  test('#98 undefined AssertionConsumerServiceURL with redirect request', t => {
    const { id, context } = sp98.createLoginRequest(idp, 'redirect');
    const originalURL = url.parse(context, true);
    const request = originalURL.query.SAMLRequest;
    const rawRequest = utility.inflateString(decodeURIComponent(request));
    const xml = new dom().parseFromString(rawRequest);
    const authnRequest = select(xml, "/*[local-name(.)='AuthnRequest']")[0];
    const acsUrl = _.find(authnRequest.attributes, (a: any) => a.nodeName === 'AssertionConsumerServiceURL').nodeValue;
    t.is(acsUrl, 'https://example.org/response');
  });
})();
