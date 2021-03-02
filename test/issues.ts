/* eslint-disable @typescript-eslint/no-unsafe-call */
import test from 'ava';
import { readFileSync } from 'fs';
import { xpath as select } from 'xml-crypto';
import { DOMParser as dom } from 'xmldom';
import { identityProvider, serviceProvider } from '../src';
import { isSamlifyError, SamlifyErrorCode } from '../src/error';
import { extract, isElement } from '../src/extractor';
import { libsaml } from '../src/libsaml';
import { BindingNamespace, wording } from '../src/urn';
import { inflateString } from '../src/utility';

const getQueryParamByType = libsaml.getQueryParamByType;

test('#31 query param for sso/slo is SamlRequest', (t) => {
	t.is(getQueryParamByType('SAMLRequest'), wording.urlParams.samlRequest);
	t.is(getQueryParamByType('LogoutRequest'), wording.urlParams.samlRequest);
});
test('#31 query param for sso/slo is SamlResponse', (t) => {
	t.is(getQueryParamByType('SAMLResponse'), wording.urlParams.samlResponse);
	t.is(getQueryParamByType('LogoutResponse'), wording.urlParams.samlResponse);
});
test('#31 query param for sso/slo returns error', (t) => {
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
		assertionConsumerService: [
			{
				Binding: BindingNamespace.Post,
				Location: 'sp.example.com/acs',
			},
			{
				Binding: BindingNamespace.Redirect,
				Location: 'sp.example.com/acs',
			},
		],
		singleLogoutService: [
			{
				Binding: BindingNamespace.Post,
				Location: 'sp.example.com/slo',
			},
			{
				Binding: BindingNamespace.Redirect,
				Location: 'sp.example.com/slo',
			},
		],
	};
	const idpcfg = {
		entityID: 'idp.example.com',
		nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
		singleSignOnService: [
			{
				Binding: BindingNamespace.Post,
				Location: 'https://idp.example.com/sso',
			},
			{
				Binding: BindingNamespace.Redirect,
				Location: 'https://idp.example.com/sso',
			},
		],
		singleLogoutService: [
			{
				Binding: BindingNamespace.Post,
				Location: 'https://idp.example.com/sso/slo',
			},
			{
				Binding: BindingNamespace.Redirect,
				Location: 'https://idp.example.com/sso/slo',
			},
		],
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
		},
	]);
	const spslo = extract(spxml, [
		{
			key: 'singleLogoutService',
			localPath: ['EntityDescriptor', 'SPSSODescriptor', 'SingleLogoutService'],
			attributes: ['Binding', 'Location', 'isDefault', 'index'],
		},
	]);
	const sso = extract(idpxml, [
		{
			key: 'singleSignOnService',
			localPath: ['EntityDescriptor', 'IDPSSODescriptor', 'SingleSignOnService'],
			attributes: ['Binding', 'Location', 'isDefault', 'index'],
		},
	]);
	const idpslo = extract(idpxml, [
		{
			key: 'singleLogoutService',
			localPath: ['EntityDescriptor', 'IDPSSODescriptor', 'SingleLogoutService'],
			attributes: ['Binding', 'Location', 'isDefault', 'index'],
		},
	]);
	const sp98 = serviceProvider({ metadata: readFileSync('./test/misc/sp_metadata_98.xml') });
	test('#33 sp metadata acs index should be increased by 1', (t) => {
		t.is(acs.assertionConsumerService.length, 2);
		t.is(acs.assertionConsumerService[0].index, '0');
		t.is(acs.assertionConsumerService[1].index, '1');
	});
	test('#352 no index attribute for sp SingleLogoutService nodes', (t) => {
		t.is(spslo.singleLogoutService.length, 2);
		t.is(spslo.singleLogoutService[0].index, undefined);
		t.is(spslo.singleLogoutService[1].index, undefined);
	});
	test('#352 no index attribute for idp SingleSignOnService nodes', (t) => {
		t.is(sso.singleSignOnService.length, 2);
		t.is(sso.singleSignOnService[0].index, undefined);
		t.is(sso.singleSignOnService[1].index, undefined);
	});
	test('#352 no index attribute for idp SingleLogoutService nodes', (t) => {
		t.is(idpslo.singleLogoutService.length, 2);
		t.is(idpslo.singleLogoutService[0].index, undefined);
		t.is(idpslo.singleLogoutService[1].index, undefined);
	});
	test('#86 duplicate issuer throws error', (t) => {
		const xml = readFileSync('./test/misc/dumpes_issuer_response.xml');
		const { issuer } = extract(xml.toString(), [
			{
				key: 'issuer',
				localPath: [
					['Response', 'Issuer'],
					['Response', 'Assertion', 'Issuer'],
				],
				attributes: [],
			},
		]);
		t.is(issuer.length, 1);
		t.is(
			// eslint-disable-next-line @typescript-eslint/no-unsafe-call
			issuer.every((i: any) => i === 'http://www.okta.com/dummyIssuer'),
			true
		);
	});

	test('#87 add existence check for signature verification', (t) => {
		try {
			libsaml.verifySignature(readFileSync('./test/misc/response.xml').toString(), {});
			t.fail();
		} catch (e) {
			t.is(isSamlifyError(e), true);
			t.is(e.code, SamlifyErrorCode.ZeroSignature);
		}
	});

	test('#91 idp gets single sign on service from the metadata', (t) => {
		t.is(idp.getEntityMeta().getSingleSignOnService(BindingNamespace.Post), 'https://idp.example.com/sso');
	});

	test('#98 undefined AssertionConsumerServiceURL with redirect request', (t) => {
		const { context } = sp98.createLoginRequest(idp, BindingNamespace.Redirect);
		const url = new URL(context);
		const request = url.searchParams.get('SAMLRequest') as string;
		const rawRequest = inflateString(decodeURIComponent(request));
		const xml = new dom().parseFromString(rawRequest);
		const authnRequest = select(xml, "/*[local-name(.)='AuthnRequest']")[0];
		if (!isElement(authnRequest)) {
			throw new Error('Not an element!');
		}
		const index = Object.keys(authnRequest.attributes).find(
			(i: any) => authnRequest.attributes[i]?.nodeName === 'AssertionConsumerServiceURL'
		) as any;
		t.is(authnRequest.attributes[index]?.nodeValue, 'https://example.org/response');
	});
})();
