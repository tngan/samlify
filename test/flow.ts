/* eslint-disable @typescript-eslint/no-unsafe-call */
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import * as validator from '@authenio/samlify-xsd-schema-validator';
import test from 'ava';
import { readFileSync } from 'fs';
import tk from 'timekeeper';
import { v4 as uuid } from 'uuid';
import { identityProvider, libsaml, serviceProvider, setSchemaValidator } from '../src';
import type { IdentityProvider } from '../src/entity-idp';
import type { ServiceProvider } from '../src/entity-sp';
import { isSamlifyError, SamlifyErrorCode } from '../src/error';
import { BindingNamespace, MessageSignatureOrder, names, wording } from '../src/urn';
import { base64Decode, base64Encode, isString } from '../src/utility';

// import * as validator from '@authenio/samlify-validate-with-xmllint';
// import * as validator from '@authenio/samlify-node-xmllint';
// import * as validator from '@authenio/samlify-libxml-xsd';

// const validator = require('@authenio/samlify-xsd-schema-validator');
// const validator = require('@authenio/samlify-validate-with-xmllint');
// const validator = require('@authenio/samlify-node-xmllint');
// const validator = require('@authenio/samlify-libxml-xsd');

setSchemaValidator(validator);

// Custom template
const loginResponseTemplate = {
	context:
		'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status><saml:Assertion ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}" InResponseTo="{InResponseTo}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{AttributeStatement}</saml:Assertion></samlp:Response>',
	attributes: [
		{
			name: 'mail',
			valueTag: 'user.email',
			nameFormat: names.attrnameFormat.basic,
			valueXsiType: 'xs:string',
		},
		{
			name: 'name',
			valueTag: 'user.name',
			nameFormat: names.attrnameFormat.basic,
			valueXsiType: 'xs:string',
		},
	],
};

const failedResponse = String(readFileSync('./test/misc/failed_response.xml'));

const createTemplateCallback = (
	_idp?: IdentityProvider,
	_sp?: ServiceProvider,
	user?: Record<string, string>,
	requestInfo?: RequestInfo
) => (template: string, values: Record<string, any>) => {
	const _id = '_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6';
	const now = new Date();
	const spEntityID = _sp?.getEntityMeta().getEntityID();
	const idpSetting = _idp?.getEntitySettings();
	const fiveMinutesLater = new Date(now.getTime());
	fiveMinutesLater.setMinutes(fiveMinutesLater.getMinutes() + 5);
	const newValues = {
		...values,
		ID: _id,
		AssertionID: idpSetting?.generateID ? idpSetting.generateID() : `${uuid()}`,
		// Destination: _sp?.entityMeta.getAssertionConsumerService(BindingNamespace.Post),
		Audience: spEntityID,
		SubjectRecipient: spEntityID,
		NameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
		NameID: user?.email,
		// Issuer: _idp?.entityMeta.getEntityID(),
		IssueInstant: now.toISOString(),
		ConditionsNotBefore: now.toISOString(),
		ConditionsNotOnOrAfter: fiveMinutesLater.toISOString(),
		SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater.toISOString(),
		AssertionConsumerServiceURL: _sp?.getEntityMeta().getAssertionConsumerService(BindingNamespace.Post),
		EntityID: spEntityID,
		InResponseTo: requestInfo?.extract.request.id ?? '_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4',
		StatusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',
		attrUserEmail: 'myemailassociatedwithsp@sp.com',
		attrUserName: 'mynameinsp',
	};
	return [libsaml.replaceTagsByValue(template, newValues), newValues] as [string, Record<string, any>];
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

const sampleRequestInfo = { samlContent: '', extract: { request: { id: 'request_id' } } } as const;
type RequestInfo = { extract: { request: { id: string } } };

// Define entities
const idp = identityProvider(defaultIdpConfig);
const sp = serviceProvider(defaultSpConfig);
const idpNoEncrypt = identityProvider({ ...defaultIdpConfig, isAssertionEncrypted: false });
const idpcustomNoEncrypt = identityProvider({
	...defaultIdpConfig,
	isAssertionEncrypted: false,
	loginResponseTemplate,
});
const idpcustom = identityProvider({ ...defaultIdpConfig, loginResponseTemplate });
const idpEncryptThenSign = identityProvider({ ...defaultIdpConfig, messageSigningOrder: MessageSignatureOrder.ETS });
const spWantLogoutReqSign = serviceProvider({ ...defaultSpConfig, wantLogoutRequestSigned: true });
const idpWantLogoutResSign = identityProvider({ ...defaultIdpConfig, wantLogoutResponseSigned: true });
const spNoAssertSign = serviceProvider({ ...defaultSpConfig, metadata: spmetaNoAssertSign });
const spNoAssertSignCustomConfig = serviceProvider({
	...defaultSpConfig,
	metadata: spmetaNoAssertSign,
	signatureConfig: {
		prefix: 'ds',
		location: {
			reference: "/*[local-name(.)='Response']/*[local-name(.)='Issuer']",
			action: 'after',
		},
	},
});
const spWithClockDrift = serviceProvider({ ...defaultSpConfig, clockDrifts: [-2000, 2000] });

// function writer(str) {
// 	writeFileSync('test.txt', str);
// }

test('create login request with redirect binding using default template and parse it', async (t) => {
	const { id, context } = sp.createLoginRequest(idp, BindingNamespace.Redirect);
	t.true(isString(id));
	t.true(isString(context));
	const url = new URL(`https://${context}`);
	const SAMLRequest = url.searchParams.get(wording.urlParams.samlRequest);
	const Signature = url.searchParams.get(wording.urlParams.signature);
	const SigAlg = url.searchParams.get(wording.urlParams.sigAlg);
	url.searchParams.delete('Signature');
	const octetString = Array.from(url.searchParams.keys())
		.map((q) => q + '=' + encodeURIComponent(url.searchParams.get(q) as string))
		.join('&');
	const { /*samlContent,*/ extract } = await idp.parseLoginRequest(sp, BindingNamespace.Redirect, {
		query: { SAMLRequest, Signature, SigAlg },
		octetString,
	});
	t.is(extract.issuer, 'https://sp.example.org/metadata');
	t.true(isString(extract.request?.id));
	t.is(extract.nameIDPolicy?.format, 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
	t.is(extract.nameIDPolicy?.allowCreate, 'false');
});

test('create login request with post binding using default template and parse it', async (t) => {
	const result = sp.createLoginRequest(idp, BindingNamespace.Post);
	t.is('entityEndpoint' in result, true);
	if (!('entityEndpoint' in result)) return;
	t.true(isString(result.id));
	t.true(isString(result.context));
	t.true(isString(result.entityEndpoint));
	t.is(result.type, 'SAMLRequest');
	const { extract } = await idp.parseLoginRequest(sp, BindingNamespace.Post, { body: { SAMLRequest: result.context } });
	t.is(extract.issuer, 'https://sp.example.org/metadata');
	t.true(isString(extract.request?.id));
	t.true(isString(extract.request?.issueInstant));
	t.is(extract.request?.destination, 'https://idp.example.org/sso/SingleSignOnService');
	t.is(extract.request?.assertionConsumerServiceUrl, 'https://sp.example.org/sp/sso');
	t.is(extract.nameIDPolicy?.format, 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
	t.is(extract.nameIDPolicy?.allowCreate, 'false');
	t.true(isString(extract.signature));
});

test('signed in sp is not matched with the signed notation in idp with post request', (t) => {
	const _idp = identityProvider({ ...defaultIdpConfig, metadata: noSignedIdpMetadata });
	try {
		sp.createLoginRequest(_idp, BindingNamespace.Post);
		t.fail();
	} catch (e) {
		t.is(isSamlifyError(e), true);
		t.is(e.code, SamlifyErrorCode.MetadataConflictRequestSignedFlag);
	}
});

test('signed in sp is not matched with the signed notation in idp with redirect request', (t) => {
	const _idp = identityProvider({ ...defaultIdpConfig, metadata: noSignedIdpMetadata });
	try {
		sp.createLoginRequest(_idp, BindingNamespace.Redirect);
		t.fail();
	} catch (e) {
		t.is(isSamlifyError(e), true);
		t.is(e.code, SamlifyErrorCode.MetadataConflictRequestSignedFlag);
	}
});

test('create login request with redirect binding using [custom template]', (t) => {
	const _sp = serviceProvider({
		...defaultSpConfig,
		loginRequestTemplate: {
			context:
				'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="{AllowCreate}"/></samlp:AuthnRequest>',
		},
	});
	const { context, id } = _sp.createLoginRequest(idp, BindingNamespace.Redirect, (template, values) => {
		values.ID = 'exposed_testing_id';
		return [
			template,
			values, // all the tags are supposed to be replaced
		] as const;
	});
	id === 'exposed_testing_id' && isString(context) ? t.pass() : t.fail();
});

test('create login request with post binding using [custom template]', (t) => {
	const _sp = serviceProvider({
		...defaultSpConfig,
		loginRequestTemplate: {
			context:
				'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="{AllowCreate}"/></samlp:AuthnRequest>',
		},
	});
	const result = _sp.createLoginRequest(idp, BindingNamespace.Post, (template, values) => {
		values.ID = 'exposed_testing_id';
		return [
			template,
			values, // all the tags are supposed to be replaced
		] as const;
	});
	t.is('entityEndpoint' in result, true);
	if (!('entityEndpoint' in result)) return;
	t.true(isString(result.id));
	t.true(isString(result.context));
	t.true(isString(result.relayState));
	t.true(isString(result.entityEndpoint));
	t.is(result.type, 'SAMLRequest');
	t.is(result.id, 'exposed_testing_id');
});

test('create login response with undefined binding', async (t) => {
	const user = { email: 'user@esaml2.com' };
	const error = await t.throwsAsync(
		() =>
			// eslint-disable-next-line @typescript-eslint/ban-ts-comment
			// @ts-expect-error
			idp.createLoginResponse(sp, {}, 'undefined', user, createTemplateCallback(idp, sp, user)) // eslint-disable-line
	);
	t.is(isSamlifyError(error), true);
	if (isSamlifyError(error)) t.is(error.code, SamlifyErrorCode.UnsupportedBinding);
});

test('create post login response', async (t) => {
	const user = { email: 'user@esaml2.com' };
	const { id, context } = await idp.createLoginResponse(
		sp,
		sampleRequestInfo,
		BindingNamespace.Post,
		user,
		createTemplateCallback(idp, sp, user)
	);
	isString(id) && isString(context) ? t.pass() : t.fail();
});

test('create logout request with redirect binding', (t) => {
	const { id, context } = sp.createLogoutRequest(idp, BindingNamespace.Redirect, { logoutNameID: 'user@esaml2' });
	isString(id) && isString(context) ? t.pass() : t.fail();
});

test('create logout request with post binding', (t) => {
	const result = sp.createLogoutRequest(idp, BindingNamespace.Post, {
		logoutNameID: 'user@esaml2',
	});
	t.is('entityEndpoint' in result, true);
	if (!('entityEndpoint' in result)) return;
	t.true(isString(result.id));
	t.true(isString(result.context));
	t.true(isString(result.relayState));
	t.true(isString(result.entityEndpoint));
	t.is(result.type, 'SAMLRequest');
});

test('create logout request when idp only has one binding', (t) => {
	const testIdp = identityProvider(oneloginIdpConfig);
	const { id, context } = sp.createLogoutRequest(testIdp, BindingNamespace.Redirect, { logoutNameID: 'user@esaml2' });
	isString(id) && isString(context) ? t.pass() : t.fail();
});

test('create logout response with undefined binding', (t) => {
	try {
		// eslint-disable-next-line @typescript-eslint/ban-ts-comment
		// @ts-expect-error
		idp.createLogoutResponse(sp, {}, 'undefined', '', createTemplateCallback(idp, sp, {}));
		t.fail();
	} catch (e) {
		t.is(isSamlifyError(e), true);
		t.is(e.code, SamlifyErrorCode.UnsupportedBinding);
	}
});

test('create logout response with redirect binding', (t) => {
	const { id, context } = idp.createLogoutResponse(
		sp,
		{},
		BindingNamespace.Redirect,
		'',
		createTemplateCallback(idp, sp, {})
	);
	t.true(isString(id));
	t.true(isString(context));
});

test('create logout response with post binding', (t) => {
	const result = idp.createLogoutResponse(sp, {}, BindingNamespace.Post, '', createTemplateCallback(idp, sp, {}));
	t.is('entityEndpoint' in result, true);
	if (!('entityEndpoint' in result)) return;
	t.true(isString(result.id));
	t.true(isString(result.context));
	t.true(isString(result.relayState));
	t.true(isString(result.entityEndpoint));
	t.is(result.type, 'SAMLResponse');
});

// Check if the response data parsing is correct
// All test cases are using customize template

// simulate idp-initiated sso
test('send response with signed assertion and parse it', async (t) => {
	// sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
	const user = { email: 'user@esaml2.com' };
	const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(
		sp,
		sampleRequestInfo,
		BindingNamespace.Post,
		user,
		createTemplateCallback(idpNoEncrypt, sp, user, sampleRequestInfo)
	);
	// receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
	const { samlContent, extract } = await sp.parseLoginResponse(idpNoEncrypt, BindingNamespace.Post, {
		body: { SAMLResponse },
	});
	t.true(isString(id));
	t.is(samlContent.startsWith('<samlp:Response'), true);
	t.is(samlContent.endsWith('/samlp:Response>'), true);
	t.is(extract.nameID, 'user@esaml2.com');
	t.is(extract.response?.inResponseTo, 'request_id');
});

test('send response with signed assertion + custom transformation algorithms and parse it', async (t) => {
	// sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
	const signedAssertionSp = serviceProvider({
		...defaultSpConfig,
		transformationAlgorithms: [
			'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
			'http://www.w3.org/2001/10/xml-exc-c14n#',
		],
	});

	const user = { email: 'user@esaml2.com' };
	const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(
		signedAssertionSp,
		sampleRequestInfo,
		BindingNamespace.Post,
		user,
		createTemplateCallback(idpNoEncrypt, sp, user, sampleRequestInfo)
	);
	// receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
	const { samlContent, extract } = await sp.parseLoginResponse(idpNoEncrypt, BindingNamespace.Post, {
		body: { SAMLResponse },
	});
	t.true(isString(id));
	t.is(samlContent.startsWith('<samlp:Response'), true);
	t.is(samlContent.endsWith('/samlp:Response>'), true);
	t.is(extract.nameID, 'user@esaml2.com');
	t.is(extract.response?.inResponseTo, 'request_id');

	// Verify xmldsig#enveloped-signature is included in the response
	if (samlContent.indexOf('http://www.w3.org/2000/09/xmldsig#enveloped-signature') === -1) {
		t.fail();
	}
});

test('send response with [custom template] signed assertion and parse it', async (t) => {
	// sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
	const requestInfo = { extract: { request: { id: 'request_id' } } };
	const user = { email: 'user@esaml2.com' };
	const { id, context: SAMLResponse } = await idpcustomNoEncrypt.createLoginResponse(
		sp,
		requestInfo,
		BindingNamespace.Post,
		user,
		// declare the callback to do custom template replacement
		createTemplateCallback(idpcustomNoEncrypt, sp, user)
	);
	// receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
	const { samlContent, extract } = await sp.parseLoginResponse(idpcustomNoEncrypt, BindingNamespace.Post, {
		body: { SAMLResponse },
	});
	t.true(isString(id));
	t.is(samlContent.startsWith('<samlp:Response'), true);
	t.is(samlContent.endsWith('/samlp:Response>'), true);
	t.is(extract.nameID, 'user@esaml2.com');
	t.is(extract.attributes?.name, 'mynameinsp');
	t.is(extract.attributes?.mail, 'user@esaml2.com');
	t.is(extract.response?.inResponseTo, '_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});

test('send response with signed message and parse it', async (t) => {
	// sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
	const user = { email: 'user@esaml2.com' };
	const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(
		spNoAssertSign,
		sampleRequestInfo,
		BindingNamespace.Post,
		user,
		createTemplateCallback(idpNoEncrypt, spNoAssertSign, user, sampleRequestInfo)
	);
	// receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
	const { samlContent, extract } = await spNoAssertSign.parseLoginResponse(idpNoEncrypt, BindingNamespace.Post, {
		body: { SAMLResponse },
	});
	t.true(isString(id));
	t.is(samlContent.startsWith('<samlp:Response'), true);
	t.is(samlContent.endsWith('/samlp:Response>'), true);
	t.is(extract.nameID, 'user@esaml2.com');
	t.is(extract.response?.inResponseTo, 'request_id');
});

test('send response with [custom template] and signed message and parse it', async (t) => {
	// sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
	// const requestInfo = { extract: { authnrequest: { id: 'request_id' } } };
	const user = { email: 'user@esaml2.com' };
	const { id, context: SAMLResponse } = await idpcustomNoEncrypt.createLoginResponse(
		spNoAssertSign,
		{ extract: { request: { id: 'request_id' } } },
		BindingNamespace.Post,
		{ email: 'user@esaml2.com' },
		createTemplateCallback(idpcustomNoEncrypt, spNoAssertSign, user)
	);
	// receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
	const { samlContent, extract } = await spNoAssertSign.parseLoginResponse(idpcustomNoEncrypt, BindingNamespace.Post, {
		body: { SAMLResponse },
	});
	t.true(isString(id));
	t.is(samlContent.startsWith('<samlp:Response'), true);
	t.is(samlContent.endsWith('/samlp:Response>'), true);
	t.is(extract.nameID, 'user@esaml2.com');
	t.is(extract.attributes?.name, 'mynameinsp');
	t.is(extract.attributes?.mail, 'user@esaml2.com');
	t.is(extract.response?.inResponseTo, '_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});

test('send login response with signed assertion + signed message and parse it', async (t) => {
	const spWantMessageSign = serviceProvider({
		...defaultSpConfig,
		wantMessageSigned: true,
	});
	const user = { email: 'user@esaml2.com' };
	const { id, context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(
		spWantMessageSign,
		sampleRequestInfo,
		BindingNamespace.Post,
		user,
		createTemplateCallback(idpNoEncrypt, spWantMessageSign, user, sampleRequestInfo)
	);
	// receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
	const { samlContent, extract } = await spWantMessageSign.parseLoginResponse(idpNoEncrypt, BindingNamespace.Post, {
		body: { SAMLResponse },
	});
	t.true(isString(id));
	t.is(samlContent.startsWith('<samlp:Response'), true);
	t.is(samlContent.endsWith('/samlp:Response>'), true);
	t.is(extract.nameID, 'user@esaml2.com');
	t.is(extract.response?.inResponseTo, 'request_id');
});

test('send login response with [custom template] and signed assertion + signed message and parse it', async (t) => {
	const spWantMessageSign = serviceProvider({
		...defaultSpConfig,
		wantMessageSigned: true,
	});
	const user = { email: 'user@esaml2.com' };
	const { id, context: SAMLResponse } = await idpcustomNoEncrypt.createLoginResponse(
		spWantMessageSign,
		{ extract: { request: { id: 'request_id' } } },
		BindingNamespace.Post,
		{ email: 'user@esaml2.com' },
		createTemplateCallback(idpcustomNoEncrypt, spWantMessageSign, user)
	);
	// receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
	const { samlContent, extract } = await spWantMessageSign.parseLoginResponse(
		idpcustomNoEncrypt,
		BindingNamespace.Post,
		{
			body: { SAMLResponse },
		}
	);
	t.true(isString(id));
	t.is(samlContent.startsWith('<samlp:Response'), true);
	t.is(samlContent.endsWith('/samlp:Response>'), true);
	t.is(extract.nameID, 'user@esaml2.com');
	t.is(extract.attributes?.name, 'mynameinsp');
	t.is(extract.attributes?.mail, 'user@esaml2.com');
	t.is(extract.response?.inResponseTo, '_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});

test('send login response with encrypted non-signed assertion and parse it', async (t) => {
	const user = { email: 'user@esaml2.com' };
	const { id, context: SAMLResponse } = await idp.createLoginResponse(
		spNoAssertSign,
		sampleRequestInfo,
		BindingNamespace.Post,
		user,
		createTemplateCallback(idp, spNoAssertSign, user, sampleRequestInfo)
	);
	// receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
	const { samlContent, extract } = await spNoAssertSign.parseLoginResponse(idp, BindingNamespace.Post, {
		body: { SAMLResponse },
	});
	t.true(isString(id));
	t.is(samlContent.startsWith('<samlp:Response'), true);
	t.is(samlContent.endsWith('/samlp:Response>'), true);
	t.is(extract.nameID, 'user@esaml2.com');
	t.is(extract.response?.inResponseTo, 'request_id');
});

test('send login response with encrypted signed assertion and parse it', async (t) => {
	const user = { email: 'user@esaml2.com' };
	const { id, context: SAMLResponse } = await idp.createLoginResponse(
		sp,
		sampleRequestInfo,
		BindingNamespace.Post,
		user,
		createTemplateCallback(idp, sp, user, sampleRequestInfo)
	);
	// receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
	const { samlContent, extract } = await sp.parseLoginResponse(idp, BindingNamespace.Post, { body: { SAMLResponse } });
	t.true(isString(id));
	t.is(samlContent.startsWith('<samlp:Response'), true);
	t.is(samlContent.endsWith('/samlp:Response>'), true);
	t.is(extract.nameID, 'user@esaml2.com');
	t.is(extract.response?.inResponseTo, 'request_id');
});

test('send login response with [custom template] and encrypted signed assertion and parse it', async (t) => {
	const user = { email: 'user@esaml2.com' };
	const { id, context: SAMLResponse } = await idpcustom.createLoginResponse(
		sp,
		{ extract: { request: { id: 'request_id' } } },
		BindingNamespace.Post,
		{ email: 'user@esaml2.com' },
		createTemplateCallback(idpcustom, sp, user)
	);
	// receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
	const { samlContent, extract } = await sp.parseLoginResponse(idpcustom, BindingNamespace.Post, {
		body: { SAMLResponse },
	});
	t.true(isString(id));
	t.is(samlContent.startsWith('<samlp:Response'), true);
	t.is(samlContent.endsWith('/samlp:Response>'), true);
	t.is(extract.nameID, 'user@esaml2.com');
	t.is(extract.attributes?.name, 'mynameinsp');
	t.is(extract.attributes?.mail, 'user@esaml2.com');
	t.is(extract.response?.inResponseTo, '_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});

test('send login response with encrypted signed assertion + signed message and parse it', async (t) => {
	const spWantMessageSign = serviceProvider({
		...defaultSpConfig,
		wantMessageSigned: true,
	});
	const user = { email: 'user@esaml2.com' };
	const { id, context: SAMLResponse } = await idp.createLoginResponse(
		spWantMessageSign,
		sampleRequestInfo,
		BindingNamespace.Post,
		user,
		createTemplateCallback(idp, spWantMessageSign, user, sampleRequestInfo)
	);
	// receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
	const { samlContent, extract } = await spWantMessageSign.parseLoginResponse(idp, BindingNamespace.Post, {
		body: { SAMLResponse },
	});

	t.true(isString(id));
	t.is(samlContent.startsWith('<samlp:Response'), true);
	t.is(samlContent.endsWith('/samlp:Response>'), true);
	t.is(extract.nameID, 'user@esaml2.com');
	t.is(extract.response?.inResponseTo, 'request_id');
});

test('send login response with [custom template] encrypted signed assertion + signed message and parse it', async (t) => {
	const spWantMessageSign = serviceProvider({
		...defaultSpConfig,
		wantMessageSigned: true,
	});
	// const requestInfo = { extract: { authnrequest: { id: 'request_id' } } };
	const user = { email: 'user@esaml2.com' };
	const { id, context: SAMLResponse } = await idpcustom.createLoginResponse(
		spWantMessageSign,
		{ extract: { request: { id: 'request_id' } } },
		BindingNamespace.Post,
		{ email: 'user@esaml2.com' },
		createTemplateCallback(idpcustom, spWantMessageSign, user)
	);
	// receiver (caution: only use metadata and public key when declare pair-up in oppoent entity)
	const { samlContent, extract } = await spWantMessageSign.parseLoginResponse(idpcustom, BindingNamespace.Post, {
		body: { SAMLResponse },
	});
	t.true(isString(id));
	t.is(samlContent.startsWith('<samlp:Response'), true);
	t.is(samlContent.endsWith('/samlp:Response>'), true);
	t.is(extract.nameID, 'user@esaml2.com');
	t.is(extract.attributes?.name, 'mynameinsp');
	t.is(extract.attributes?.mail, 'user@esaml2.com');
	t.is(extract.response?.inResponseTo, '_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4');
});

// simulate idp-init slo
test('idp sends a redirect logout request without signature and sp parses it', async (t) => {
	const { id, context } = idp.createLogoutRequest(sp, BindingNamespace.Redirect, { logoutNameID: 'user@esaml2.com' });
	const searchParams = new URL(context).searchParams;
	t.is(searchParams.has('SAMLRequest'), true);
	t.true(isString(id));
	t.true(isString(context));
	const originalURL = new URL(context);
	const SAMLRequest = encodeURIComponent(originalURL.searchParams.get('SAMLRequest') as string);
	let result: any;
	const { samlContent, extract } = (result = await sp.parseLogoutRequest(idp, BindingNamespace.Redirect, {
		query: { SAMLRequest },
	}));
	t.is(result.sigAlg, null);
	t.true(isString(samlContent));
	t.is(extract.nameID, 'user@esaml2.com');
	t.is(extract.signature, null);
	t.true(isString(extract.request?.id));
	t.is(extract.request?.destination, 'https://sp.example.org/sp/slo');
	t.is(extract.issuer, 'https://idp.example.com/metadata');
});

test('idp sends a redirect logout request with signature and sp parses it', async (t) => {
	const { id, context } = idp.createLogoutRequest(spWantLogoutReqSign, BindingNamespace.Redirect, {
		logoutNameID: 'user@esaml2.com',
	});
	const searchParams = new URL(context).searchParams;
	t.is(searchParams.has('SAMLRequest'), true);
	t.is(searchParams.has('SigAlg'), true);
	t.is(searchParams.has('Signature'), true);
	t.true(isString(id));
	t.true(isString(context));
	const originalURL = new URL(context);
	const SAMLRequest = originalURL.searchParams.get('SAMLRequest');
	const Signature = originalURL.searchParams.get('Signature');
	const SigAlg = originalURL.searchParams.get('SigAlg');
	originalURL.searchParams.delete('Signature');
	const octetString = Array.from(originalURL.searchParams)
		.map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
		.join('&');
	const { extract } = await spWantLogoutReqSign.parseLogoutRequest(idp, BindingNamespace.Redirect, {
		query: { SAMLRequest, Signature, SigAlg },
		octetString,
	});
	t.is(extract.nameID, 'user@esaml2.com');
	t.is(extract.issuer, 'https://idp.example.com/metadata');
	t.true(isString(extract.request?.id));
	t.is(extract.request?.destination, 'https://sp.example.org/sp/slo');
	t.is(extract.signature, null); // redirect binding doesn't embed the signature
});

test('idp sends a post logout request without signature and sp parses it', async (t) => {
	const result = idp.createLogoutRequest(sp, BindingNamespace.Post, {
		logoutNameID: 'user@esaml2.com',
	});
	t.is('entityEndpoint' in result, true);
	if (!('entityEndpoint' in result)) return;
	t.true(isString(result.id));
	t.true(isString(result.context));
	t.true(isString(result.entityEndpoint));
	t.is(result.type, 'SAMLRequest');
	const { extract } = await sp.parseLogoutRequest(idp, BindingNamespace.Post, {
		body: { SAMLRequest: result.context },
	});
	t.is(extract.nameID, 'user@esaml2.com');
	t.is(extract.issuer, 'https://idp.example.com/metadata');
	t.true(isString(extract.request?.id));
	t.is(extract.request?.destination, 'https://sp.example.org/sp/slo');
	t.is(extract.signature, null);
});

test('idp sends a post logout request with signature and sp parses it', async (t) => {
	const result = idp.createLogoutRequest(spWantLogoutReqSign, BindingNamespace.Post, {
		logoutNameID: 'user@esaml2.com',
	});
	t.is('entityEndpoint' in result, true);
	if (!('entityEndpoint' in result)) return;
	t.true(isString(result.id));
	t.true(isString(result.context));
	t.true(isString(result.entityEndpoint));
	t.is(result.type, 'SAMLRequest');
	const { extract } = await spWantLogoutReqSign.parseLogoutRequest(idp, BindingNamespace.Post, {
		body: { SAMLRequest: result.context },
	});
	t.is(extract.nameID, 'user@esaml2.com');
	t.is(extract.issuer, 'https://idp.example.com/metadata');
	t.is(extract.request?.destination, 'https://sp.example.org/sp/slo');
	t.true(isString(extract.request?.id));
	t.true(isString(extract.signature));
});

// simulate init-slo
test('sp sends a post logout response without signature and parse', async (t) => {
	const { context: SAMLResponse } = sp.createLogoutResponse(
		idp,
		null,
		BindingNamespace.Post,
		'',
		createTemplateCallback(idp, sp, {})
	);
	const { /*samlContent,*/ extract } = await idp.parseLogoutResponse(sp, BindingNamespace.Post, {
		body: { SAMLResponse },
	});
	t.is(extract.signature, null);
	t.is(extract.issuer, 'https://sp.example.org/metadata');
	t.true(isString(extract.response?.id));
	t.is(extract.response?.destination, 'https://idp.example.org/sso/SingleLogoutService');
});

test('sp sends a post logout response with signature and parse', async (t) => {
	const { /*relayState, type, entityEndpoint, id,*/ context: SAMLResponse } = sp.createLogoutResponse(
		idpWantLogoutResSign,
		sampleRequestInfo,
		BindingNamespace.Post,
		'',
		createTemplateCallback(idpWantLogoutResSign, sp, {})
	);
	const { /*samlContent,*/ extract } = await idpWantLogoutResSign.parseLogoutResponse(sp, BindingNamespace.Post, {
		body: { SAMLResponse },
	});
	t.true(isString(extract.signature));
	t.is(extract.issuer, 'https://sp.example.org/metadata');
	t.true(isString(extract.response?.id));
	t.is(extract.response?.destination, 'https://idp.example.org/sso/SingleLogoutService');
});

test('send login response with encrypted non-signed assertion with EncryptThenSign and parse it', async (t) => {
	const user = { email: 'user@esaml2.com' };
	const { id, context: SAMLResponse } = await idpEncryptThenSign.createLoginResponse(
		spNoAssertSignCustomConfig,
		sampleRequestInfo,
		BindingNamespace.Post,
		user,
		createTemplateCallback(idpEncryptThenSign, spNoAssertSignCustomConfig, user),
		true
	);
	const { samlContent, extract } = await spNoAssertSignCustomConfig.parseLoginResponse(
		idpEncryptThenSign,
		BindingNamespace.Post,
		{
			body: { SAMLResponse },
		}
	);
	t.true(isString(id));
	t.is(samlContent.startsWith('<samlp:Response'), true);
	t.is(samlContent.endsWith('/samlp:Response>'), true);
	t.is(extract.nameID, 'user@esaml2.com');
});

test('Customize prefix (saml2) for encrypted assertion tag', async (t) => {
	const user = { email: 'test@email.com' };
	const idpCustomizePfx = identityProvider(
		Object.assign(defaultIdpConfig, {
			tagPrefix: {
				encryptedAssertion: 'saml2',
			},
		})
	);
	const { /*id,*/ context: SAMLResponse } = await idpCustomizePfx.createLoginResponse(
		sp,
		sampleRequestInfo,
		BindingNamespace.Post,
		user,
		createTemplateCallback(idpCustomizePfx, sp, user)
	);
	t.is((base64Decode(SAMLResponse) as string).includes('saml2:EncryptedAssertion'), true);
	await sp.parseLoginResponse(idpCustomizePfx, BindingNamespace.Post, {
		body: { SAMLResponse },
	});
});

test('Customize prefix (default is saml) for encrypted assertion tag', async (t) => {
	const user = { email: 'test@email.com' };
	const { /*id,*/ context: SAMLResponse } = await idp.createLoginResponse(
		sp,
		sampleRequestInfo,
		BindingNamespace.Post,
		user,
		createTemplateCallback(idp, sp, user)
	);
	t.is((base64Decode(SAMLResponse) as string).includes('saml:EncryptedAssertion'), true);
	await sp.parseLoginResponse(idp, BindingNamespace.Post, { body: { SAMLResponse } });
});

test('avoid malformatted response', async (t) => {
	// sender (caution: only use metadata and public key when declare pair-up in oppoent entity)
	const user = { email: 'user@email.com' };
	const { context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(
		sp,
		sampleRequestInfo,
		BindingNamespace.Post,
		user,
		createTemplateCallback(idpNoEncrypt, sp, user)
	);
	const rawResponse = String(base64Decode(SAMLResponse, true));
	const attackResponse = `<NameID>evil@evil.com${rawResponse}</NameID>`;
	try {
		await sp.parseLoginResponse(idpNoEncrypt, BindingNamespace.Post, {
			body: { SAMLResponse: base64Encode(attackResponse) },
		});
	} catch (e) {
		// it must throw an error
		t.is(true, true);
	}
});

test('should reject signature wrapped response - case 1', async (t) => {
	//
	const user = { email: 'user@esaml2.com' };
	const { /*id,*/ context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(
		sp,
		sampleRequestInfo,
		BindingNamespace.Post,
		user,
		createTemplateCallback(idpNoEncrypt, sp, user)
	);
	//Decode
	const buffer = Buffer.from(SAMLResponse, 'base64');
	const xml = buffer.toString();
	//Create version of response without signature
	const stripped = xml.replace(/<ds:Signature[\s\S]*ds:Signature>/, '');
	//Create version of response with altered IDs and new username
	const outer = xml
		.replace(/assertion" ID="_[0-9a-f]{3}/g, 'assertion" ID="_000')
		.replace('user@esaml2.com', 'admin@esaml2.com');
	//Put stripped version under SubjectConfirmationData of modified version
	const xmlWrapped = outer.replace(
		/<saml:SubjectConfirmationData[^>]*\/>/,
		'<saml:SubjectConfirmationData>' +
			stripped.replace('<?xml version="1.0" encoding="UTF-8"?>', '') +
			'</saml:SubjectConfirmationData>'
	);
	const wrappedResponse = Buffer.from(xmlWrapped).toString('base64');
	try {
		await sp.parseLoginResponse(idpNoEncrypt, BindingNamespace.Post, { body: { SAMLResponse: wrappedResponse } });
	} catch (e) {
		t.is(isSamlifyError(e), true);
		t.is(e.code, SamlifyErrorCode.PotentialWrappingAttack);
	}
});

test('should reject signature wrapped response - case 2', async (t) => {
	//
	const user = { email: 'user@esaml2.com' };
	const { /*id,*/ context: SAMLResponse } = await idpNoEncrypt.createLoginResponse(
		sp,
		sampleRequestInfo,
		BindingNamespace.Post,
		user,
		createTemplateCallback(idpNoEncrypt, sp, user)
	);
	//Decode
	const buffer = Buffer.from(SAMLResponse, 'base64');
	const xml = buffer.toString();
	//Create version of response without signature
	const stripped = xml.replace(/<ds:Signature[\s\S]*ds:Signature>/, '');
	//Create version of response with altered IDs and new username
	const outer = xml
		.replace(/assertion" ID="_[0-9a-f]{3}/g, 'assertion" ID="_000')
		.replace('user@esaml2.com', 'admin@esaml2.com');
	//Put stripped version under SubjectConfirmationData of modified version
	const xmlWrapped = outer.replace(
		/<\/saml:Conditions>/,
		'</saml:Conditions><saml:Advice>' +
			stripped.replace('<?xml version="1.0" encoding="UTF-8"?>', '') +
			'</saml:Advice>'
	);
	const wrappedResponse = Buffer.from(xmlWrapped).toString('base64');
	try {
		await sp.parseLoginResponse(idpNoEncrypt, BindingNamespace.Post, {
			body: { SAMLResponse: wrappedResponse },
		});
	} catch (e) {
		t.is(isSamlifyError(e), true);
		t.is(e.code, SamlifyErrorCode.PotentialWrappingAttack);
	}
});

test('should throw two-tiers code error when the response does not return success status', async (t) => {
	try {
		await sp.parseLoginResponse(idpNoEncrypt, BindingNamespace.Post, {
			body: { SAMLResponse: base64Encode(failedResponse) },
		});
	} catch (e) {
		t.is(isSamlifyError(e), true);
		t.is(e.code, SamlifyErrorCode.FailedStatus);
		t.is(
			e.message,
			'with top tier code: urn:oasis:names:tc:SAML:2.0:status:Requester, second tier code: urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy'
		);
	}
});

test.serial('should throw SUBJECT_UNCONFIRMED for the expired SAML response without clock drift setup', async (t) => {
	const now = new Date();
	const fiveMinutesOneSecLater = new Date(now.getTime());
	fiveMinutesOneSecLater.setMinutes(fiveMinutesOneSecLater.getMinutes() + 5);
	fiveMinutesOneSecLater.setSeconds(fiveMinutesOneSecLater.getSeconds() + 1);

	const user = { email: 'user@esaml2.com' };

	try {
		const { context: SAMLResponse } = await idp.createLoginResponse(
			sp,
			sampleRequestInfo,
			BindingNamespace.Post,
			user,
			createTemplateCallback(idp, sp, user)
		);
		// simulate the time on client side when response arrives after 5.1 sec
		tk.freeze(fiveMinutesOneSecLater);
		await sp.parseLoginResponse(idp, BindingNamespace.Post, { body: { SAMLResponse } });
		// test failed, it shouldn't happen
		t.is(true, false);
	} catch (e) {
		t.is(isSamlifyError(e), true);
		t.is(e.code, SamlifyErrorCode.SubjectUnconfirmed);
	} finally {
		tk.reset();
	}
});

test.serial('should not throw SUBJECT_UNCONFIRMED for the expired SAML response with clock drift setup', async (t) => {
	const now = new Date();
	const fiveMinutesOneSecLater = new Date(now.getTime());
	fiveMinutesOneSecLater.setMinutes(fiveMinutesOneSecLater.getMinutes() + 5);
	fiveMinutesOneSecLater.setSeconds(fiveMinutesOneSecLater.getSeconds() + 1);
	const user = { email: 'user@esaml2.com' };

	try {
		const { context: SAMLResponse } = await idp.createLoginResponse(
			spWithClockDrift,
			sampleRequestInfo,
			BindingNamespace.Post,
			user,
			createTemplateCallback(idp, spWithClockDrift, user)
		);
		// simulate the time on client side when response arrives after 5.1 sec
		tk.freeze(fiveMinutesOneSecLater);
		await spWithClockDrift.parseLoginResponse(idp, BindingNamespace.Post, { body: { SAMLResponse } });
		t.is(true, true);
	} catch (e) {
		// test failed, it shouldn't happen
		t.is(e, false);
	} finally {
		tk.reset();
	}
});
