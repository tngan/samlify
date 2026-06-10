import * as esaml2 from '../index';
import { readFileSync } from 'fs';
import { test, expect, describe } from 'vitest';
import { randomUUID } from 'crypto';
import * as validator from '@authenio/samlify-xsd-schema-validator';

esaml2.setSchemaValidator(validator);

const {
  IdentityProvider: identityProvider,
  ServiceProvider: serviceProvider,
  SamlLib: libsaml,
  Utility: utility,
  Constants: ref,
} = esaml2;

const binding = ref.namespace.binding;

const defaultIdpConfig = {
  privateKey: readFileSync('./test/key/idp/privkey.pem'),
  privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
  isAssertionEncrypted: false,
  metadata: readFileSync('./test/misc/idpmeta.xml'),
};

const defaultSpConfig = {
  privateKey: readFileSync('./test/key/sp/privkey.pem'),
  privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
  isAssertionEncrypted: false,
  metadata: readFileSync('./test/misc/spmeta.xml'),
};

const loginResponseTemplate = {
  context: '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status><saml:Assertion ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}" InResponseTo="{InResponseTo}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{AttributeStatement}</saml:Assertion></samlp:Response>',
  attributes: [
    { name: 'mail', valueTag: 'user.email', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', valueXsiType: 'xs:string' },
    { name: 'role', valueTag: 'user.role', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', valueXsiType: 'xs:string' },
  ],
};

function createTemplateCallback(_idp: any, _sp: any, _binding: string, user: any) {
  return (template: string) => {
    const _id = '_' + randomUUID();
    const now = new Date();
    const fiveMinutesLater = new Date(now.getTime() + 300_000);
    const tvalue: Record<string, unknown> = {
      ID: _id,
      AssertionID: '_' + randomUUID(),
      Destination: _sp.entityMeta.getAssertionConsumerService(_binding),
      Audience: _sp.entityMeta.getEntityID(),
      SubjectRecipient: _sp.entityMeta.getEntityID(),
      NameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      NameID: user.email,
      Issuer: _idp.entityMeta.getEntityID(),
      IssueInstant: now.toISOString(),
      ConditionsNotBefore: now.toISOString(),
      ConditionsNotOnOrAfter: fiveMinutesLater.toISOString(),
      SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater.toISOString(),
      InResponseTo: '_request_id',
      StatusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',
      attrUserEmail: user.email,
      attrUserRole: user.role,
    };
    return { id: _id, context: libsaml.replaceTagsByValue(template, tvalue) };
  };
}

describe('Attribute injection prevention', () => {

  test('XML tags in attribute values are escaped and do not inject new attributes', async () => {
    const idp = identityProvider({ ...defaultIdpConfig, loginResponseTemplate });
    const sp = serviceProvider(defaultSpConfig);

    // Attempt to inject a new <saml:Attribute> via the role value
    const injection = [
      'user',
      '</saml:AttributeValue></saml:Attribute>',
      '<saml:Attribute Name="admin" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">',
      '<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">true</saml:AttributeValue>',
      '</saml:Attribute>',
      '<saml:Attribute Name="role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">',
      '<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">user',
    ].join('');

    const user = { email: 'attacker@example.com', role: injection };

    const { context: SAMLResponse } = await idp.createLoginResponse(
      sp,
      { extract: { request: { id: '_request_id' } } },
      'post',
      user,
      createTemplateCallback(idp, sp, 'post', user),
    );

    // Decode and verify the injection payload was escaped, not parsed as XML
    const xml: string = Buffer.from(SAMLResponse, 'base64').toString('utf-8');

    // The injected closing/opening tags should be escaped as entities
    expect(xml).toContain('&lt;/saml:AttributeValue&gt;');
    expect(xml).toContain('&lt;saml:Attribute');

    // There should be no raw (unescaped) injected <saml:Attribute Name="admin"> element
    // Only the two legitimate attributes (mail, role) should exist as actual XML elements
    const attrMatches = xml.match(/<saml:Attribute /g);
    expect(attrMatches).toHaveLength(2);

    // The SP should parse only the two legitimate attributes (mail, role)
    const { extract } = await sp.parseLoginResponse(idp, 'post', { body: { SAMLResponse } });
    expect(extract.attributes).not.toHaveProperty('admin');
    expect(extract.attributes.mail).toBe('attacker@example.com');
  });

  test('replaceTagsByValue escapes element text values containing XML special characters', () => {
    const template = '<element>{Value}</element>';
    const result = libsaml.replaceTagsByValue(template, { Value: '<script>alert("xss")</script>' });
    expect(result).toBe('<element>&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;</element>');
    expect(result).not.toContain('<script>');
  });

  test('replaceTagsByValue escapes attribute values containing XML special characters', () => {
    const template = '<element attr="{Value}">text</element>';
    const result = libsaml.replaceTagsByValue(template, { Value: '"><injected' });
    expect(result).toBe('<element attr="&quot;&gt;&lt;injected">text</element>');
  });

  test('replaceTagsByValue handles values with ampersands', () => {
    const template = '<element>{Value}</element>';
    const result = libsaml.replaceTagsByValue(template, { Value: 'a&b' });
    expect(result).toBe('<element>a&amp;b</element>');
  });

  test('replaceTagsByValue does not double-escape safe values', () => {
    const template = '<element>{Value}</element>';
    const result = libsaml.replaceTagsByValue(template, { Value: 'hello world' });
    expect(result).toBe('<element>hello world</element>');
  });

  test('normal attribute values pass through unchanged', async () => {
    const idp = identityProvider({ ...defaultIdpConfig, loginResponseTemplate });
    const sp = serviceProvider(defaultSpConfig);

    const user = { email: 'user@example.com', role: 'viewer' };

    const { context: SAMLResponse } = await idp.createLoginResponse(
      sp,
      { extract: { request: { id: '_request_id' } } },
      'post',
      user,
      createTemplateCallback(idp, sp, 'post', user),
    );

    const { extract } = await sp.parseLoginResponse(idp, 'post', { body: { SAMLResponse } });
    expect(extract.attributes.mail).toBe('user@example.com');
    expect(extract.attributes.role).toBe('viewer');
  });
});
