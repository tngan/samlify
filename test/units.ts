import { afterEach, beforeAll, describe, expect, test } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

import * as esaml2 from '../index';
import * as Types from '../src/types';
import * as Extractor from '../src/extractor';
import {
  zipObject,
  flattenDeep,
  last,
  uniq,
  get,
  isString,
  isNonEmptyArray,
  castArrayOpt,
  notEmpty,
  escapeXPathValue,
  camelCase,
  readPrivateKey,
} from '../src/utility';
import utility from '../src/utility';
import { verifyTime } from '../src/validator';
import { getContext, setSchemaValidator, setDOMParserOptions } from '../src/api';
import libsaml from '../src/libsaml';
import IdpMetadata from '../src/metadata-idp';
import SpMetadata from '../src/metadata-sp';

const { IdentityProvider: identityProvider, ServiceProvider: serviceProvider } = esaml2;

const idpMetaXml = fs.readFileSync('./test/misc/idpmeta.xml');
const spMetaXml = fs.readFileSync('./test/misc/spmeta.xml');

beforeAll(() => {
  // Ensure a validator is registered (the flow tests register one too,
  // but units that exercise libsaml.isValidXml depend on it).
  setSchemaValidator({
    validate: () => Promise.resolve('OK'),
  });
});

describe('Types module', () => {
  test('re-exports entity and metadata constructors', () => {
    expect(typeof Types.IdentityProviderConstructor).toBe('function');
    expect(typeof Types.IdentityProviderMetadata).toBe('function');
    expect(typeof Types.ServiceProviderConstructor).toBe('function');
    expect(typeof Types.ServiceProviderMetadata).toBe('function');
  });
});

describe('utility helpers', () => {
  test('zipObject — skipDuplicated overwrites collisions', () => {
    expect(zipObject(['a', 'b', 'a'], [1, 2, 3])).toEqual({ a: 3, b: 2 });
  });

  test('zipObject — when skipDuplicated is false, collisions aggregate to arrays', () => {
    expect(zipObject(['a', 'b', 'a'], [1, 2, 3], false)).toEqual({ a: [1, 3], b: 2 });
    expect(zipObject(['a', 'a', 'a'], [1, 2, 3], false)).toEqual({ a: [1, 2, 3] });
  });

  test('flattenDeep — recursive flatten', () => {
    expect(flattenDeep([1, [2, [3, [4]], 5]])).toEqual([1, 2, 3, 4, 5]);
    expect(flattenDeep('x' as unknown as string[])).toEqual(['x']);
  });

  test('last — return final element', () => {
    expect(last([1, 2, 3])).toBe(3);
    expect(last([])).toBeUndefined();
  });

  test('uniq — preserve order, drop duplicates', () => {
    expect(uniq(['a', 'b', 'a', 'c', 'b'])).toEqual(['a', 'b', 'c']);
  });

  test('get — resolve dotted path or fall back to default', () => {
    const obj = { a: { b: { c: 42 } }, x: 'top' };
    expect(get(obj, 'a.b.c')).toBe(42);
    expect(get(obj, 'x')).toBe('top');
    expect(get(obj, 'a.b.missing')).toBeNull();
    expect(get(obj, 'a.b.missing', 'fallback')).toBe('fallback');
    expect(get(null, 'a.b')).toBeNull();
  });

  test('isString — guard for primitive strings', () => {
    expect(isString('hi')).toBe(true);
    expect(isString(1)).toBe(false);
    expect(isString(null)).toBe(false);
    expect(isString(undefined)).toBe(false);
  });

  test('isNonEmptyArray — true only for non-empty arrays', () => {
    expect(isNonEmptyArray([1])).toBe(true);
    expect(isNonEmptyArray([])).toBe(false);
    expect(isNonEmptyArray('ab')).toBe(false);
    expect(isNonEmptyArray(undefined)).toBe(false);
  });

  test('castArrayOpt — wrap scalar, pass through array, undefined → []', () => {
    expect(castArrayOpt(undefined)).toEqual([]);
    expect(castArrayOpt('a')).toEqual(['a']);
    expect(castArrayOpt(['a', 'b'])).toEqual(['a', 'b']);
  });

  test('notEmpty — narrow null/undefined', () => {
    expect(notEmpty(0)).toBe(true);
    expect(notEmpty('')).toBe(true);
    expect(notEmpty(null)).toBe(false);
    expect(notEmpty(undefined)).toBe(false);
  });

  test('escapeXPathValue — quote handling for XPath injection safety', () => {
    expect(escapeXPathValue('plain')).toBe("'plain'");
    expect(escapeXPathValue("it's")).toContain('concat(');
    expect(escapeXPathValue("a'b'c")).toContain('concat(');
  });

  test('camelCase — handles separators and existing camel case', () => {
    expect(camelCase('hello world')).toBe('helloWorld');
    expect(camelCase('hello-world_again.now')).toBe('helloWorldAgainNow');
    expect(camelCase('XMLParser')).toBe('xmlParser');
    expect(camelCase('alreadyCamel')).toBe('alreadyCamel');
  });

  test('utility default — string helpers', () => {
    expect(utility.isString('s')).toBe(true);
    expect(utility.parseString('value')).toBe('value');
    expect(utility.parseString(undefined as unknown as string, 'default')).toBe('default');
  });

  test('utility default — encoding round-trips', () => {
    const encoded = utility.base64Encode('hello');
    expect(utility.base64Decode(encoded)).toBe('hello');
    expect(Buffer.isBuffer(utility.base64Decode(encoded, true))).toBe(true);

    const compressed = utility.deflateString('round-trip');
    expect(typeof utility.inflateString(utility.base64Encode(compressed))).toBe('string');
  });

  test('utility default — applyDefault merges right onto left', () => {
    expect(utility.applyDefault({ a: 1, b: 2 }, { b: 3, c: 4 })).toEqual({ a: 1, b: 3, c: 4 });
  });

  test('utility default — getFullURL composes from req fields', () => {
    const url = utility.getFullURL({
      protocol: 'https',
      get: () => 'example.com',
      originalUrl: '/path?x=1',
    });
    expect(url).toBe('https://example.com/path?x=1');
  });

  test('utility default — convertToString respects flag', () => {
    expect(utility.convertToString(Buffer.from('a'), true)).toBe('a');
    expect(Buffer.isBuffer(utility.convertToString(Buffer.from('a'), false))).toBe(true);
  });

  test('utility default — normalizeCerString / normalizePemString strip headers', () => {
    const cert = '-----BEGIN CERTIFICATE-----\nABCD\nEFGH\n-----END CERTIFICATE-----';
    expect(utility.normalizeCerString(cert)).toBe('ABCDEFGH');

    const key = '-----BEGIN RSA PRIVATE KEY-----\n1234\n-----END RSA PRIVATE KEY-----';
    expect(utility.normalizePemString(key)).toBe('1234');
  });

  test('readPrivateKey — passes through when no passphrase', () => {
    const buf = Buffer.from('not-really-a-key');
    expect(readPrivateKey(buf, undefined)).toBe(buf);
  });
});

describe('validator.verifyTime', () => {
  test('returns true and warns when both bounds are missing', () => {
    expect(verifyTime(undefined, undefined)).toBe(true);
  });

  test('honours notBefore-only and notOnOrAfter-only branches', () => {
    const past = new Date(Date.now() - 60_000).toISOString();
    const future = new Date(Date.now() + 60_000).toISOString();
    expect(verifyTime(past, undefined)).toBe(true);
    expect(verifyTime(future, undefined)).toBe(false);
    expect(verifyTime(undefined, future)).toBe(true);
    expect(verifyTime(undefined, past)).toBe(false);
  });

  test('applies clock-drift tolerance to both bounds', () => {
    const slightlyFuture = new Date(Date.now() + 2_000).toISOString();
    const slightlyPast = new Date(Date.now() - 2_000).toISOString();
    // Without drift, current time is outside both edges in different directions.
    expect(verifyTime(slightlyFuture, undefined)).toBe(false);
    expect(verifyTime(undefined, slightlyPast)).toBe(false);
    // With generous drift, both edges accept the current time.
    expect(verifyTime(slightlyFuture, undefined, [-5_000, 5_000])).toBe(true);
    expect(verifyTime(undefined, slightlyPast, [-5_000, 5_000])).toBe(true);
  });
});

describe('api configuration', () => {
  test('setSchemaValidator throws when validate is not a function', () => {
    expect(() => setSchemaValidator({ validate: undefined as unknown as () => Promise<unknown> }))
      .toThrow('validate must be a callback function having one argument as xml input');
  });

  test('setSchemaValidator stores the validator in the context', async () => {
    const marker = Symbol('marker');
    setSchemaValidator({ validate: () => Promise.resolve(marker) });
    const result = await getContext().validate!('<x/>');
    expect(result).toBe(marker);
  });

  test('setDOMParserOptions replaces the DOM parser used by the context', () => {
    const before = getContext().dom;
    setDOMParserOptions();
    const after = getContext().dom;
    expect(after).not.toBe(before);
  });
});

describe('libsaml — pure helpers', () => {
  test('getQueryParamByType maps URL params to canonical names', () => {
    expect(libsaml.getQueryParamByType('SAMLRequest')).toBe('SAMLRequest');
    expect(libsaml.getQueryParamByType('LogoutRequest')).toBe('SAMLRequest');
    expect(libsaml.getQueryParamByType('SAMLResponse')).toBe('SAMLResponse');
    expect(libsaml.getQueryParamByType('LogoutResponse')).toBe('SAMLResponse');
    expect(() => libsaml.getQueryParamByType('Bogus')).toThrow('ERR_UNDEFINED_QUERY_PARAMS');
  });

  test('createXPath supports string and attribute selectors', () => {
    expect(libsaml.createXPath('Issuer')).toContain("local-name(.)='Issuer'");
    expect(libsaml.createXPath('Issuer', true)).toContain('/text()');
    expect(libsaml.createXPath({ name: 'Response', attr: 'ID' })).toContain('/@ID');
  });

  test('replaceTagsByValue interpolates element text and escapes attributes', () => {
    const xml = libsaml.replaceTagsByValue(
      '<a id="{Id}">{Body}</a>',
      { Id: 'a&b', Body: '<x/>' },
    );
    // Attribute value escaped, element text not escaped.
    expect(xml).toBe('<a id="a&amp;b"><x/></a>');
  });

  test('replaceTagsByValue omits attributes whose value is null or undefined (#455, saml-core §3.4.1)', () => {
    // null/undefined in attribute position drop the whole attribute. When
    // the body of the element is also a placeholder that resolves to
    // null/undefined, the entire element is dropped (saml-core §3.7.1
    // covers the same rule for `<samlp:SessionIndex>`).
    const xml = libsaml.replaceTagsByValue(
      '<a id="{Id}">{Body}</a>',
      { Id: null, Body: undefined },
    );
    // Both the attribute and the body are absent → entire element drops.
    expect(xml).toBe('');
  });

  test('replaceTagsByValue keeps the element when only the attribute is absent', () => {
    const xml = libsaml.replaceTagsByValue(
      '<a id="{Id}">visible</a>',
      { Id: null },
    );
    expect(xml).toBe('<a>visible</a>');
  });

  test('replaceTagsByValue drops only the placeholder in mixed-text content', () => {
    const xml = libsaml.replaceTagsByValue(
      '<a>before-{Tag}-after</a>',
      { Tag: undefined },
    );
    expect(xml).toBe('<a>before--after</a>');
  });

  test('replaceTagsByValue keeps explicit empty-string attributes', () => {
    // Empty string is a legitimate value and should NOT trigger omission.
    const xml = libsaml.replaceTagsByValue(
      '<a id="{Id}"/>',
      { Id: '' },
    );
    expect(xml).toBe('<a id=""/>');
  });

  test('replaceTagsByValue omits only the attribute whose tag is missing', () => {
    const xml = libsaml.replaceTagsByValue(
      '<a foo="x" bar="{Y}" baz="z"/>',
      { Y: undefined },
    );
    expect(xml).toBe('<a foo="x" baz="z"/>');
  });

  test('attributeStatementBuilder renders attributes with defaults', () => {
    const xml = libsaml.attributeStatementBuilder([
      { name: 'mail', nameFormat: 'fmt', valueXsiType: 'xs:string', valueTag: 'user.email' },
    ]);
    expect(xml).toContain('Name="mail"');
    expect(xml).toContain('NameFormat="fmt"');
    expect(xml).toContain('xsi:type="xs:string"');
    expect(xml).toContain('{attrUserEmail}');
  });

  test('createKeySection emits the expected element tree', () => {
    const section = libsaml.createKeySection('signing', '-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----');
    expect(section).toHaveProperty('KeyDescriptor');
  });
});

describe('extractor — buildAbsoluteXPath / buildAttributeXPath via extract', () => {
  test('handles wildcard segments (`~Foo`) and multi-attribute extraction', () => {
    const xml = `<?xml version="1.0"?>
      <Root xmlns="urn:demo">
        <FooBar a="1" b="2"/>
      </Root>`;
    const result = Extractor.extract(xml, [{
      key: 'attrs',
      localPath: ['Root', '~Foo'],
      attributes: ['a', 'b'],
    }]);
    expect(result.attrs).toEqual({ a: '1', b: '2' });
  });

  test('multi-localPath union returns unique text nodes', () => {
    const xml = `<?xml version="1.0"?>
      <Root xmlns="urn:demo">
        <A><Issuer>foo</Issuer></A>
        <B><Issuer>bar</Issuer></B>
      </Root>`;
    const result = Extractor.extract(xml, [{
      key: 'issuer',
      localPath: [['Root', 'A', 'Issuer'], ['Root', 'B', 'Issuer']],
      attributes: [],
    }]);
    expect((result.issuer as string[]).sort()).toEqual(['bar', 'foo']);
  });

  test('context: true returns a single string when there is exactly one node', () => {
    const xml = `<Root><Sig>x</Sig></Root>`;
    const result = Extractor.extract(xml, [{
      key: 'sig',
      localPath: ['Root', 'Sig'],
      attributes: [],
      context: true,
    }]);
    expect(typeof result.sig).toBe('string');
    expect(result.sig as string).toContain('<Sig');
  });

  test('context: true returns null when no node matches', () => {
    const xml = `<Root/>`;
    const result = Extractor.extract(xml, [{
      key: 'sig',
      localPath: ['Root', 'Missing'],
      attributes: [],
      context: true,
    }]);
    expect(result.sig).toBeNull();
  });
});

describe('Entity helpers', () => {
  const baseIdpConfig = {
    privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
    privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
    metadata: idpMetaXml,
  };
  const baseSpConfig = {
    privateKey: fs.readFileSync('./test/key/sp/privkey.pem'),
    privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
    metadata: spMetaXml,
  };
  const idp = identityProvider(baseIdpConfig);
  const sp = serviceProvider(baseSpConfig);

  test('verifyFields — string equal and non-equal', () => {
    expect(idp.verifyFields('issuer-x', 'issuer-x')).toBe(true);
    expect(idp.verifyFields('issuer-x', 'issuer-y')).toBe(false);
  });

  test('verifyFields — array all-match and at-least-one-mismatch', () => {
    expect(idp.verifyFields(['a', 'a'], 'a')).toBe(true);
    expect(idp.verifyFields(['a', 'b'], 'a')).toBe(false);
  });

  test('verifyFields — empty input returns false', () => {
    expect(idp.verifyFields([] as string[], 'x')).toBe(false);
    expect(idp.verifyFields(undefined as unknown as string, 'x')).toBe(false);
  });

  test('createLogoutRequest throws on unknown binding', () => {
    expect(() => idp.createLogoutRequest(sp, 'artifact', { logoutNameID: 'a' })).toThrow('ERR_UNDEFINED_BINDING');
  });

  test('createLogoutResponse throws on unknown binding', () => {
    expect(() => idp.createLogoutResponse(sp, { extract: {} } as any, 'artifact')).toThrow('ERR_CREATE_LOGOUT_RESPONSE_UNDEFINED_BINDING');
  });

  test('exportMetadata writes the metadata XML to disk', () => {
    const out = path.join(os.tmpdir(), `samlify-meta-${Date.now()}.xml`);
    try {
      idp.exportMetadata(out);
      expect(fs.readFileSync(out, 'utf8')).toContain('EntityDescriptor');
    } finally {
      try { fs.unlinkSync(out); } catch { /* ignore */ }
    }
  });

  test('getEntitySetting returns the merged settings', () => {
    expect(idp.getEntitySetting()).toBeDefined();
    expect(typeof idp.getEntitySetting().requestSignatureAlgorithm).toBe('string');
  });
});

describe('IdentityProvider — loginResponseTemplate handling', () => {
  const baseConfig = {
    privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
    privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
    metadata: idpMetaXml,
  };

  test('honours custom additionalTemplates when supplied', () => {
    const idp = identityProvider({
      ...baseConfig,
      loginResponseTemplate: {
        context: '<Response>{AttributeStatement}</Response>',
        attributes: [
          { name: 'email', valueTag: 'user.email', nameFormat: 'fmt', valueXsiType: 'xs:string' },
        ],
        additionalTemplates: {
          attributeStatementTemplate: { context: '<AS>{Attributes}</AS>' },
          attributeTemplate: { context: '<A name="{Name}">{Value}</A>' },
        },
      } as any,
    });
    const ctx = (idp.entitySetting.loginResponseTemplate as { context: string }).context;
    expect(ctx).toContain('<AS>');
    expect(ctx).toContain('<A name="email"');
  });

  test('warns and skips template expansion when context/attributes are missing', () => {
    const warn = console.warn;
    const messages: string[] = [];
    console.warn = (msg: string) => { messages.push(msg); };
    try {
      identityProvider({
        ...baseConfig,
        // Invalid: context is not a string and attributes is missing.
        loginResponseTemplate: { context: 123, attributes: undefined } as any,
      });
    } finally {
      console.warn = warn;
    }
    expect(messages.some(m => m.includes('Invalid login response template'))).toBe(true);
  });
});

describe('flow — checkStatus and dispatch errors', () => {
  test('flow rejects with ERR_UNEXPECTED_FLOW when binding is unknown', async () => {
    const { flow } = await import('../src/flow');
    await expect(flow({
      binding: 'artifact',
      parserType: 'SAMLRequest',
      type: 'login',
      request: { query: {}, body: {} },
      self: {} as any,
      from: {} as any,
    })).rejects.toThrow('ERR_UNEXPECTED_FLOW');
  });

  test('flow rejects with an Error instance, not a raw string (#581)', async () => {
    const { flow } = await import('../src/flow');
    const err = await flow({
      binding: 'artifact',
      parserType: 'SAMLRequest',
      type: 'login',
      request: { query: {}, body: {} },
      self: {} as any,
      from: {} as any,
    }).catch(e => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toBe('ERR_UNEXPECTED_FLOW');
  });
});

describe('Binding logout flows', () => {
  const idp = identityProvider({
    privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
    privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
    metadata: idpMetaXml,
  });
  const sp = serviceProvider({
    privateKey: fs.readFileSync('./test/key/sp/privkey.pem'),
    privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
    metadata: spMetaXml,
  });

  test('createLogoutRequest — redirect binding produces a redirect URL', () => {
    const result = idp.createLogoutRequest(sp, 'redirect', { logoutNameID: 'user@example.com' });
    expect(result.id).toMatch(/^_/);
    expect(result.context).toContain('SAMLRequest=');
  });

  test('createLogoutRequest — post binding produces a base64 envelope', () => {
    const result = idp.createLogoutRequest(sp, 'post', { logoutNameID: 'user@example.com' });
    expect(result.id).toMatch(/^_/);
    expect((result as { type?: string }).type).toBe('SAMLRequest');
  });

  test('createLogoutResponse — redirect binding produces a redirect URL', () => {
    const requestInfo = { extract: { request: { id: '_abc' } } } as any;
    const result = idp.createLogoutResponse(sp, requestInfo, 'redirect', 'state');
    expect(result.context).toContain('SAMLResponse=');
  });

  test('createLogoutResponse — post binding produces a base64 envelope', () => {
    const requestInfo = { extract: { request: { id: '_abc' } } } as any;
    const result = idp.createLogoutResponse(sp, requestInfo, 'post', 'state');
    expect((result as { type?: string }).type).toBe('SAMLResponse');
  });

  test('createLogoutRequest — redirect with a custom logoutRequestTemplate', () => {
    const idpCustom = identityProvider({
      privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
      privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
      metadata: idpMetaXml,
      logoutRequestTemplate: { context: '<LogoutRequest>{NameID}</LogoutRequest>' },
    });
    // Redirect callback receives the template object and must return a string context.
    const cb = (template: { context: string } | string) => {
      const ctx = typeof template === 'string' ? template : template.context;
      return { id: '_custom-logout', context: ctx };
    };
    const result = idpCustom.createLogoutRequest(sp, 'redirect', { logoutNameID: 'u@x' }, '', cb as any);
    expect(result.id).toBe('_custom-logout');
  });

  test('createLogoutRequest — post with a custom logoutRequestTemplate', () => {
    const idpCustom = identityProvider({
      privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
      privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
      metadata: idpMetaXml,
      logoutRequestTemplate: { context: '<LogoutRequest>{NameID}</LogoutRequest>' },
    });
    const cb = (template: string) => ({ id: '_custom-logout-post', context: template });
    const result = idpCustom.createLogoutRequest(sp, 'post', { logoutNameID: 'u@x' }, '', cb as any);
    expect(result.id).toBe('_custom-logout-post');
  });

  test('createLogoutResponse — post with a custom logoutResponseTemplate', () => {
    const idpCustom = identityProvider({
      privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
      privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
      metadata: idpMetaXml,
      logoutResponseTemplate: { context: '<LogoutResponse/>' },
    });
    const cb = (template: string) => ({ id: '_custom-resp', context: template });
    const result = idpCustom.createLogoutResponse(sp, { extract: { request: { id: '_a' } } } as any, 'post', '', cb as any);
    expect(result.id).toBe('_custom-resp');
  });

  test('createLogoutRequest — simpleSign binding produces a base64 envelope (#584)', () => {
    const result = idp.createLogoutRequest(sp, 'simpleSign', { logoutNameID: 'user@example.com' });
    expect(result.id).toMatch(/^_/);
    expect((result as { type?: string }).type).toBe('SAMLRequest');
    expect((result as { context: string }).context.length).toBeGreaterThan(0);
  });

  test('createLogoutRequest — simpleSign binding includes signature when target wants signed logout requests', () => {
    const idpSigned = identityProvider({
      privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
      privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
      metadata: idpMetaXml,
    });
    const spWantSigned = serviceProvider({
      privateKey: fs.readFileSync('./test/key/sp/privkey.pem'),
      privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
      metadata: spMetaXml,
      wantLogoutRequestSigned: true,
    });
    const result = idpSigned.createLogoutRequest(spWantSigned, 'simpleSign', { logoutNameID: 'user@example.com' }, 'state');
    expect((result as { signature?: unknown }).signature).toBeDefined();
    expect((result as { sigAlg?: string }).sigAlg).toContain('xmldsig');
  });

  test('createLogoutResponse — simpleSign binding produces a base64 envelope (#584)', () => {
    const requestInfo = { extract: { request: { id: '_abc' } } } as any;
    const result = idp.createLogoutResponse(sp, requestInfo, 'simpleSign', 'state');
    expect((result as { type?: string }).type).toBe('SAMLResponse');
  });

  test('createLogoutRequest — simpleSign with a custom logoutRequestTemplate', () => {
    const idpCustom = identityProvider({
      privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
      privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
      metadata: idpMetaXml,
      logoutRequestTemplate: { context: '<LogoutRequest>{NameID}</LogoutRequest>' },
    });
    const cb = (template: string) => ({ id: '_custom-ss-logout', context: template });
    const result = idpCustom.createLogoutRequest(sp, 'simpleSign', { logoutNameID: 'u@x' }, '', cb as any);
    expect(result.id).toBe('_custom-ss-logout');
  });

  test('createLogoutResponse — simpleSign with a custom logoutResponseTemplate', () => {
    const idpCustom = identityProvider({
      privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
      privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
      metadata: idpMetaXml,
      logoutResponseTemplate: { context: '<LogoutResponse/>' },
    });
    const cb = (template: string) => ({ id: '_custom-ss-resp', context: template });
    const result = idpCustom.createLogoutResponse(sp, { extract: { request: { id: '_a' } } } as any, 'simpleSign', '', cb as any);
    expect(result.id).toBe('_custom-ss-resp');
  });

  test('createLogoutResponse — simpleSign signs when target wants signed logout responses', () => {
    const idpSigned = identityProvider({
      privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
      privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
      metadata: idpMetaXml,
    });
    const spWantSigned = serviceProvider({
      privateKey: fs.readFileSync('./test/key/sp/privkey.pem'),
      privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
      metadata: spMetaXml,
      wantLogoutResponseSigned: true,
    });
    const requestInfo = { extract: { request: { id: '_abc' } } } as any;
    const result = idpSigned.createLogoutResponse(spWantSigned, requestInfo, 'simpleSign', 'state');
    expect((result as { signature?: unknown }).signature).toBeDefined();
  });

  test('createLogoutResponse — redirect with a custom logoutResponseTemplate', () => {
    const idpCustom = identityProvider({
      privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
      privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
      metadata: idpMetaXml,
      logoutResponseTemplate: { context: '<LogoutResponse/>' },
    });
    const cb = (template: { context: string } | string) => {
      const ctx = typeof template === 'string' ? template : template.context;
      return { id: '_custom-resp-r', context: ctx };
    };
    const result = idpCustom.createLogoutResponse(sp, { extract: { request: { id: '_a' } } } as any, 'redirect', '', cb as any);
    expect(result.context).toContain('SAMLResponse=');
  });
});

describe('Binding edge cases — falsy fallback branches', () => {
  const idpNosign = identityProvider({
    privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
    privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
    metadata: fs.readFileSync('./test/misc/idpmeta_nosign.xml'),
  });
  const spNosign = serviceProvider({
    entityID: 'https://sp-no-sign.example.org/metadata',
    authnRequestsSigned: false,
    wantAssertionsSigned: false,
    nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
    assertionConsumerService: [{
      Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      Location: 'https://sp-no-sign.example.org/acs',
    }],
  });

  test('SP createLoginRequest (post) against an IdP that does not require signed AuthnRequests', () => {
    const result = spNosign.createLoginRequest(idpNosign, 'post');
    expect((result as any).type).toBe('SAMLRequest');
  });

  test('SimpleSign login request omits signature when WantAuthnRequestsSigned is false', () => {
    const result = spNosign.createLoginRequest(idpNosign, 'simpleSign');
    expect((result as { signature?: unknown }).signature).toBeUndefined();
  });

  test('SimpleSign login response handles user without email and absent SessionNotOnOrAfter', async () => {
    const idp = identityProvider({
      privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
      privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
      metadata: idpMetaXml,
    });
    const sp = serviceProvider({
      privateKey: fs.readFileSync('./test/key/sp/privkey.pem'),
      privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
      metadata: spMetaXml,
    });
    const result = await idp.createLoginResponse(
      sp,
      { extract: { request: { id: '_x' } } } as any,
      'simpleSign',
      {} /* no email */,
    );
    expect((result as any).context).toBeDefined();
  });
});

describe('Entity construction edge cases', () => {
  test('ServiceProvider createLoginRequest throws on unknown binding', () => {
    const sp = serviceProvider({
      privateKey: fs.readFileSync('./test/key/sp/privkey.pem'),
      privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
      metadata: spMetaXml,
    });
    const idp = identityProvider({
      privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
      privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
      metadata: idpMetaXml,
    });
    expect(() => sp.createLoginRequest(idp, 'artifact')).toThrow('ERR_SP_LOGIN_REQUEST_UNDEFINED_BINDING');
  });

});

describe('libsaml — encrypt/decrypt error paths', () => {
  const idp = identityProvider({
    privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
    privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
    metadata: idpMetaXml,
  });
  const sp = serviceProvider({
    privateKey: fs.readFileSync('./test/key/sp/privkey.pem'),
    privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
    metadata: spMetaXml,
  });

  test('encryptAssertion rejects when xml is undefined', async () => {
    await expect(libsaml.encryptAssertion(idp as any, sp as any, undefined as any)).rejects.toThrow('ERR_UNDEFINED_ASSERTION');
  });

  test('encryptAssertion throws when no Assertion node is present', async () => {
    await expect(libsaml.encryptAssertion(idp as any, sp as any, '<Response/>')).rejects.toThrow('ERR_NO_ASSERTION');
  });

  test('encryptAssertion throws when multiple Assertion nodes are present', async () => {
    const xml = '<Response xmlns="urn:t"><Assertion>1</Assertion><Assertion>2</Assertion></Response>';
    await expect(libsaml.encryptAssertion(idp as any, sp as any, xml)).rejects.toThrow('ERR_MULTIPLE_ASSERTION');
  });

  test('encryptAssertion passes through when isAssertionEncrypted is false', async () => {
    const xml = '<Response xmlns="urn:t"><Assertion>x</Assertion></Response>';
    const idpPlain = identityProvider({
      privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
      privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
      metadata: idpMetaXml,
      isAssertionEncrypted: false,
    });
    const result = await libsaml.encryptAssertion(idpPlain as any, sp as any, xml);
    expect(typeof result).toBe('string');
  });

  test('decryptAssertion rejects when entireXML is empty', async () => {
    await expect(libsaml.decryptAssertion(sp as any, '' as any)).rejects.toThrow('ERR_UNDEFINED_ASSERTION');
  });

  test('decryptAssertion throws when no EncryptedAssertion is present', async () => {
    await expect(libsaml.decryptAssertion(sp as any, '<Response/>')).rejects.toThrow('ERR_UNDEFINED_ENCRYPTED_ASSERTION');
  });

  test('isValidXml rejects when no validator is registered', async () => {
    const before = getContext().validate;
    getContext().validate = undefined;
    try {
      await expect(libsaml.isValidXml('<x/>')).rejects.toThrow('no validation function found');
    } finally {
      getContext().validate = before;
    }
  });
});

describe('Metadata builders from options', () => {
  test('IdP metadata from options — exercises nameIDFormat/sso/slo branches', () => {
    const meta = IdpMetadata({
      entityID: 'https://example.org/idp',
      signingCert: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----',
      encryptCert: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----',
      wantAuthnRequestsSigned: true,
      nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
      singleSignOnService: [
        { isDefault: true, Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', Location: 'https://example.org/sso' },
      ],
      singleLogoutService: [
        { isDefault: true, Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', Location: 'https://example.org/slo' },
      ],
    });
    expect(meta.getMetadata()).toContain('EntityDescriptor');
    expect(meta.isWantAuthnRequestsSigned()).toBe(true);
  });

  test('IdP metadata from options — throws when SSO endpoint is missing', () => {
    expect(() => IdpMetadata({
      entityID: 'https://example.org/idp',
      // No singleSignOnService — should throw.
    })).toThrow('ERR_IDP_METADATA_MISSING_SINGLE_SIGN_ON_SERVICE');
  });

  test('SP metadata from options — exercises ACS/SLO/key descriptor branches', () => {
    const meta = SpMetadata({
      entityID: 'https://example.org/sp',
      authnRequestsSigned: true,
      wantAssertionsSigned: true,
      wantMessageSigned: true,
      signingCert: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----',
      encryptCert: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----',
      nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
      singleLogoutService: [
        { isDefault: true, Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', Location: 'https://example.org/slo' },
      ],
      assertionConsumerService: [
        { isDefault: true, Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', Location: 'https://example.org/acs' },
        { Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', Location: 'https://example.org/acs2' },
      ],
    });
    expect(meta.getMetadata()).toContain('EntityDescriptor');
    expect(meta.isAuthnRequestSigned()).toBe(true);
    expect(meta.isWantAssertionsSigned()).toBe(true);
  });

  test('SP metadata from options — defaults to emailAddress NameIDFormat when none provided', () => {
    const meta = SpMetadata({
      entityID: 'https://example.org/sp',
      assertionConsumerService: [
        { Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', Location: 'https://example.org/acs' },
      ],
    });
    expect(meta.getMetadata()).toContain('emailAddress');
  });

  test('SP metadata from options — does not warn when wantMessageSigned without signatureConfig (#454)', () => {
    const warn = console.warn;
    const messages: string[] = [];
    console.warn = (msg: string) => { messages.push(msg); };
    try {
      SpMetadata({
        entityID: 'https://example.org/sp',
        wantMessageSigned: true,
        assertionConsumerService: [
          { Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', Location: 'https://example.org/acs' },
        ],
      });
    } finally {
      console.warn = warn;
    }
    expect(messages.some(m => m.includes('missing signatureConfig'))).toBe(false);
  });
});

describe('IdP metadata elementsOrder (#429, saml-metadata §2.4.3)', () => {
  // saml-metadata §2.4.3 — `<IDPSSODescriptor>` declares a fixed sequence
  // for its child elements; some interop profiles (Shibboleth, OneLogin)
  // require non-default orderings. The IdP factory now mirrors the SP
  // factory's `elementsOrder` option so callers can pick a sequence
  // without having to hand-write metadata XML.
  const baseIdpOptions = {
    entityID: 'https://example.org/idp',
    signingCert: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----',
    encryptCert: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----',
    wantAuthnRequestsSigned: true,
    nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],
    singleSignOnService: [
      { Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', Location: 'https://example.org/sso' },
    ],
    singleLogoutService: [
      { Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', Location: 'https://example.org/slo' },
    ],
  };

  // Indices of each top-level child element in the rendered XML. We assert
  // on relative ordering rather than exact byte output to keep the tests
  // resilient to certificate / formatting changes elsewhere.
  const indexOf = (xmlStr: string, tag: string) => xmlStr.indexOf(`<${tag}`);

  test('default order matches the historical IdP emission sequence', () => {
    const xmlStr = IdpMetadata(baseIdpOptions).getMetadata();
    // KeyDescriptor → NameIDFormat → SingleSignOnService → SingleLogoutService
    expect(indexOf(xmlStr, 'KeyDescriptor')).toBeGreaterThan(-1);
    expect(indexOf(xmlStr, 'KeyDescriptor')).toBeLessThan(indexOf(xmlStr, 'NameIDFormat'));
    expect(indexOf(xmlStr, 'NameIDFormat')).toBeLessThan(indexOf(xmlStr, 'SingleSignOnService'));
    expect(indexOf(xmlStr, 'SingleSignOnService')).toBeLessThan(indexOf(xmlStr, 'SingleLogoutService'));
  });

  test('default IdP metadata XML is byte-identical when elementsOrder is omitted (regression pin)', () => {
    // Regression pin: callers that don't supply `elementsOrder` MUST receive
    // exactly the same metadata XML as before #429 was implemented.
    const opts = {
      ...baseIdpOptions,
      // Strip certs so the expected string stays manageable.
      signingCert: undefined,
      encryptCert: undefined,
    };
    const xmlStr = IdpMetadata(opts).getMetadata();
    expect(xmlStr).toBe(
      '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"' +
      ' xmlns:assertion="urn:oasis:names:tc:SAML:2.0:assertion"' +
      ' xmlns:ds="http://www.w3.org/2000/09/xmldsig#"' +
      ' entityID="https://example.org/idp">' +
      '<IDPSSODescriptor WantAuthnRequestsSigned="true"' +
      ' protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">' +
      '<NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>' +
      '<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"' +
      ' Location="https://example.org/sso"></SingleSignOnService>' +
      '<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"' +
      ' Location="https://example.org/slo"></SingleLogoutService>' +
      '</IDPSSODescriptor></EntityDescriptor>'
    );
  });

  test('custom elementsOrder is honoured — SingleSignOnService can precede KeyDescriptor', () => {
    const xmlStr = IdpMetadata({
      ...baseIdpOptions,
      elementsOrder: ['SingleSignOnService', 'KeyDescriptor', 'NameIDFormat', 'SingleLogoutService'],
    }).getMetadata();
    // `<SingleSignOnService>` now appears before `<KeyDescriptor>`.
    expect(indexOf(xmlStr, 'SingleSignOnService')).toBeGreaterThan(-1);
    expect(indexOf(xmlStr, 'KeyDescriptor')).toBeGreaterThan(-1);
    expect(indexOf(xmlStr, 'SingleSignOnService')).toBeLessThan(indexOf(xmlStr, 'KeyDescriptor'));
    // The remaining tail order from the supplied array is also preserved.
    expect(indexOf(xmlStr, 'KeyDescriptor')).toBeLessThan(indexOf(xmlStr, 'NameIDFormat'));
    expect(indexOf(xmlStr, 'NameIDFormat')).toBeLessThan(indexOf(xmlStr, 'SingleLogoutService'));
  });

  test('elementsOrder filters elements that are not populated', () => {
    // NameIDFormat omitted from options — even if it appears in the order
    // array, no `<NameIDFormat>` should be emitted.
    const xmlStr = IdpMetadata({
      ...baseIdpOptions,
      nameIDFormat: undefined as unknown as string[],
      elementsOrder: ['KeyDescriptor', 'NameIDFormat', 'SingleSignOnService', 'SingleLogoutService'],
    }).getMetadata();
    expect(xmlStr).not.toContain('<NameIDFormat');
    expect(xmlStr).toContain('<SingleSignOnService');
    expect(xmlStr).toContain('<SingleLogoutService');
  });

  test('Constants.elementsOrder.idp exposes default/onelogin/shibboleth profiles', () => {
    // The pre-baked profiles ride on the same `elementsOrder` constant the
    // SP side already exports, namespaced under `idp` to avoid colliding
    // with the existing SP-side keys.
    const idp = (esaml2.Constants as unknown as {
      elementsOrder: { idp: { default: string[]; onelogin: string[]; shibboleth: string[] } };
    }).elementsOrder.idp;
    expect(idp.default).toEqual(['KeyDescriptor', 'NameIDFormat', 'SingleSignOnService', 'SingleLogoutService']);
    expect(idp.onelogin).toContain('SingleSignOnService');
    expect(idp.shibboleth).toContain('SingleLogoutService');
  });
});

describe('SP metadata default signatureConfig (#454)', () => {
  // saml-bindings §3.5 — when an SP declares `wantMessageSigned: true` without
  // a `signatureConfig`, the SP should fall back to the same signature placement
  // the binding builders already use internally (Issuer-after, ds prefix). The
  // previous warning made working configurations appear broken; this suite pins
  // the new behaviour: silent default, populated entitySetting, caller value
  // preserved.
  const acs = [
    { Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', Location: 'https://example.org/acs' },
  ];

  const expectedDefault = {
    prefix: 'ds',
    location: {
      reference: "/*[local-name(.)='Response']/*[local-name(.)='Issuer']",
      action: 'after',
    },
  };

  test('does not emit a warning when wantMessageSigned is set without signatureConfig', () => {
    const warn = console.warn;
    const messages: string[] = [];
    console.warn = (msg: string) => { messages.push(msg); };
    try {
      serviceProvider({
        entityID: 'https://example.org/sp',
        wantMessageSigned: true,
        assertionConsumerService: acs,
      });
    } finally {
      console.warn = warn;
    }
    expect(messages.some(m => m.includes('missing signatureConfig'))).toBe(false);
    expect(messages.length).toBe(0);
  });

  test('populates entitySetting.signatureConfig with the binding default (saml-bindings §3.5)', () => {
    const sp = serviceProvider({
      entityID: 'https://example.org/sp',
      wantMessageSigned: true,
      assertionConsumerService: acs,
    });
    expect(sp.getEntitySetting().signatureConfig).toEqual(expectedDefault);
  });

  test('preserves caller-supplied signatureConfig instead of overwriting it', () => {
    const callerConfig = {
      prefix: 'foo',
      location: { reference: '/x', action: 'before' as const },
    };
    const sp = serviceProvider({
      entityID: 'https://example.org/sp',
      wantMessageSigned: true,
      signatureConfig: callerConfig,
      assertionConsumerService: acs,
    });
    expect(sp.getEntitySetting().signatureConfig).toEqual(callerConfig);
  });
});

describe('Metadata helpers', () => {
  const idpMeta = IdpMetadata(idpMetaXml);
  const spMeta = SpMetadata(spMetaXml);

  test('getX509Certificate returns null for an unknown use', () => {
    expect(idpMeta.getX509Certificate('not-a-real-use')).toBeNull();
  });

  test('getSingleLogoutService — string binding miss falls back to raw value', () => {
    // Asking for a binding that isn't declared resolves to the raw service map.
    const raw = idpMeta.getSingleLogoutService('artifact');
    // Raw value is whatever the metadata declared — accept undefined or an object/array.
    expect(['object', 'undefined']).toContain(typeof raw);
  });

  test('getSingleLogoutService — without binding returns the raw service entry', () => {
    expect(idpMeta.getSingleLogoutService(undefined)).not.toBeNull();
  });

  test('getSupportBindings — returns empty list for falsy input', () => {
    expect(spMeta.getSupportBindings(undefined as unknown as string[])).toEqual([]);
  });

  test('getSupportBindings — extracts the first key of each service entry', () => {
    const result = spMeta.getSupportBindings([
      { post: 'http://example.com/post' } as unknown as string,
      { redirect: 'http://example.com/redirect' } as unknown as string,
    ]);
    expect(result).toEqual(['post', 'redirect']);
  });
});

describe('Security audit (2026-04)', () => {
  // saml-sec-consider §6.3.1 — the DOM parser must reject DOCTYPE / entity
  // declarations to defend against XXE.
  test('setDOMParserOptions: caller-supplied options preserve XXE protection', () => {
    setDOMParserOptions({ /* deliberately empty — caller did not opt out */ });
    const dom = getContext().dom;
    // Restore default parser for subsequent tests in the file.
    setDOMParserOptions();
    // Attempt to parse a DOCTYPE-laden document; the safe error handler
    // throws on the entity declaration.
    expect(() => dom.parseFromString(`<!DOCTYPE r [<!ENTITY xxe "secret">]><r>&xxe;</r>`)).toThrow();
  });

  // saml-sec-consider §6.5 / xmldsig-core §6.4 — verifying with an
  // attacker-supplied unknown SigAlg must not silently downgrade to SHA-1.
  test('libsaml.verifyMessageSignature rejects unknown signature algorithms', () => {
    const fakeMetadata = {
      getX509Certificate: () => 'irrelevant',
    } as any;
    expect(() =>
      libsaml.verifyMessageSignature(
        fakeMetadata,
        'octets',
        Buffer.from('signature'),
        'http://attacker.example.com/madeup-alg',
      ),
    ).toThrow('ERR_UNSUPPORTED_SIGNATURE_ALGORITHM');
  });

  test('libsaml.constructMessageSignature rejects unknown signature algorithms', () => {
    expect(() =>
      libsaml.constructMessageSignature(
        'octets',
        '-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----',
        undefined,
        true,
        'http://attacker.example.com/madeup-alg',
      ),
    ).toThrow('ERR_UNSUPPORTED_SIGNATURE_ALGORITHM');
  });
});

describe('LogoutRequest SessionIndex (#470, saml-core §3.7.1)', () => {
  // saml-core §3.7.1 — `<samlp:SessionIndex>` is `minOccurs="0"`, so it
  // must appear when the SP knows the session index, and must be absent
  // otherwise. Previously the bindings either dropped the field entirely
  // or omitted it from the template.

  test('default LogoutRequest template includes SessionIndex when supplied', () => {
    const xml = libsaml.replaceTagsByValue(libsaml.defaultLogoutRequestTemplate.context, {
      ID: '_x',
      Destination: 'https://idp/slo',
      Issuer: 'https://sp/meta',
      IssueInstant: '2026-05-01T00:00:00Z',
      NameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      NameID: 'user@example.com',
      SessionIndex: '_session-abc',
    });
    expect(xml).toContain('<samlp:SessionIndex>_session-abc</samlp:SessionIndex>');
  });

  test('default LogoutRequest template drops SessionIndex when not supplied', () => {
    const xml = libsaml.replaceTagsByValue(libsaml.defaultLogoutRequestTemplate.context, {
      ID: '_x',
      Destination: 'https://idp/slo',
      Issuer: 'https://sp/meta',
      IssueInstant: '2026-05-01T00:00:00Z',
      NameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      NameID: 'user@example.com',
      SessionIndex: undefined,
    });
    expect(xml).not.toContain('SessionIndex');
    expect(xml).not.toContain('<samlp:SessionIndex');
  });

  test('createLogoutRequest (post): user.sessionIndex surfaces in the rendered XML', () => {
    const idp = identityProvider({
      privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
      privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
      metadata: idpMetaXml,
    });
    const sp = serviceProvider({
      privateKey: fs.readFileSync('./test/key/sp/privkey.pem'),
      privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
      metadata: spMetaXml,
    });
    const result = idp.createLogoutRequest(sp, 'post', {
      logoutNameID: 'u@x',
      sessionIndex: '_session-post-1',
    });
    const decoded = Buffer.from(result.context, 'base64').toString('utf8');
    expect(decoded).toContain('<samlp:SessionIndex>_session-post-1</samlp:SessionIndex>');
  });

  test('createLogoutRequest (redirect): user.sessionIndex surfaces in the rendered XML', () => {
    const idp = identityProvider({
      privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
      privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
      metadata: idpMetaXml,
    });
    const sp = serviceProvider({
      privateKey: fs.readFileSync('./test/key/sp/privkey.pem'),
      privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
      metadata: spMetaXml,
    });
    const result = idp.createLogoutRequest(sp, 'redirect', {
      logoutNameID: 'u@x',
      sessionIndex: '_session-redirect-1',
    });
    const url = new URL(result.context, 'http://example.test');
    const inflated = require('zlib').inflateRawSync(
      Buffer.from(decodeURIComponent(url.searchParams.get('SAMLRequest')!), 'base64'),
    ).toString('utf8');
    expect(inflated).toContain('<samlp:SessionIndex>_session-redirect-1</samlp:SessionIndex>');
  });

  test('createLogoutRequest (simpleSign): user.sessionIndex surfaces in the rendered XML', () => {
    const idp = identityProvider({
      privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
      privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
      metadata: idpMetaXml,
    });
    const sp = serviceProvider({
      privateKey: fs.readFileSync('./test/key/sp/privkey.pem'),
      privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
      metadata: spMetaXml,
    });
    const result = idp.createLogoutRequest(sp, 'simpleSign', {
      logoutNameID: 'u@x',
      sessionIndex: '_session-ss-1',
    });
    const decoded = Buffer.from(result.context, 'base64').toString('utf8');
    expect(decoded).toContain('<samlp:SessionIndex>_session-ss-1</samlp:SessionIndex>');
  });

  test('createLogoutRequest (post): no SessionIndex element when sessionIndex is omitted', () => {
    const idp = identityProvider({
      privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
      privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
      metadata: idpMetaXml,
    });
    const sp = serviceProvider({
      privateKey: fs.readFileSync('./test/key/sp/privkey.pem'),
      privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
      metadata: spMetaXml,
    });
    const result = idp.createLogoutRequest(sp, 'post', {
      logoutNameID: 'u@x',
      // sessionIndex intentionally omitted
    });
    const decoded = Buffer.from(result.context, 'base64').toString('utf8');
    expect(decoded).not.toContain('<samlp:SessionIndex');
  });
});

describe('AuthnRequest attribute omission (#455, saml-core §3.4.1)', () => {
  // saml-core §3.4.1 declares ACS URL, NameIDPolicy/Format, AllowCreate
  // (and friends) as `use="optional"`. If samlify can't fill them in, it
  // must omit the attribute rather than emit `name=""` or `name="undefined"`.

  test('default AuthnRequest template drops AssertionConsumerServiceURL when value is undefined', () => {
    const xml = libsaml.replaceTagsByValue(libsaml.defaultLoginRequestTemplate.context, {
      ID: '_x',
      Destination: 'https://idp/sso',
      Issuer: 'https://sp/meta',
      IssueInstant: '2026-05-01T00:00:00Z',
      AssertionConsumerServiceURL: undefined,
      NameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      AllowCreate: false,
    });
    expect(xml).not.toContain('AssertionConsumerServiceURL=""');
    expect(xml).not.toContain('AssertionConsumerServiceURL="undefined"');
    expect(xml).not.toContain('AssertionConsumerServiceURL=');
  });

  test('default AuthnRequest template drops NameIDFormat and AllowCreate when both are undefined', () => {
    const xml = libsaml.replaceTagsByValue(libsaml.defaultLoginRequestTemplate.context, {
      ID: '_x',
      Destination: 'https://idp/sso',
      Issuer: 'https://sp/meta',
      IssueInstant: '2026-05-01T00:00:00Z',
      AssertionConsumerServiceURL: 'https://sp/acs',
      NameIDFormat: undefined,
      AllowCreate: undefined,
    });
    expect(xml).not.toContain('Format=');
    expect(xml).not.toContain('AllowCreate=');
    // The NameIDPolicy element itself remains (saml-core §3.4.1 allows it
    // with no attributes).
    expect(xml).toContain('<samlp:NameIDPolicy');
  });
});

describe('Per-request relayState (#163)', () => {
  // saml-bindings §3.4.3 / §3.5.3: RelayState is request-scoped. The
  // tests below pin the contract that callers can override the entity-
  // level setting on a per-call basis, including under concurrency.

  const idpDefault = identityProvider({
    privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
    privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
    metadata: idpMetaXml,
    relayState: 'idp-default-state',
  });
  const spDefault = serviceProvider({
    privateKey: fs.readFileSync('./test/key/sp/privkey.pem'),
    privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
    metadata: spMetaXml,
    relayState: 'sp-default-state',
  });

  describe('createLoginRequest (#583, saml-bindings §3.4.3)', () => {
    test('redirect: per-request relayState surfaces in the URL', () => {
      const result = spDefault.createLoginRequest(idpDefault, 'redirect', {
        relayState: 'per-request-deep-link',
      });
      expect(result.context).toContain(`RelayState=${encodeURIComponent('per-request-deep-link')}`);
    });

    test('redirect: empty per-request relayState falls back to entity setting', () => {
      const result = spDefault.createLoginRequest(idpDefault, 'redirect');
      expect(result.context).toContain(`RelayState=${encodeURIComponent('sp-default-state')}`);
    });

    test('redirect: per-request override beats entity setting', () => {
      const result = spDefault.createLoginRequest(idpDefault, 'redirect', {
        relayState: 'override',
      });
      expect(result.context).toContain('RelayState=override');
      expect(result.context).not.toContain('sp-default-state');
    });

    test('redirect: backwards-compatible callback shape still works', () => {
      const cb = (template: string) => ({ id: '_legacy', context: template });
      const result = spDefault.createLoginRequest(idpDefault, 'redirect', cb);
      expect(result.id).toBeDefined();
    });

    test('binding parameter omitted defaults to redirect', () => {
      const result = spDefault.createLoginRequest(idpDefault);
      expect(result.context).toContain('SAMLRequest=');
    });

    test('redirect: per-request relayState wins even when entity setting is unset', () => {
      const spNoEntityState = serviceProvider({
        privateKey: fs.readFileSync('./test/key/sp/privkey.pem'),
        privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
        metadata: spMetaXml,
      });
      const result = spNoEntityState.createLoginRequest(idpDefault, 'redirect', {
        relayState: 'only-per-request',
      });
      expect(result.context).toContain(`RelayState=${encodeURIComponent('only-per-request')}`);
    });

    test('post: per-request relayState surfaces in the binding context', () => {
      const result = spDefault.createLoginRequest(idpDefault, 'post', {
        relayState: 'post-state',
      });
      expect((result as { relayState?: string }).relayState).toBe('post-state');
    });

    test('simpleSign: per-request relayState surfaces in the binding context', () => {
      const result = spDefault.createLoginRequest(idpDefault, 'simpleSign', {
        relayState: 'ss-state',
      });
      expect((result as { relayState?: string }).relayState).toBe('ss-state');
    });

    test('concurrency: two interleaved calls produce different relayStates', () => {
      const a = spDefault.createLoginRequest(idpDefault, 'redirect', { relayState: 'state-A' });
      const b = spDefault.createLoginRequest(idpDefault, 'redirect', { relayState: 'state-B' });
      expect(a.context).toContain('state-A');
      expect(a.context).not.toContain('state-B');
      expect(b.context).toContain('state-B');
      expect(b.context).not.toContain('state-A');
    });
  });

  describe('createLogoutRequest (saml-profiles §4.4)', () => {
    test('options bag: per-request relayState surfaces on the result', () => {
      const result = idpDefault.createLogoutRequest(spDefault, 'redirect', { logoutNameID: 'u@x' }, {
        relayState: 'logout-deep-link',
      });
      expect(result.context).toContain(`RelayState=${encodeURIComponent('logout-deep-link')}`);
    });

    test('legacy positional: string in 4th param still works', () => {
      const result = idpDefault.createLogoutRequest(spDefault, 'redirect', { logoutNameID: 'u@x' }, 'legacy-state');
      expect(result.context).toContain(`RelayState=${encodeURIComponent('legacy-state')}`);
    });

    test('post binding: per-request relayState propagates', () => {
      const result = idpDefault.createLogoutRequest(spDefault, 'post', { logoutNameID: 'u@x' }, {
        relayState: 'post-logout-state',
      });
      expect((result as { relayState?: string }).relayState).toBe('post-logout-state');
    });

    test('simpleSign binding: per-request relayState propagates', () => {
      const result = idpDefault.createLogoutRequest(spDefault, 'simpleSign', { logoutNameID: 'u@x' }, {
        relayState: 'ss-logout-state',
      });
      expect((result as { relayState?: string }).relayState).toBe('ss-logout-state');
    });

    test('options bag: customTagReplacement co-exists with relayState', () => {
      const cb = (template: string) => ({ id: '_custom-logout', context: template });
      const idpWithTpl = identityProvider({
        privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
        privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
        metadata: idpMetaXml,
        logoutRequestTemplate: { context: '<LogoutRequest/>' },
      });
      const result = idpWithTpl.createLogoutRequest(spDefault, 'post', { logoutNameID: 'u@x' }, {
        relayState: 'tagged-state',
        customTagReplacement: cb,
      });
      expect(result.id).toBe('_custom-logout');
      expect((result as { relayState?: string }).relayState).toBe('tagged-state');
    });
  });

  describe('createLogoutResponse (saml-profiles §4.4)', () => {
    const requestInfo = { extract: { request: { id: '_abc' } } } as any;

    test('options bag: per-request relayState surfaces on the result', () => {
      const result = idpDefault.createLogoutResponse(spDefault, requestInfo, 'redirect', {
        relayState: 'resp-deep-link',
      });
      expect(result.context).toContain(`RelayState=${encodeURIComponent('resp-deep-link')}`);
    });

    test('legacy positional: string in 4th param still works', () => {
      const result = idpDefault.createLogoutResponse(spDefault, requestInfo, 'redirect', 'legacy-resp');
      expect(result.context).toContain(`RelayState=${encodeURIComponent('legacy-resp')}`);
    });

    test('post binding: per-request relayState propagates', () => {
      const result = idpDefault.createLogoutResponse(spDefault, requestInfo, 'post', {
        relayState: 'post-resp-state',
      });
      expect((result as { relayState?: string }).relayState).toBe('post-resp-state');
    });

    test('simpleSign binding: per-request relayState propagates', () => {
      const result = idpDefault.createLogoutResponse(spDefault, requestInfo, 'simpleSign', {
        relayState: 'ss-resp-state',
      });
      expect((result as { relayState?: string }).relayState).toBe('ss-resp-state');
    });
  });

  describe('createLoginResponse (saml-profiles §4.1.6)', () => {
    test('options bag: relayState propagates through redirect binding', async () => {
      const result = await idpDefault.createLoginResponse(
        spDefault,
        { extract: { request: { id: '_x' } } } as any,
        'redirect',
        { email: 'u@x' },
        { relayState: 'resp-redirect' },
      );
      expect(result.context).toContain(`RelayState=${encodeURIComponent('resp-redirect')}`);
    });

    test('options bag: relayState propagates through simpleSign binding', async () => {
      const result = await idpDefault.createLoginResponse(
        spDefault,
        { extract: { request: { id: '_x' } } } as any,
        'simpleSign',
        { email: 'u@x' },
        { relayState: 'resp-ss' },
      );
      expect((result as { relayState?: string }).relayState).toBe('resp-ss');
    });

    test('legacy positional shape still wires relayState through', async () => {
      const cb = undefined;
      const encryptThenSign = false;
      const result = await idpDefault.createLoginResponse(
        spDefault,
        { extract: { request: { id: '_x' } } } as any,
        'redirect',
        { email: 'u@x' },
        cb,
        encryptThenSign,
        'legacy-resp-state',
      );
      expect(result.context).toContain(`RelayState=${encodeURIComponent('legacy-resp-state')}`);
    });
  });
});

describe('Redirect binding endpoint discovery (closes #308 #405, saml-bindings §3.4 / saml-metadata §2.4.3)', () => {
  // Both issues report a TypeError thrown deep inside url.parse when the
  // peer's metadata declares no HTTP-Redirect endpoint. The fix is a
  // type-guard at the top of each redirect builder: when
  // getSingleSignOnService / getSingleLogoutService falls through to the
  // raw service map (an object), throw a clear named error instead.

  test('SP createLoginRequest(redirect) throws ERR_NO_REDIRECT_SSO_ENDPOINT when IdP advertises no HTTP-Redirect SSO', () => {
    // IdP built from options with only an HTTP-POST SingleSignOnService —
    // no HTTP-Redirect entry, mirroring the metadata reported in #308.
    // The SP's spmeta.xml has AuthnRequestsSigned="true", so the IdP must
    // set wantAuthnRequestsSigned to avoid the unrelated signed-flag conflict.
    const idpPostOnly = identityProvider({
      wantAuthnRequestsSigned: true,
      isAssertionEncrypted: false,
      singleSignOnService: [{
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        Location: 'https://idp.example.org/sso/post',
      }],
    });
    const sp = serviceProvider({
      privateKey: fs.readFileSync('./test/key/sp/privkey.pem'),
      privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
      metadata: spMetaXml,
    });
    expect(() => sp.createLoginRequest(idpPostOnly, 'redirect')).toThrow('ERR_NO_REDIRECT_SSO_ENDPOINT');
  });

  test('IdP createLogoutRequest(redirect) throws ERR_NO_REDIRECT_SLO_ENDPOINT when SP advertises no HTTP-Redirect SLO', () => {
    // SP built from options with only an HTTP-POST SingleLogoutService —
    // mirrors the logout-side variant of the same root cause (#405).
    const idp = identityProvider({
      privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
      privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
      metadata: idpMetaXml,
    });
    const spPostOnlySlo = serviceProvider({
      entityID: 'https://sp.example.org/metadata',
      privateKey: fs.readFileSync('./test/key/sp/privkey.pem'),
      privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
      assertionConsumerService: [{
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        Location: 'https://sp.example.org/sp/sso',
      }],
      singleLogoutService: [{
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        Location: 'https://sp.example.org/sp/slo',
      }],
    });
    expect(() => idp.createLogoutRequest(spPostOnlySlo, 'redirect', { logoutNameID: 'u@x' }))
      .toThrow('ERR_NO_REDIRECT_SLO_ENDPOINT');
  });

  test('IdP createLogoutResponse(redirect) throws ERR_NO_REDIRECT_SLO_ENDPOINT when SP advertises no HTTP-Redirect SLO', () => {
    const idp = identityProvider({
      privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
      privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
      metadata: idpMetaXml,
    });
    const spPostOnlySlo = serviceProvider({
      entityID: 'https://sp.example.org/metadata',
      privateKey: fs.readFileSync('./test/key/sp/privkey.pem'),
      privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
      assertionConsumerService: [{
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        Location: 'https://sp.example.org/sp/sso',
      }],
      singleLogoutService: [{
        Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        Location: 'https://sp.example.org/sp/slo',
      }],
    });
    const requestInfo = { extract: { request: { id: '_abc' } } } as any;
    expect(() => idp.createLogoutResponse(spPostOnlySlo, requestInfo, 'redirect', 'state'))
      .toThrow('ERR_NO_REDIRECT_SLO_ENDPOINT');
  });
});

describe('ForceAuthn (#359, saml-core §3.4.1)', () => {
  // saml-core §3.4.1 declares `ForceAuthn` as `xs:boolean` with
  // `use="optional"` on `<samlp:AuthnRequest>`. saml-profiles §4.1.4.1
  // pins the semantics: when "true", the IdP MUST authenticate the
  // presenter directly rather than rely on a previous security context.

  const idp = identityProvider({
    privateKey: fs.readFileSync('./test/key/idp/privkey.pem'),
    privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
    metadata: idpMetaXml,
  });
  const sp = serviceProvider({
    privateKey: fs.readFileSync('./test/key/sp/privkey.pem'),
    privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
    metadata: spMetaXml,
  });

  test('default AuthnRequest template renders ForceAuthn when set', () => {
    const xml = libsaml.replaceTagsByValue(libsaml.defaultLoginRequestTemplate.context, {
      ID: '_x',
      Destination: 'https://idp/sso',
      Issuer: 'https://sp/meta',
      IssueInstant: '2026-05-01T00:00:00Z',
      AssertionConsumerServiceURL: 'https://sp/acs',
      NameIDFormat: 'fmt',
      AllowCreate: true,
      ForceAuthn: true,
    });
    expect(xml).toContain('ForceAuthn="true"');
  });

  test('default AuthnRequest template omits ForceAuthn when undefined', () => {
    const xml = libsaml.replaceTagsByValue(libsaml.defaultLoginRequestTemplate.context, {
      ID: '_x',
      Destination: 'https://idp/sso',
      Issuer: 'https://sp/meta',
      IssueInstant: '2026-05-01T00:00:00Z',
      AssertionConsumerServiceURL: 'https://sp/acs',
      NameIDFormat: 'fmt',
      AllowCreate: true,
      ForceAuthn: undefined,
    });
    expect(xml).not.toContain('ForceAuthn=');
  });

  test('createLoginRequest (redirect): forceAuthn surfaces in the rendered XML', () => {
    const result = sp.createLoginRequest(idp, 'redirect', { forceAuthn: true });
    const url = new URL(result.context, 'http://example.test');
    const inflated = require('zlib').inflateRawSync(
      Buffer.from(decodeURIComponent(url.searchParams.get('SAMLRequest')!), 'base64'),
    ).toString('utf8');
    expect(inflated).toContain('ForceAuthn="true"');
  });

  test('createLoginRequest (post): forceAuthn surfaces in the rendered XML', () => {
    const result = sp.createLoginRequest(idp, 'post', { forceAuthn: true });
    const decoded = Buffer.from(result.context, 'base64').toString('utf8');
    expect(decoded).toContain('ForceAuthn="true"');
  });

  test('createLoginRequest (simpleSign): forceAuthn surfaces in the rendered XML', () => {
    const result = sp.createLoginRequest(idp, 'simpleSign', { forceAuthn: true });
    const decoded = Buffer.from(result.context, 'base64').toString('utf8');
    expect(decoded).toContain('ForceAuthn="true"');
  });

  test('backwards-compat: no options bag, no ForceAuthn attribute in the XML', () => {
    const result = sp.createLoginRequest(idp, 'redirect');
    const url = new URL(result.context, 'http://example.test');
    const inflated = require('zlib').inflateRawSync(
      Buffer.from(decodeURIComponent(url.searchParams.get('SAMLRequest')!), 'base64'),
    ).toString('utf8');
    expect(inflated).not.toContain('ForceAuthn=');
  });

  test('createLoginRequest (redirect): forceAuthn=false renders ForceAuthn="false"', () => {
    // saml-core §3.4.1 — explicit `false` is still a valid xs:boolean and
    // the IdP MAY rely on a previous security context. We render it verbatim.
    const result = sp.createLoginRequest(idp, 'redirect', { forceAuthn: false });
    const url = new URL(result.context, 'http://example.test');
    const inflated = require('zlib').inflateRawSync(
      Buffer.from(decodeURIComponent(url.searchParams.get('SAMLRequest')!), 'base64'),
    ).toString('utf8');
    expect(inflated).toContain('ForceAuthn="false"');
  });

  test('createLoginRequest (post): no options bag, no ForceAuthn attribute in the XML', () => {
    const result = sp.createLoginRequest(idp, 'post');
    const decoded = Buffer.from(result.context, 'base64').toString('utf8');
    expect(decoded).not.toContain('ForceAuthn=');
  });

  test('createLoginRequest (simpleSign): no options bag, no ForceAuthn attribute in the XML', () => {
    const result = sp.createLoginRequest(idp, 'simpleSign');
    const decoded = Buffer.from(result.context, 'base64').toString('utf8');
    expect(decoded).not.toContain('ForceAuthn=');
  });
});

describe('IdP tagPrefix override (#388, saml-core §1.4)', () => {
  // saml-core §1.4 — XML namespace prefixes are not normative; only the
  // namespace URIs are. Callers can rebind them as long as the URI
  // bindings remain correct. Some peers (legacy ADFS, custom integrations)
  // require non-standard prefixes; this lets us swap `samlp:` ↔ `samlp2:`
  // and `saml:` ↔ `saml2:` without supplying a fully custom template.

  const idpKey = fs.readFileSync('./test/key/idp/privkey.pem');
  const idpKeyPass = 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW';
  const spKey = fs.readFileSync('./test/key/sp/privkey.pem');
  const spKeyPass = 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px';

  const sp = serviceProvider({ privateKey: spKey, privateKeyPass: spKeyPass, metadata: spMetaXml });
  const requestInfo = { extract: { request: { id: '_req-id' } } } as any;

  const decode = (b64: string) => Buffer.from(b64, 'base64').toString('utf8');

  test('login response template uses overridden protocol prefix', async () => {
    const idp = identityProvider({
      privateKey: idpKey,
      privateKeyPass: idpKeyPass,
      metadata: idpMetaXml,
      tagPrefix: { protocol: 'samlp2' },
    });
    const result = await idp.createLoginResponse(sp, requestInfo, 'post', { email: 'u@x' });
    const xml = decode((result as { context: string }).context);
    expect(xml).toContain('<samlp2:Response');
    expect(xml).toContain('xmlns:samlp2="urn:oasis:names:tc:SAML:2.0:protocol"');
    expect(xml).not.toContain('<samlp:Response');
  });

  test('login response template uses overridden assertion prefix', async () => {
    const idp = identityProvider({
      privateKey: idpKey,
      privateKeyPass: idpKeyPass,
      metadata: idpMetaXml,
      tagPrefix: { assertion: 'saml2' },
    });
    const result = await idp.createLoginResponse(sp, requestInfo, 'post', { email: 'u@x' });
    const xml = decode((result as { context: string }).context);
    expect(xml).toContain('<saml2:Issuer');
    expect(xml).toContain('<saml2:Assertion');
    expect(xml).toContain('xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"');
    expect(xml).not.toMatch(/<saml:Issuer/);
  });

  test('both prefixes overridden simultaneously land on the rendered XML', async () => {
    const idp = identityProvider({
      privateKey: idpKey,
      privateKeyPass: idpKeyPass,
      metadata: idpMetaXml,
      tagPrefix: { protocol: 'p2', assertion: 'a2' },
    });
    const result = await idp.createLoginResponse(sp, requestInfo, 'post', { email: 'u@x' });
    const xml = decode((result as { context: string }).context);
    expect(xml).toContain('<p2:Response');
    expect(xml).toContain('<a2:Issuer');
    expect(xml).toContain('<a2:Assertion');
    expect(xml).toContain('xmlns:p2="urn:oasis:names:tc:SAML:2.0:protocol"');
    expect(xml).toContain('xmlns:a2="urn:oasis:names:tc:SAML:2.0:assertion"');
    expect(xml).not.toContain('<samlp:Response');
    expect(xml).not.toMatch(/<saml:Issuer/);
  });

  test('default behaviour preserved when no tagPrefix overrides are supplied', async () => {
    const idp = identityProvider({
      privateKey: idpKey,
      privateKeyPass: idpKeyPass,
      metadata: idpMetaXml,
    });
    const result = await idp.createLoginResponse(sp, requestInfo, 'post', { email: 'u@x' });
    const xml = decode((result as { context: string }).context);
    expect(xml).toContain('<samlp:Response');
    expect(xml).toContain('<saml:Issuer');
    expect(xml).toContain('xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"');
    expect(xml).toContain('xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"');
  });

  test('caller-supplied loginResponseTemplate is rewritten too', () => {
    const idp = identityProvider({
      privateKey: idpKey,
      privateKeyPass: idpKeyPass,
      metadata: idpMetaXml,
      tagPrefix: { protocol: 'p2' },
      // The IdP constructor rewrites the caller's template in place so
      // customTagReplacement consumers see the rebound prefix too.
      loginResponseTemplate: {
        context: '<samlp:Response>{ID}</samlp:Response>',
        attributes: [],
      } as any,
    });
    const ctx = (idp.entitySetting.loginResponseTemplate as { context: string }).context;
    expect(ctx).toContain('<p2:Response>');
    expect(ctx).not.toContain('<samlp:Response>');
  });

  test('rewrite also applies to logoutRequest and logoutResponse default templates', () => {
    const idp = identityProvider({
      privateKey: idpKey,
      privateKeyPass: idpKeyPass,
      metadata: idpMetaXml,
      tagPrefix: { protocol: 'samlp2', assertion: 'saml2' },
    });
    const logoutReqResult = idp.createLogoutRequest(sp, 'post', { logoutNameID: 'u@x' }) as { context: string };
    const reqXml = decode(logoutReqResult.context);
    expect(reqXml).toContain('<samlp2:LogoutRequest');
    expect(reqXml).toContain('<saml2:Issuer');
    expect(reqXml).toContain('xmlns:samlp2="urn:oasis:names:tc:SAML:2.0:protocol"');

    const logoutRespResult = idp.createLogoutResponse(
      sp,
      { extract: { request: { id: '_lr' } } } as any,
      'post',
      'state',
    ) as { context: string };
    const respXml = decode(logoutRespResult.context);
    expect(respXml).toContain('<samlp2:LogoutResponse');
    expect(respXml).toContain('<saml2:Issuer');
  });

  test('caller-supplied logoutRequestTemplate is rewritten too', () => {
    const idp = identityProvider({
      privateKey: idpKey,
      privateKeyPass: idpKeyPass,
      metadata: idpMetaXml,
      tagPrefix: { protocol: 'p2', assertion: 'a2' },
      logoutRequestTemplate: {
        context: '<samlp:LogoutRequest><saml:Issuer>{Issuer}</saml:Issuer></samlp:LogoutRequest>',
      },
    });
    const ctx = (idp.entitySetting.logoutRequestTemplate as { context: string }).context;
    expect(ctx).toContain('<p2:LogoutRequest>');
    expect(ctx).toContain('<a2:Issuer>');
    expect(ctx).not.toContain('<samlp:');
    expect(ctx).not.toContain('<saml:');
  });

  test('caller-supplied logoutResponseTemplate is rewritten too', () => {
    const idp = identityProvider({
      privateKey: idpKey,
      privateKeyPass: idpKeyPass,
      metadata: idpMetaXml,
      tagPrefix: { protocol: 'p2', assertion: 'a2' },
      logoutResponseTemplate: {
        context: '<samlp:LogoutResponse><saml:Issuer>{Issuer}</saml:Issuer></samlp:LogoutResponse>',
      },
    });
    const ctx = (idp.entitySetting.logoutResponseTemplate as { context: string }).context;
    expect(ctx).toContain('<p2:LogoutResponse>');
    expect(ctx).toContain('<a2:Issuer>');
    expect(ctx).not.toContain('<samlp:');
    expect(ctx).not.toContain('<saml:');
  });

  test('redirect binding picks up the rewritten default templates', async () => {
    const idp = identityProvider({
      privateKey: idpKey,
      privateKeyPass: idpKeyPass,
      metadata: idpMetaXml,
      tagPrefix: { protocol: 'p2', assertion: 'a2' },
    });
    // login response over redirect
    const loginResp = await idp.createLoginResponse(sp, requestInfo, 'redirect', { email: 'u@x' });
    const loginResponseQuery = (loginResp.context as string).split('SAMLResponse=')[1].split('&')[0];
    const loginXml = require('zlib')
      .inflateRawSync(Buffer.from(decodeURIComponent(loginResponseQuery), 'base64'))
      .toString('utf8');
    expect(loginXml).toContain('<p2:Response');
    expect(loginXml).toContain('<a2:Assertion');

    // logout request over redirect
    const logoutReq = idp.createLogoutRequest(sp, 'redirect', { logoutNameID: 'u@x' });
    const reqQuery = (logoutReq.context as string).split('SAMLRequest=')[1].split('&')[0];
    const reqXml = require('zlib')
      .inflateRawSync(Buffer.from(decodeURIComponent(reqQuery), 'base64'))
      .toString('utf8');
    expect(reqXml).toContain('<p2:LogoutRequest');
    expect(reqXml).toContain('<a2:Issuer');

    // logout response over redirect
    const logoutResp = idp.createLogoutResponse(sp, { extract: { request: { id: '_lr' } } } as any, 'redirect', '');
    const respQuery = (logoutResp.context as string).split('SAMLResponse=')[1].split('&')[0];
    const respXml = require('zlib')
      .inflateRawSync(Buffer.from(decodeURIComponent(respQuery), 'base64'))
      .toString('utf8');
    expect(respXml).toContain('<p2:LogoutResponse');
    expect(respXml).toContain('<a2:Issuer');
  });

  test('simpleSign binding picks up the rewritten default templates', async () => {
    const idp = identityProvider({
      privateKey: idpKey,
      privateKeyPass: idpKeyPass,
      metadata: idpMetaXml,
      tagPrefix: { protocol: 'p2', assertion: 'a2' },
    });
    const loginResp = await idp.createLoginResponse(sp, requestInfo, 'simpleSign', { email: 'u@x' });
    const loginXml = decode((loginResp as { context: string }).context);
    expect(loginXml).toContain('<p2:Response');
    expect(loginXml).toContain('<a2:Assertion');

    const logoutReq = idp.createLogoutRequest(sp, 'simpleSign', { logoutNameID: 'u@x' });
    const reqXml = decode((logoutReq as { context: string }).context);
    expect(reqXml).toContain('<p2:LogoutRequest');
    expect(reqXml).toContain('<a2:Issuer');

    const logoutResp = idp.createLogoutResponse(sp, { extract: { request: { id: '_lr' } } } as any, 'simpleSign', '');
    const respXml = decode((logoutResp as { context: string }).context);
    expect(respXml).toContain('<p2:LogoutResponse');
    expect(respXml).toContain('<a2:Issuer');
  });

  test('encryptedAssertion prefix continues to be honoured independently', () => {
    // Defaults to 'saml' on every IdP — preserved when the new
    // protocol/assertion overrides are introduced.
    const idp = identityProvider({
      privateKey: idpKey,
      privateKeyPass: idpKeyPass,
      metadata: idpMetaXml,
      tagPrefix: { protocol: 'samlp2', encryptedAssertion: 'saml' },
    });
    expect(idp.entitySetting.tagPrefix?.encryptedAssertion).toBe('saml');
    expect(idp.entitySetting.tagPrefix?.protocol).toBe('samlp2');
  });
});
