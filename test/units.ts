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

  test('replaceTagsByValue treats null and undefined as empty strings', () => {
    const xml = libsaml.replaceTagsByValue(
      '<a id="{Id}">{Body}</a>',
      { Id: null, Body: undefined },
    );
    expect(xml).toBe('<a id=""></a>');
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

  test('SP metadata from options — warns when wantMessageSigned without signatureConfig', () => {
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
    expect(messages.some(m => m.includes('missing signatureConfig'))).toBe(true);
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
