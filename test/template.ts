import { test, expect, describe, vi } from 'vitest';
import * as esaml2 from '../index';
import { renderTemplate, placeholderName } from '../src/template';
import { camelCase } from '../src/utility';

const { SamlLib: libsaml } = esaml2;

const placeholders = (template: string) => [...new Set([...template.matchAll(/\{([^{}]+)\}/g)].map(m => m[1]))];

describe('renderTemplate', () => {
  test('escapes values in attribute values and text', () => {
    const xml = renderTemplate('<a x="{V}" y=\'{V}\'>{V}</a>', { V: `"'<&>` });
    expect(xml).toBe('<a x="&quot;&apos;&lt;&amp;&gt;" y=\'&quot;&apos;&lt;&amp;&gt;\'>&quot;&apos;&lt;&amp;&gt;</a>');
  });

  test('inserts values in one pass and never as placeholders', () => {
    const xml = renderTemplate('<a x="{A}">{B}</a>', { A: '{B}', B: '{A}' });
    expect(xml).toBe('<a x="&#123;B&#125;">&#123;A&#125;</a>');
  });

  test('keeps $-replacement patterns literal', () => {
    expect(renderTemplate('<a>{V}</a>', { V: "$&$'$`$1" })).toBe("<a>$&amp;$&apos;$`$1</a>");
  });

  test('omits optional attributes and elements', () => {
    const template = '<r a="{N}" b="x{N}y"><e c="1">{N}</e><m>p{N}q</m><k>{V}</k></r>';
    expect(renderTemplate(template, { N: null, V: 'v' })).toBe('<r b="xy"><m>pq</m><k>v</k></r>');
    expect(renderTemplate(template, { N: undefined, V: 'v' })).toBe('<r b="xy"><m>pq</m><k>v</k></r>');
    expect(renderTemplate(template, { N: 0, V: false })).toBe('<r a="0" b="x0y"><e c="1">0</e><m>p0q</m><k>false</k></r>');
  });

  test('leaves placeholders without a value in place', () => {
    expect(renderTemplate('<a x="{X}">{Y}</a>', {})).toBe('<a x="{X}">{Y}</a>');
  });

  test('matches tag names literally, including encoded ones', () => {
    const key = 'a.b(c)*+?[x]$';
    expect(renderTemplate(`<a>{${key}}</a>`, { [key]: 'v' })).toBe('<a>v</a>');
    const odd = 'x"y{z}';
    expect(renderTemplate(`<a>{${placeholderName(odd)}}</a>`, { [odd]: 'v' })).toBe('<a>v</a>');
  });

  test.each([
    ['an element name', '<{T}/>'],
    ['an element name suffix', '<a{T}/>'],
    ['an attribute name', '<a {T}="x"/>'],
    ['an attribute name suffix', '<a b{T}="x"/>'],
    ['an end tag', '<a></{T}>'],
    ['a comment', '<a><!-- {T} --></a>'],
    ['a CDATA section', '<a><![CDATA[{T}]]></a>'],
    ['a processing instruction', '<?pi {T}?><a/>'],
  ])('rejects a placeholder in %s', (_where, template) => {
    expect(() => renderTemplate(template, { T: 'x' })).toThrow('ERR_TEMPLATE_PLACEHOLDER_POSITION');
  });

  test('rejects malformed tags', () => {
    expect(() => renderTemplate('<a b=c/>', {})).toThrow('ERR_TEMPLATE_MALFORMED');
    expect(() => renderTemplate('<a b="c/>', {})).toThrow('ERR_TEMPLATE_MALFORMED');
    expect(() => renderTemplate('<a b="c"', {})).toThrow('ERR_TEMPLATE_MALFORMED');
  });

  test('passes comments, CDATA, declarations and stray braces through', () => {
    const template = '<?xml version="1.0"?><!DOCTYPE a><a><!-- c --><![CDATA[<x>]]>{ x }{}{V}</a>';
    expect(renderTemplate(template, { V: 'v' })).toBe('<?xml version="1.0"?><!DOCTYPE a><a><!-- c --><![CDATA[<x>]]>{ x }{}v</a>');
    expect(renderTemplate('<a>{open', {})).toBe('<a>{open');
  });

  test('handles spacing around = and attributes without a value', () => {
    expect(renderTemplate('<a  b = "{V}" c\n="2" d>{U}x</a>', { V: '1' })).toBe('<a  b = "1" c\n="2" d>{U}x</a>');
  });

  test('rejects an unterminated start tag', () => {
    expect(() => renderTemplate('<a b="1" ', {})).toThrow('ERR_TEMPLATE_MALFORMED');
  });

  test('cannot be desynchronised by unexpected characters or quoted >', () => {
    // A `>` inside a quoted value must not end the tag early and hide a placeholder.
    expect(() => renderTemplate('<a é="x>" {Y}="v"/>', { Y: 'y' })).toThrow('ERR_TEMPLATE_PLACEHOLDER_POSITION');
    expect(() => renderTemplate('<a "x>" {Y}="v"/>', { Y: 'y' })).toThrow('ERR_TEMPLATE_MALFORMED');
    expect(() => renderTemplate('<a b"x">{Y}</a>', { Y: 'y' })).toThrow('ERR_TEMPLATE_MALFORMED');
    expect(() => renderTemplate('< a x="{Y}"/>', { Y: 'y' })).toThrow('ERR_TEMPLATE_MALFORMED');
    expect(() => renderTemplate('<?pi a > {X} ?><a/>', { X: 'x' })).toThrow('ERR_TEMPLATE_PLACEHOLDER_POSITION');
    expect(() => renderTemplate('<!DOCTYPE a [<!ATTLIST a b CDATA ">{X}">]><a/>', { X: 'x' })).toThrow('ERR_TEMPLATE_PLACEHOLDER_POSITION');
  });

  test('accepts non-ASCII element and attribute names', () => {
    expect(renderTemplate('<é á="{V}">{V}</é>', { V: '<v>' })).toBe('<é á="&lt;v&gt;">&lt;v&gt;</é>');
  });

  test('renders fragments and text without a root element', () => {
    expect(renderTemplate('<saml:A x="{X}"/>{Y}<saml:B/>', { X: '1', Y: '<2>' })).toBe('<saml:A x="1"/>&lt;2&gt;<saml:B/>');
  });
});

describe('renderTemplate matches replaceTagsByValue on samlify templates', () => {
  const samples = [
    'plain', 'https://sp.example.org/acs?a=1&b=2', `quote" apos' lt< gt> amp&`, '{Other}', "$&$'", null, undefined, 42, true, '',
  ];
  const attributeStatement = libsaml.attributeStatementBuilder([
    { name: 'mail', valueTag: 'user.email', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', valueXsiType: 'xs:string' },
  ]);
  const templates: Record<string, string> = {
    loginRequest: libsaml.defaultLoginRequestTemplate.context,
    loginResponse: libsaml.defaultLoginResponseTemplate.context.replace('{AttributeStatement}', () => attributeStatement),
    logoutRequest: libsaml.defaultLogoutRequestTemplate.context,
    logoutResponse: libsaml.defaultLogoutResponseTemplate.context,
    attribute: libsaml.defaultAttributeTemplate.context,
  };

  test.each(Object.keys(templates))('%s', name => {
    const template = templates[name];
    const tags = placeholders(template);
    expect(tags.length).toBeGreaterThan(0);
    // Deterministic sweep: each tag cycles through the samples at a different rate.
    for (let round = 0; round < 60; round++) {
      const values = Object.fromEntries(tags.map((tag, i) => [tag, samples[(round * (i + 1) + i) % samples.length]]));
      expect(renderTemplate(template, values)).toBe(libsaml.replaceTagsByValue(template, values));
    }
  });
});

describe('legacy replaceTagsByValue hardening', () => {
  test('a value is never filled in by a later tag', () => {
    expect(libsaml.replaceTagsByValue('<a>{A}</a><b>{B}</b>', { A: '{B}', B: 'secret' }))
      .toBe('<a>&#123;B&#125;</a><b>secret</b>');
  });

  test('tag names with RegExp characters are matched literally', () => {
    expect(libsaml.replaceTagsByValue('<a x="{a.b+}">{(c)}</a>', { 'a.b+': '1', '(c)': '2', '.': 'no' }))
      .toBe('<a x="1">2</a>');
    expect(() => libsaml.replaceTagsByValue('<a>{x}</a>', { '[': 'v' })).not.toThrow();
  });
});

describe('attributeStatementBuilder', () => {
  const quote = 'a"><evil/><x y="';

  test.each(['legacy', 'strict'] as const)('escapes attribute metadata (%s)', renderer => {
    const xml = libsaml.attributeStatementBuilder([
      { name: quote, nameFormat: quote, valueXsiType: quote, valueXmlnsXs: quote, valueXmlnsXsi: quote, valueTag: 'role' },
    ], undefined, undefined, renderer);
    expect(xml).not.toContain('<evil/>');
    expect(xml.match(/&quot;&gt;&lt;evil\/&gt;/g)).toHaveLength(5);
    expect(xml).toContain('{attrRole}');
  });

  test.each(['legacy', 'strict'] as const)('keeps $-replacement patterns literal (%s)', renderer => {
    const xml = libsaml.attributeStatementBuilder([
      { name: "$&$'$`", nameFormat: 'fmt', valueXsiType: 'xs:string', valueTag: 'role' },
    ], undefined, undefined, renderer);
    expect(xml).toContain('Name="$&amp;$&apos;$`"');
  });

  test.each(['legacy', 'strict'] as const)('an unusual valueTag stays one placeholder and is filled in (%s)', renderer => {
    const valueTag = 'role}</saml:AttributeValue><evil/>{x';
    const xml = libsaml.attributeStatementBuilder([
      { name: 'role', nameFormat: 'fmt', valueXsiType: 'xs:string', valueTag },
    ], undefined, undefined, renderer);
    expect(xml).not.toContain('<evil/>');
    // Tag name convention from docs/template.md: `attr` + camel-cased valueTag.
    const camel = camelCase(valueTag);
    const key = `attr${camel.charAt(0).toUpperCase()}${camel.slice(1)}`;
    const filled = libsaml.renderTags(xml, { [key]: 'admin' }, renderer);
    expect(filled).toContain('>admin</saml:AttributeValue>');
    expect(filled).not.toContain('<evil/>');
  });

  test('legacy and strict produce the same statement', () => {
    const attributes = [
      { name: 'mail', valueTag: 'user.email', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', valueXsiType: 'xs:string' },
      { name: 'groups', valueTag: 'user.groups', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri', valueXsiType: 'xs:string', valueXmlnsXs: 'urn:xs' },
    ];
    expect(libsaml.attributeStatementBuilder(attributes, undefined, undefined, 'strict'))
      .toBe(libsaml.attributeStatementBuilder(attributes));
  });

  test('strict rejects a custom attribute template with a placeholder in a name', () => {
    expect(() => libsaml.attributeStatementBuilder(
      [{ name: 'n', nameFormat: 'f', valueXsiType: 'xs:string', valueTag: 'v' }],
      { context: '<saml:Attribute {Name}="x">{Value}</saml:Attribute>' },
      undefined,
      'strict',
    )).toThrow('ERR_TEMPLATE_PLACEHOLDER_POSITION');
  });
});

void vi;
