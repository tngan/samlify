/**
 * @file template.ts
 * @author tngan
 * @desc Context-aware rendering of `{Tag}` placeholders in SAML XML templates.
 */
import xmlEscape from 'xml-escape';

/** Value accepted for a placeholder; `null` / `undefined` mean "omit". */
export type TemplateValue = string | number | boolean | null | undefined;

/** Placeholder values keyed by tag name. */
export type TemplateValues = Record<string, TemplateValue>;

/**
 * Template engine used for the XML samlify builds.
 *
 * - `legacy` — string substitution (`replaceTagsByValue`); the default until v3.
 * - `strict` — {@link renderTemplate}: placeholders are only accepted in
 *   attribute values and text, and every value is escaped for its position.
 */
export type TemplateRenderer = 'legacy' | 'strict';

interface Literal {
  kind: 'literal';
  text: string;
}

interface Placeholder {
  kind: 'placeholder';
  /** Placeholder name as written in the template. */
  name: string;
  context: 'attribute' | 'text';
}

/** Attribute whose whole value is one placeholder; omitted when the value is null. */
interface OptionalAttribute {
  kind: 'optional-attribute';
  /** Leading whitespace, attribute name, `=` and quotes, e.g. ` ID="{ID}"`. */
  text: string;
  name: string;
}

/** Element whose only content is one placeholder; omitted when the value is null. */
interface OptionalElement {
  kind: 'optional-element';
  /** Segments of the start tag, rendered when the element is kept. */
  startTag: Segment[];
  endTag: string;
  name: string;
}

type Segment = Literal | Placeholder | OptionalAttribute | OptionalElement;

const NAME_START = /[A-Za-z_:]/;
const NAME_CHAR = /[\w:.-]/;

/**
 * XML-escape text for an attribute value or character data, also encoding
 * `{` and `}` as character references. XML parsers and canonicalization read
 * them as the same characters; encoding them guarantees that inserted text
 * never reads as a placeholder in a later rendering step.
 *
 * @param text raw text
 * @returns escaped text
 */
export function escapeXmlValue(text: string): string {
  return xmlEscape(text).replace(/[{}]/g, c => (c === '{' ? '&#123;' : '&#125;'));
}

/**
 * Encode a tag name the way it must appear in a template so that it reads
 * as one placeholder. For plain names (letters, digits, `.`, `-`, `_`) this
 * is the name itself.
 *
 * @param name tag name
 * @returns placeholder text without the surrounding braces
 */
export function placeholderName(name: string): string {
  return escapeXmlValue(name);
}

/** Map the placeholder names a template may contain to their value keys. */
function lookupFor(values: TemplateValues): Map<string, string> {
  const lookup = new Map<string, string>();
  Object.keys(values).forEach(key => {
    lookup.set(placeholderName(key), key);
    lookup.set(key, key);
  });
  return lookup;
}

function positionError(template: string, index: number, where: string): Error {
  return new Error(`ERR_TEMPLATE_PLACEHOLDER_POSITION: placeholder ${where} at offset ${index}: ${template.slice(index, index + 40)}`);
}

/**
 * Read a `{name}` placeholder starting at `index` (which holds `{`).
 *
 * @returns the name and the index after `}`, or `null` when the brace does
 *   not open a placeholder (no closing brace before markup)
 */
function readPlaceholder(template: string, index: number): { name: string; end: number } | null {
  const close = template.indexOf('}', index + 1);
  if (close === -1) {
    return null;
  }
  const name = template.slice(index + 1, close);
  if (name === '' || /[{<>"']/.test(name)) {
    return null;
  }
  return { name, end: close + 1 };
}

/** Split character data or an attribute value into literals and placeholders. */
function splitValue(template: string, from: number, to: number, context: 'attribute' | 'text'): Segment[] {
  const segments: Segment[] = [];
  let literalStart = from;
  let i = from;
  while (i < to) {
    if (template[i] === '{') {
      const placeholder = readPlaceholder(template, i);
      if (placeholder && placeholder.end <= to) {
        if (i > literalStart) {
          segments.push({ kind: 'literal', text: template.slice(literalStart, i) });
        }
        segments.push({ kind: 'placeholder', name: placeholder.name, context });
        i = placeholder.end;
        literalStart = i;
        continue;
      }
    }
    i++;
  }
  if (to > literalStart) {
    segments.push({ kind: 'literal', text: template.slice(literalStart, to) });
  }
  return segments;
}

/** Throw when a placeholder appears in markup where no value may go. */
function assertNoPlaceholder(template: string, from: number, to: number, where: string): void {
  for (let i = from; i < to; i++) {
    if (template[i] === '{') {
      const placeholder = readPlaceholder(template, i);
      if (placeholder && placeholder.end <= to) {
        throw positionError(template, i, where);
      }
    }
  }
}

/**
 * Parse a start tag beginning at `index` (which holds `<`).
 *
 * @returns the tag's segments, its name, whether it is self-closing and the
 *   index after `>`
 */
function parseStartTag(template: string, index: number): { segments: Segment[]; name: string; selfClosing: boolean; end: number } {
  const segments: Segment[] = [];
  let i = index + 1;
  const nameStart = i;
  while (i < template.length && NAME_CHAR.test(template[i])) {
    i++;
  }
  const name = template.slice(nameStart, i);
  assertNoPlaceholder(template, nameStart, i + 1, 'in an element name');
  let literalStart = index;

  while (i < template.length) {
    const c = template[i];
    if (c === '>' || (c === '/' && template[i + 1] === '>')) {
      const end = c === '>' ? i + 1 : i + 2;
      segments.push({ kind: 'literal', text: template.slice(literalStart, end) });
      return { segments, name, selfClosing: c === '/', end };
    }
    if (c === '{') {
      throw positionError(template, i, 'in an element or attribute name');
    }
    if (/\s/.test(c)) {
      // Attribute: whitespace, name, `=`, quoted value.
      const attrStart = i;
      while (i < template.length && /\s/.test(template[i])) {
        i++;
      }
      if (!NAME_START.test(template[i] ?? '')) {
        continue;
      }
      while (i < template.length && NAME_CHAR.test(template[i])) {
        i++;
      }
      if (template[i] === '{') {
        throw positionError(template, i, 'in an attribute name');
      }
      while (/\s/.test(template[i] ?? '')) {
        i++;
      }
      if (template[i] !== '=') {
        continue;
      }
      i++;
      while (/\s/.test(template[i] ?? '')) {
        i++;
      }
      const quote = template[i];
      if (quote !== '"' && quote !== "'") {
        throw new Error(`ERR_TEMPLATE_MALFORMED: unquoted attribute value at offset ${i}`);
      }
      const valueStart = i + 1;
      const valueEnd = template.indexOf(quote, valueStart);
      if (valueEnd === -1) {
        throw new Error(`ERR_TEMPLATE_MALFORMED: unterminated attribute value at offset ${i}`);
      }
      const value = splitValue(template, valueStart, valueEnd, 'attribute');
      i = valueEnd + 1;
      const whole = value.length === 1 && value[0].kind === 'placeholder' ? value[0] as Placeholder : null;
      if (attrStart > literalStart) {
        segments.push({ kind: 'literal', text: template.slice(literalStart, attrStart) });
      }
      if (whole) {
        segments.push({ kind: 'optional-attribute', text: template.slice(attrStart, i), name: whole.name });
      } else {
        segments.push({ kind: 'literal', text: template.slice(attrStart, valueStart) });
        segments.push(...value);
        segments.push({ kind: 'literal', text: quote });
      }
      literalStart = i;
      continue;
    }
    i++;
  }
  throw new Error(`ERR_TEMPLATE_MALFORMED: unterminated start tag at offset ${index}`);
}

/**
 * Tokenize a template into literals and placeholders, recording the markup
 * context of every placeholder.
 *
 * @param template XML template (a document or a fragment)
 * @returns segments in document order
 */
function tokenize(template: string): Segment[] {
  const segments: Segment[] = [];
  let i = 0;
  let textStart = 0;
  const flushText = (to: number) => {
    if (to > textStart) {
      segments.push(...splitValue(template, textStart, to, 'text'));
    }
  };

  while (i < template.length) {
    if (template[i] !== '<') {
      i++;
      continue;
    }
    flushText(i);
    let end: number;
    if (template.startsWith('<!--', i)) {
      end = template.indexOf('-->', i + 4);
      end = end === -1 ? template.length : end + 3;
      assertNoPlaceholder(template, i, end, 'in a comment');
    } else if (template.startsWith('<![CDATA[', i)) {
      end = template.indexOf(']]>', i + 9);
      end = end === -1 ? template.length : end + 3;
      assertNoPlaceholder(template, i, end, 'in a CDATA section');
    } else if (template.startsWith('<?', i) || template.startsWith('<!', i) || template.startsWith('</', i)) {
      end = template.indexOf('>', i + 2);
      end = end === -1 ? template.length : end + 1;
      assertNoPlaceholder(template, i, end, template[i + 1] === '/' ? 'in an end tag' : 'in markup declarations');
      segments.push({ kind: 'literal', text: template.slice(i, end) });
      i = end;
      textStart = i;
      continue;
    } else {
      const tag = parseStartTag(template, i);
      end = tag.end;
      // `<X ...>{Tag}</X>`: the element is omitted when the value is null.
      const placeholder = !tag.selfClosing && template[end] === '{' ? readPlaceholder(template, end) : null;
      const endTag = `</${tag.name}>`;
      if (placeholder && template.startsWith(endTag, placeholder.end)) {
        segments.push({ kind: 'optional-element', startTag: tag.segments, endTag, name: placeholder.name });
        i = placeholder.end + endTag.length;
        textStart = i;
        continue;
      }
      segments.push(...tag.segments);
      i = end;
      textStart = i;
      continue;
    }
    segments.push({ kind: 'literal', text: template.slice(i, end) });
    i = end;
    textStart = i;
  }
  flushText(template.length);
  return segments;
}

/**
 * Render a SAML XML template, replacing `{Tag}` placeholders with values.
 *
 * Every placeholder is classified by its position in the markup, and the
 * template is rendered in a single pass:
 *
 * - A placeholder is only accepted inside an attribute value or in text.
 *   One in an element or attribute name, an end tag, a comment, a CDATA
 *   section or a processing instruction throws
 *   `ERR_TEMPLATE_PLACEHOLDER_POSITION`.
 * - Values are XML-escaped and inserted as data; inserted text is never
 *   scanned for further placeholders, so a value cannot add markup or fill
 *   in another tag.
 * - A `null` / `undefined` value omits the attribute when the placeholder is
 *   the attribute's whole value, omits the element when the placeholder is
 *   its only content, and is empty otherwise.
 * - Placeholders without a value are left in place.
 *
 * For valid templates the output is identical to `replaceTagsByValue`.
 * `{` and `}` in values are written as character references.
 *
 * @param template XML template (a document or a fragment)
 * @param values placeholder values keyed by tag name
 * @returns rendered XML
 */
export function renderTemplate(template: string, values: TemplateValues): string {
  const lookup = lookupFor(values);
  const keyOf = (name: string) => lookup.get(name);
  const isOmitted = (key: string) => values[key] === null || values[key] === undefined;

  const render = (segments: Segment[]): string => segments.map(segment => {
    switch (segment.kind) {
      case 'literal':
        return segment.text;
      case 'placeholder': {
        const key = keyOf(segment.name);
        if (key === undefined) {
          return `{${segment.name}}`;
        }
        return isOmitted(key) ? '' : escapeXmlValue(String(values[key]));
      }
      case 'optional-attribute': {
        const key = keyOf(segment.name);
        if (key === undefined) {
          return segment.text;
        }
        if (isOmitted(key)) {
          return '';
        }
        const placeholder = `{${segment.name}}`;
        const at = segment.text.lastIndexOf(placeholder);
        return segment.text.slice(0, at) + escapeXmlValue(String(values[key])) + segment.text.slice(at + placeholder.length);
      }
      case 'optional-element': {
        const key = keyOf(segment.name);
        if (key !== undefined && isOmitted(key)) {
          return '';
        }
        const body = key === undefined ? `{${segment.name}}` : escapeXmlValue(String(values[key]));
        return render(segment.startTag) + body + segment.endTag;
      }
    }
  }).join('');

  return render(tokenize(template));
}
