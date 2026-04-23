/**
 * @file extractor.ts
 * @author tngan
 * @desc Declarative XPath extractor for SAML messages. Defines the field
 * catalogs (login/logout request & response) and a generic `extract` that
 * evaluates them against an XML document.
 */
import { select, SelectedValue, SelectReturnType } from 'xpath';
import { uniq, last, zipObject, notEmpty, escapeXPathValue, camelCase } from './utility';
import { getContext } from './api';
import type { ExtractorField, ExtractorFields, ExtractorResult, ExtractorValue } from './types';

export type { ExtractorField, ExtractorFields, ExtractorResult } from './types';

/**
 * Coerce the heterogeneous return type of `xpath.select` into a Node array.
 */
function toNodeArray(result: SelectReturnType): Node[] {
  if (Array.isArray(result)) return result;
  if (result != null && typeof result === 'object' && 'nodeType' in (result as object)) {
    return [result as Node];
  }
  return [];
}

/**
 * Build an absolute XPath expression from a list of local-name segments.
 * A segment prefixed with `~` matches any element whose local-name contains
 * the remaining text (case-sensitive substring).
 */
function buildAbsoluteXPath(paths: string[]): string {
  return paths.reduce<string>((currentPath, name) => {
    const isWildcard = name.startsWith('~');
    if (isWildcard) {
      const pathName = name.replace('~', '');
      return currentPath + `/*[contains(local-name(), ${escapeXPathValue(pathName)})]`;
    }
    return currentPath + `/*[local-name(.)=${escapeXPathValue(name)}]`;
  }, '');
}

/**
 * Append an attribute selector to an XPath. Zero attributes select text
 * content; one attribute selects that attribute; multiple attributes use an
 * `or` filter.
 */
function buildAttributeXPath(attributes: string[]): string {
  if (attributes.length === 0) {
    return '/text()';
  }
  if (attributes.length === 1) {
    return `/@${attributes[0]}`;
  }
  const filters = attributes.map(attribute => `name()=${escapeXPathValue(attribute)}`).join(' or ');
  return `/@*[${filters}]`;
}

/** Default extractor fields for an inbound `AuthnRequest` (login request). */
export const loginRequestFields: ExtractorFields = [
  {
    key: 'request',
    localPath: ['AuthnRequest'],
    attributes: ['ID', 'IssueInstant', 'Destination', 'AssertionConsumerServiceURL'],
  },
  {
    key: 'issuer',
    localPath: ['AuthnRequest', 'Issuer'],
    attributes: [],
  },
  {
    key: 'nameIDPolicy',
    localPath: ['AuthnRequest', 'NameIDPolicy'],
    attributes: ['Format', 'AllowCreate'],
  },
  {
    key: 'authnContextClassRef',
    localPath: ['AuthnRequest', 'AuthnContextClassRef'],
    attributes: [],
  },
  {
    key: 'signature',
    localPath: ['AuthnRequest', 'Signature'],
    attributes: [],
    context: true,
  },
];

/** Two-tier status code extractor for login responses. */
export const loginResponseStatusFields: ExtractorFields = [
  {
    key: 'top',
    localPath: ['Response', 'Status', 'StatusCode'],
    attributes: ['Value'],
  },
  {
    key: 'second',
    localPath: ['Response', 'Status', 'StatusCode', 'StatusCode'],
    attributes: ['Value'],
  },
];

/** Two-tier status code extractor for logout responses. */
export const logoutResponseStatusFields: ExtractorFields = [
  {
    key: 'top',
    localPath: ['LogoutResponse', 'Status', 'StatusCode'],
    attributes: ['Value'],
  },
  {
    key: 'second',
    localPath: ['LogoutResponse', 'Status', 'StatusCode', 'StatusCode'],
    attributes: ['Value'],
  },
];

/**
 * Build the login-response extractor bound to a particular assertion XML.
 * Assertion-scoped fields are re-rooted at the assertion fragment via the
 * `shortcut` mechanism so that wrapping attacks can't redirect extraction.
 *
 * @param assertion XML string of the (verified) assertion node
 * @returns extractor fields ready for `extract`
 */
export const loginResponseFields: (assertion: string) => ExtractorFields = assertion => [
  {
    key: 'conditions',
    localPath: ['Assertion', 'Conditions'],
    attributes: ['NotBefore', 'NotOnOrAfter'],
    shortcut: assertion,
  },
  {
    key: 'response',
    localPath: ['Response'],
    attributes: ['ID', 'IssueInstant', 'Destination', 'InResponseTo'],
  },
  {
    key: 'audience',
    localPath: ['Assertion', 'Conditions', 'AudienceRestriction', 'Audience'],
    attributes: [],
    shortcut: assertion,
  },
  {
    key: 'issuer',
    localPath: ['Assertion', 'Issuer'],
    attributes: [],
    shortcut: assertion,
  },
  {
    key: 'nameID',
    localPath: ['Assertion', 'Subject', 'NameID'],
    attributes: [],
    shortcut: assertion,
  },
  {
    key: 'sessionIndex',
    localPath: ['Assertion', 'AuthnStatement'],
    attributes: ['AuthnInstant', 'SessionNotOnOrAfter', 'SessionIndex'],
    shortcut: assertion,
  },
  {
    key: 'attributes',
    localPath: ['Assertion', 'AttributeStatement', 'Attribute'],
    index: ['Name'],
    attributePath: ['AttributeValue'],
    attributes: [],
    shortcut: assertion,
  },
];

/** Default extractor fields for an inbound `LogoutRequest`. */
export const logoutRequestFields: ExtractorFields = [
  {
    key: 'request',
    localPath: ['LogoutRequest'],
    attributes: ['ID', 'IssueInstant', 'Destination'],
  },
  {
    key: 'issuer',
    localPath: ['LogoutRequest', 'Issuer'],
    attributes: [],
  },
  {
    key: 'nameID',
    localPath: ['LogoutRequest', 'NameID'],
    attributes: [],
  },
  {
    key: 'sessionIndex',
    localPath: ['LogoutRequest', 'SessionIndex'],
    attributes: [],
  },
  {
    key: 'signature',
    localPath: ['LogoutRequest', 'Signature'],
    attributes: [],
    context: true,
  },
];

/** Default extractor fields for an inbound `LogoutResponse`. */
export const logoutResponseFields: ExtractorFields = [
  {
    key: 'response',
    localPath: ['LogoutResponse'],
    attributes: ['ID', 'Destination', 'InResponseTo'],
  },
  {
    key: 'issuer',
    localPath: ['LogoutResponse', 'Issuer'],
    attributes: [],
  },
  {
    key: 'signature',
    localPath: ['LogoutResponse', 'Signature'],
    attributes: [],
    context: true,
  },
];

/**
 * Evaluate the given extractor fields against an XML document and return
 * a flat object keyed by `field.key`. Handles:
 *   - multi-path localPaths (`string[][]`) collected with `|`
 *   - parent/child attribute aggregation (`index` + `attributePath`)
 *   - whole-subtree extraction (`context: true`)
 *   - single/multiple/zero-attribute text extraction
 *
 * @param context XML string to parse
 * @param fields extractor field definitions
 * @returns extracted SAML values keyed by field name
 */
export function extract(context: string, fields: ExtractorField[]): ExtractorResult {
  const { dom } = getContext();
  const rootDoc = dom.parseFromString(context);

  return fields.reduce<ExtractorResult>((result, field) => {
    const { key, localPath, attributes, context: isEntire, shortcut, index, attributePath } = field;

    let targetDoc = rootDoc;
    if (shortcut) {
      targetDoc = dom.parseFromString(shortcut);
    }

    // Multi-path union: each entry is a separate localPath whose text()
    // values are merged.
    if (localPath.every(path => Array.isArray(path))) {
      const multiXPaths = (localPath as string[][])
        .map(path => `${buildAbsoluteXPath(path)}/text()`)
        .join(' | ');

      result[key] = uniq(
        toNodeArray(select(multiXPaths, targetDoc))
          .map((n: Node) => n.nodeValue)
          .filter(notEmpty),
      );
      return result;
    }

    const baseXPath = buildAbsoluteXPath(localPath as string[]);
    const attributeXPath = buildAttributeXPath(attributes);

    // Parent/child aggregation (e.g. SAML Attribute → AttributeValue).
    if (index && attributePath) {
      const indexPath = buildAttributeXPath(index);
      const fullLocalXPath = `${baseXPath}${indexPath}`;
      const parentNodes = toNodeArray(select(baseXPath, targetDoc));
      const parentAttributes = toNodeArray(select(fullLocalXPath, targetDoc)).map((n: Attr) => n.value);
      const childXPath = buildAbsoluteXPath([last(localPath as string[])].concat(attributePath));
      const childAttributeXPath = buildAttributeXPath(attributes);
      const fullChildXPath = `${childXPath}${childAttributeXPath}`;

      const childAttributes = parentNodes.map(node => {
        const nodeDoc = dom.parseFromString(node.toString());
        if (attributes.length === 0) {
          const childValues = toNodeArray(select(fullChildXPath, nodeDoc)).map((n: Node) => n.nodeValue);
          return childValues.length === 1 ? childValues[0] : childValues;
        }
        if (attributes.length > 0) {
          const childValues = toNodeArray(select(fullChildXPath, nodeDoc)).map((n: Attr) => n.value);
          return childValues.length === 1 ? childValues[0] : childValues;
        }
        return null;
      });

      result[key] = zipObject(parentAttributes, childAttributes as (string | string[] | null)[], false) as ExtractorValue;
      return result;
    }

    // Whole-subtree capture.
    if (isEntire) {
      const nodes = toNodeArray(select(baseXPath, targetDoc));
      let value: ExtractorValue = null;
      if (nodes.length === 1) {
        value = nodes[0].toString();
      } else if (nodes.length > 1) {
        value = nodes.map(n => n.toString());
      }
      result[key] = value;
      return result;
    }

    // Multi-attribute capture: produce one record per parent node.
    if (attributes.length > 1) {
      const baseNode = toNodeArray(select(baseXPath, targetDoc)).map(n => n.toString());
      const childXPath = `${buildAbsoluteXPath([last(localPath as string[])])}${attributeXPath}`;
      const attributeValues = baseNode.map((node: string) => {
        const nodeDoc = dom.parseFromString(node);
        return toNodeArray(select(childXPath, nodeDoc)).reduce<Record<string, string>>((r, n: Attr) => {
          r[camelCase(n.name)] = n.value;
          return r;
        }, {});
      });
      result[key] = (attributeValues.length === 1 ? attributeValues[0] : attributeValues) as ExtractorValue;
      return result;
    }

    // Single-attribute capture.
    if (attributes.length === 1) {
      const fullPath = `${baseXPath}${attributeXPath}`;
      const attributeValues = toNodeArray(select(fullPath, targetDoc)).map((n: Attr) => n.value);
      result[key] = attributeValues[0];
      return result;
    }

    // Zero-attribute capture: element text content.
    if (attributes.length === 0) {
      let attributeValue: SelectedValue[] | (string | null)[] | string | null = null;
      const nodes = toNodeArray(select(baseXPath, targetDoc));
      if (nodes.length === 1) {
        const fullPath = `string(${baseXPath}${attributeXPath})`;
        const strResult = select(fullPath, targetDoc);
        attributeValue =
          typeof strResult === 'string'
            ? strResult
            : strResult === null
              ? null
              : Array.isArray(strResult)
                ? strResult
                : null;
      }
      if (nodes.length > 1) {
        attributeValue = nodes
          .filter((n: Node) => n.firstChild)
          .map((n: Node) => n.firstChild!.nodeValue);
      }
      result[key] = attributeValue as ExtractorValue;
      return result;
    }

    return result;
  }, {} as ExtractorResult);
}
