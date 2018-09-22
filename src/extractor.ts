import { DOMParser } from 'xmldom';
import { select } from 'xpath';
import { zipObject, camelCase, last } from 'lodash';
const dom = DOMParser;

function buildAbsoluteXPath(paths) {
  return paths.reduce((currentPath, name) => {
    let appendedPath = currentPath;
    const isWildcard = name.startsWith('~');
    if (isWildcard) {
      const pathName = name.replace('~', '');
      appendedPath = currentPath + `/*[contains(local-name(), '${pathName}')]`;
    }
    if (!isWildcard) {
      appendedPath = currentPath + `/*[local-name(.)='${name}']`;
    }
    return appendedPath;
  }, '');
}

function buildAttributeXPath(attributes) {
  if (attributes.length === 0) {
    return '/text()';
  }
  if (attributes.length === 1) {
    return `/@${attributes[0]}`;
  }
  const filters = attributes.map(attribute => `name()='${attribute}'`).join(' or ');
  return `/@*[${filters}]`;
}

/**
 * @desc High-level XML extractor
 * @param  {string} context 
 * @param  {object} fields
 */
export function extract(context: string, fields) {

  const doc = new dom().parseFromString(context);

  return fields.reduce((result: any, field) => {
    // get essential fields
    const key = field.key;
    const localPath = field.localPath;
    const attributes = field.attributes;
    const isEntire = field.context;
    // get optional fields
    const index = field.index;
    const attributePath = field.attributePath;

    console.log(field);

    // special case: multiple path
    /*
      {
        key: 'issuer',
        localPath: [
          ['Response', 'Issuer'],
          ['Response', 'Assertion', 'Issuer']
        ],
        attributes: []
      }
     */
    if (localPath.every(path => Array.isArray(path))) {
      const multiXPaths = localPath
        .map(path => {
          // not support attribute yet, so ignore it
          return `${buildAbsoluteXPath(path)}/text()`;
        })
        .join(' | ');

      return {
        ...result,
        [key]: select(multiXPaths, doc).map(n => n.nodeValue)
      };
    }
    // eo special case: multiple path

    const baseXPath = buildAbsoluteXPath(localPath);
    const attributeXPath = buildAttributeXPath(attributes);

    // special case: get attributes where some are in child, some are in parent
    /*
      {
        key: 'attributes',
        localPath: ['Response', 'Assertion', 'AttributeStatement', 'Attribute'],
        index: ['Name'],
        attributePath: ['AttributeValue'],
        attributes: []
      } 
    */
    if (index && attributePath) {
      // find the index in localpath
      const indexPath = buildAttributeXPath(index);
      const fullLocalXPath = `${baseXPath}${indexPath}`;
      const parentNodes = select(baseXPath, doc);
      // [uid, mail, edupersonaffiliation], ready for aggregate
      const parentAttributes = select(fullLocalXPath, doc).map(n => n.value);
      // [attribute, attributevalue]
      const childXPath = buildAbsoluteXPath([last(localPath)].concat(attributePath));
      const childAttributeXPath = buildAttributeXPath(attributes);
      const fullChildXPath = `${childXPath}${childAttributeXPath}`;
      // [ 'test', 'test@example.com', [ 'users', 'examplerole1' ] ]
      const childAttributes = parentNodes.map(node => {
        const nodeDoc = new dom().parseFromString(node.toString());
        if (attributes.length === 0) {
          const childValues = select(fullChildXPath, nodeDoc).map(n => n.nodeValue);
          if (childValues.length === 1) {
            return childValues[0];
          }
          return childValues;
        }
        if (attributes.length > 0) {
          const childValues = select(fullChildXPath, nodeDoc).map(n => n.value);
          if (childValues.length === 1) {
            return childValues[0];
          }
          return childValues;
        }
        return null;
      });
      // aggregation
      const obj = zipObject(parentAttributes, childAttributes);
      return {
        ...result,
        [key]: obj
      };
    }
    // case: fetch entire content, only allow one existence
    /*
      {
        key: 'signature',
        localPath: ['AuthnRequest', 'Signature'],
        attributes: [],
        context: true
      }
    */
    if (isEntire) {
      const node = select(baseXPath, doc);
      return {
        ...result,
        [key]: node.length === 1 ? node[0].toString() : null
      };
    }
    // case: multiple attribute
    /*
      {
        key: 'nameIDPolicy',
        localPath: ['AuthnRequest', 'NameIDPolicy'],
        attributes: ['Format', 'AllowCreate']
      }
    */
    if (attributes.length > 1) {
      const fullPath = `${baseXPath}${attributeXPath}`;
      const attributeValues = select(fullPath, doc).map(n => n.value);
      return {
        ...result,
        [key]: zipObject(attributes.map(a => camelCase(a)), attributeValues)
      };
    }
    // case: single attribute
    /*
      {
        key: 'statusCode',
        localPath: ['Response', 'Status', 'StatusCode'],
        attributes: ['Value'],
      }
    */
    if (attributes.length === 1) {
      const fullPath = `${baseXPath}${attributeXPath}`;
      const attributeValues = select(fullPath, doc).map(n => n.value);
      return {
        ...result,
        [key]: attributeValues[0]
      };
    }
    // case: zero attribute
    /*
      {
        key: 'issuer',
        localPath: ['AuthnRequest', 'Issuer'],
        attributes: []
      }
    */
    if (attributes.length === 0) {
      const fullPath = `string(${baseXPath}${attributeXPath})`;
      const attributeValue = select(fullPath, doc);
      return {
        ...result,
        [key]: attributeValue
      };
    }

    return result;
  }, {});

}
