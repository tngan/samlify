/**
 * @file xml.ts
 * @author tngan
 * @desc Internal helper for parsing XML with the module-wide DOM parser.
 */
import { getContext } from './api';

/**
 * Parse an XML string with the parser configured in the runtime context.
 *
 * xmldom 0.9 requires an explicit MIME type and ships node types that are
 * independent of `lib.dom`; xpath and xml-crypto are typed against the
 * `lib.dom` interfaces, so the result is cast once here. This module is not
 * referenced by any public declaration, keeping `lib.dom` out of consumers'
 * programs.
 *
 * @param xml XML string
 * @returns parsed document
 */
export function parseXml(xml: string): Document {
  return getContext().dom.parseFromString(xml, 'text/xml') as unknown as Document;
}
