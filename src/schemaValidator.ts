import { validateXML } from 'xmllint-wasm';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {fileURLToPath} from 'node:url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const schemas = [
  'saml-schema-protocol-2.0.xsd',
  'datatypes.dtd',
  'saml-schema-assertion-2.0.xsd',
  'xmldsig-core-schema.xsd',
  'XMLSchema.dtd',
  'xenc-schema.xsd',
  'saml-schema-metadata-2.0.xsd',
  'saml-schema-ecp-2.0.xsd',
  'saml-schema-dce-2.0.xsd'
];
function detectXXEIndicators(samlString:string) {
  const xxePatterns = [
    /<!DOCTYPE\s[^>]*>/i,
    /<!ENTITY\s+[^\s>]+\s+(?:SYSTEM|PUBLIC)\s+['"][^>]*>/i,
    /&[a-zA-Z0-9._-]+;/g,
    /SYSTEM\s*=/i,
    /PUBLIC\s*=/i,
    /file:\/\//,
    /\.dtd['"]?/
  ];

  const matches = {};
  xxePatterns.forEach((pattern, index) => {
    const found = samlString.match(pattern);
    if (found) {
      matches[`pattern_${index}`] = {
        pattern: pattern.toString(),
        matches: found
      };
    }
  });

  return Object.keys(matches).length > 0 ? matches : null;
}
export const validate = async (xml: string) => {
  const indicators = detectXXEIndicators(xml);
  if (indicators) {
    console.error('XXE风险特征:', indicators);
    throw new Error('ERR_EXCEPTION_VALIDATE_XML');
  }

  const schemaPath = path.resolve(__dirname, 'schema');
  const [schema, ...preload] = await Promise.all(schemas.map(async file => ({
    fileName: file,
    contents: await fs.promises.readFile(`${schemaPath}/${file}`, 'utf-8')
  })))
  try {
    const validationResult = await validateXML({
      xml: [
        {
          fileName: 'content.xml',
          contents: xml,
        },
      ],
      extension: 'schema',
      schema: [schema.contents],
      preload: preload
    });

    if (validationResult.valid) {
      return true;
    }

    console.debug(validationResult);
    throw validationResult.errors;

  } catch (error) {

    console.error('[ERROR] validateXML', error);
    throw new Error('ERR_EXCEPTION_VALIDATE_XML');

  }

};
