import {validateXML} from 'xmllint-wasm';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {fileURLToPath} from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
let obj =[
    'soap-envelope.xsd',
    'xml.xsd',
    'saml-schema-protocol-2.0.xsd',
    'saml-schema-assertion-2.0.xsd',
    'xmldsig-core-schema.xsd',
    'xenc-schema.xsd',
    'saml-schema-metadata-2.0.xsd',
    'saml-schema-ecp-2.0.xsd',
    'saml-schema-dce-2.0.xsd'
]
let normal = [
    'soap-envelope.xsd',
    'xml.xsd',

    // 2. SOAP核心模式（所有SOAP消息的基础）


    // 3. XML签名模式（SAML签名的前置依赖）
    'xmldsig-core-schema.xsd',

    // 4. XML加密模式（SAML断言加密的前置依赖）
    'xenc-schema.xsd',

    // 5. SAML核心模式（最基础的SAML组件）
    'saml-schema-assertion-2.0.xsd', // 断言定义

    // 6. SAML协议模式（依赖断言模式）
    'saml-schema-protocol-2.0.xsd',

    // 7. SAML扩展模式（依赖核心模式）
    'saml-schema-metadata-2.0.xsd', // 元数据
    'saml-schema-ecp-2.0.xsd', // ECP扩展
    'saml-schema-dce-2.0.xsd'  // DCE扩展

]
const schemas = obj;

function detectXXEIndicators(samlString: string) {
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
    const [xmlParse, ...preload] = await Promise.all(schemas.map(async file => ({
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
            schema: [xmlParse],
            preload: [xmlParse, ...preload],
        });

        if (validationResult.valid) {
            console.log("---------------------验证通过--------------------")
            console.log("---------------------验证通过--------------------")
            return true;
        }
        console.log('-----------------------没验证通过-----------------------')
        console.debug(validationResult);
        throw validationResult.errors;

    } catch (error) {
        console.log('-----------------------没验证通过error-----------------------')
        console.error('[ERROR] validateXML', error);
        throw new Error('ERR_EXCEPTION_VALIDATE_XML');

    }

};
