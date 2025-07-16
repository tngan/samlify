import axios from 'axios';
import https from 'node:https';
import crypto from "node:crypto";
import {Builder} from 'xml2js'
import iconv from 'iconv-lite'
import {IdentityProviderConstructor as IdentityProvider, ServiceProviderConstructor as ServiceProvider} from "./types.js";
// 2. 配置 Axios 实例（处理自签名证书）
const axiosInstance = axios.create({
    httpsAgent: new https.Agent({
        rejectUnauthorized: false // 允许自签名证书
    })
});
export async function sendArtifactResolve(url:string,soapRequest:any) {
    try {
        const response = await axiosInstance.post(
            url,
            soapRequest,
            {
                headers: {
                    'Content-Type': 'text/xml',
                    'SOAPAction': '"ArtifactResolve"'
                },
                timeout: 5000 // 5秒超时
            }
        );

        return response.data;
    } catch (error) {
        throw error.response.data;
    }
}

export async function sendArtifactResponse(url:string,soapRequest:any) {
    try {
        const response = await axiosInstance.post(
            url,
            soapRequest,
            {
                headers: {
                    'Content-Type': 'text/xml',
                    'SOAPAction': '"ArtifactResponse"'
                },
                timeout: 5000 // 5秒超时
            }
        );

        return response.data;
    } catch (error) {
        throw error.response.data;
    }
}
/**
 * @desc   generate Art id
 *
 * @param entityIDString
 * @param endpointIndex
 */
export function createArt(
    entityIDString: string | IdentityProvider | ServiceProvider,
    endpointIndex = 0
) {
    // 安全获取 sourceEntityId
    let sourceEntityId: string;
    if (typeof entityIDString === "string") {
        sourceEntityId = entityIDString;
    } else {
        // 确保只在非字符串类型上访问 entityMeta
        sourceEntityId = entityIDString.entityMeta.getEntityID();
    }

    // 1. 固定类型代码 (0x0004 - 2字节)
    const typeCode = Buffer.from([0x00, 0x04]);

    // 2. 端点索引 (2字节，大端序)
    if (endpointIndex < 0 || endpointIndex > 65535) {
        throw new Error("Endpoint index must be between 0 and 65535");
    }
    const endpointBuf = Buffer.alloc(2);
    endpointBuf.writeUInt16BE(endpointIndex);

    // 3. Source ID - 实体ID的SHA-1哈希 (20字节)
    const sourceId = crypto
        .createHash("sha1")
        .update(sourceEntityId)
        .digest();

    // 4. Message Handler - 20字节随机值
    const messageHandler = crypto.randomBytes(20);

    // 组合所有组件 (2+2+20+20 = 44字节)
    const artifact = Buffer.concat([
        typeCode,
        endpointBuf,
        sourceId,
        messageHandler,
    ]);

    // 返回Base64编码的Artifact
    return {
        artifact: artifact.toString("base64"),
        origin: {
            typeCode: typeCode.readUInt16BE(0), // 改为整数值
            endpointIndex: endpointIndex, // 修复字段名并赋正确的值
            sourceId: sourceId.toString("hex"), // 转为十六进制
            messageHandle: messageHandler.toString("hex"), // 转为十六进制
        },
    };
}

/**
 * @desc   generate Art id
 * @param artifact
 */
export function parseArt(artifact: string) {
    // 解码 Base64
    console.log(Object.prototype.toString.call(artifact))
    if(Object.prototype.toString.call(artifact) !== '[object String]'){
        return
    }
    const decoded = Buffer.from(artifact, 'base64');

    // 确保长度正确（SAML 工件固定为 44 字节）
    if (decoded.length !== 44) {
        throw new Error(`Invalid artifact length: ${decoded.length}, expected 44 bytes`);
    }

    // 读取前 4 字节（TypeCode + EndpointIndex）
    const typeCode = decoded.readUInt16BE(0);
    const endpointIndex = decoded.readUInt16BE(2);

    // 使用 Buffer.from() 替代 slice()
    const sourceId = Buffer.from(
        decoded.buffer,         // 底层 ArrayBuffer
        decoded.byteOffset + 4, // 起始偏移量
        20                     // 长度
    ).toString('hex');

    const messageHandle = Buffer.from(
        decoded.buffer,          // 底层 ArrayBuffer
        decoded.byteOffset + 24,  // 起始偏移量
        20                       // 长度
    ).toString('hex');

    return {typeCode, endpointIndex, sourceId, messageHandle};
}

/**
* 将对象转换为 ISO-8859-1 编码的 XML 字符串
* @param {Object} data - 要转换的数据对象
* @returns {Buffer} - ISO-8859-1 编码的 XML 数据 (Buffer)
*/
export  function encodeXmlToIso88591(data) {
    try {
        // 1. 创建 XML 构建器
        const builder = new Builder({
            headless: false,  // 包含 XML 声明
            renderOpts: { 'pretty': false }, // 紧凑格式
            xmldec: {
                version: '1.0',
                encoding: 'ISO-8859-1',
                standalone: true
            }
        });

        // 2. 构建 XML 字符串 (UTF-8 格式)
        const utf8Xml = builder.buildObject(data);

        // 3. 转换为 ISO-8859-1 编码的 Buffer
        return iconv.encode(utf8Xml, 'iso-8859-1');
    } catch (error) {
        throw new Error(`XML 编码失败: ${error.message}`);
    }
}
