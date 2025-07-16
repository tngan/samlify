import {getContext} from "./api.js";
import {select} from "xpath";
import {SignedXml} from "xml-crypto";
import fs from "fs";
import utility, {flattenDeep} from "./utility.js";
import libsaml, {SignatureVerifierOptions} from "./libsaml.js";
import {wording} from "./urn.js";
import {DOMParser} from '@xmldom/xmldom';

const certUse = wording.certUse;

const docParser = new DOMParser();

async function verifyAndDecryptSoapMessage(xml, opts: SignatureVerifierOptions){
    const {dom} = getContext();
    const doc = dom.parseFromString(xml, 'application/xml');
    const docParser = new DOMParser();
    let type = ''
    // 为 SOAP 消息定义 XPath
    const artifactResolveXpath = "/*[local-name()='Envelope']/*[local-name()='Body']/*[local-name()='ArtifactResolve']";
    const artifactResponseXpath = "/*[local-name()='Envelope']/*[local-name()='Body']/*[local-name()='ArtifactResponse']";

    // 检测 ArtifactResolve 或 ArtifactResponse 的存在
    // @ts-expect-error
    const artifactResolveNodes = select(artifactResolveXpath, doc);
    // @ts-expect-error
    const artifactResponseNodes = select(artifactResponseXpath, doc);

    // 根据消息类型选择合适的 XPath
    let basePath = "";
    if (artifactResolveNodes?.length > 0) {
        type = 'artifactResolve'
        basePath = "/*[local-name()='Envelope']/*[local-name()='Body']/*[local-name()='ArtifactResolve']";
    } else if (artifactResponseNodes?.length > 0) {
        type = 'artifactResponse'
        basePath = "/*[local-name()='Envelope']/*[local-name()='Body']/*[local-name()='ArtifactResponse']";
    } else {
        throw new Error('ERR_UNSUPPORTED_SOAP_MESSAGE_TYPE');
    }

    // 基于 SOAP 结构重新定义 XPath
    const messageSignatureXpath = `${basePath}/*[local-name(.)='Signature']`;

    // @ts-expect-error
    const messageSignatureNode = select(messageSignatureXpath, doc);


    let selection: any[] = [];

    if (messageSignatureNode?.length > 0) {
        selection = selection.concat(messageSignatureNode);
    }
    if (selection.length === 0) {
        throw new Error('ERR_ZERO_SIGNATURE');
    }
    return verifySignature(xml, selection, opts)

}

function verifySignature(xml, selection, opts) {
    // 尝试所有签名节点
    for (const signatureNode of selection) {
        const sig = new SignedXml();
        let verified = false;

        sig.signatureAlgorithm = opts.signatureAlgorithm!;
        if (!opts.keyFile && !opts.metadata) {
            throw new Error('ERR_UNDEFINED_SIGNATURE_VERIFIER_OPTIONS');
        }

        if (opts.keyFile) {
            sig.publicCert = fs.readFileSync(opts.keyFile);
        }

        if (opts.metadata) {
            const certificateNode = select(".//*[local-name(.)='X509Certificate']", signatureNode) as any;

            // 证书处理逻辑
            let metadataCert: any = opts.metadata.getX509Certificate(certUse.signing);
            if (Array.isArray(metadataCert)) {
                metadataCert = flattenDeep(metadataCert);
            } else if (typeof metadataCert === 'string') {
                metadataCert = [metadataCert];
            }
            metadataCert = metadataCert.map(utility.normalizeCerString);

            // 没有证书的情况
            if (certificateNode.length === 0 && metadataCert.length === 0) {
                throw new Error('NO_SELECTED_CERTIFICATE');
            }

            if (certificateNode.length !== 0) {
                const x509CertificateData = certificateNode[0].firstChild.data;
                const x509Certificate = utility.normalizeCerString(x509CertificateData);

                if (metadataCert.length >= 1 && !metadataCert.includes(x509Certificate)) {
                    throw new Error('ERROR_UNMATCH_CERTIFICATE_DECLARATION_IN_METADATA');
                }

                sig.publicCert = libsaml.getKeyInfo(x509Certificate).getKey();
            } else {
                sig.publicCert = libsaml.getKeyInfo(metadataCert[0]).getKey();
            }
        }

        sig.loadSignature(signatureNode);
        verified = sig.checkSignature(xml); // 使用原始XML验证

        if (!verified) {
            throw new Error('ERR_FAILED_TO_VERIFY_SIGNATURE');
        }

        if (sig.getSignedReferences().length < 1) {
            throw new Error('NO_SIGNATURE_REFERENCES');
        }
        const signedVerifiedXML = sig.getSignedReferences()[0];
        const rootNode = docParser.parseFromString(signedVerifiedXML, 'application/xml').documentElement;

        // 处理签名的内容
        switch (rootNode?.localName) {

            case 'ArtifactResolve':
                return [true, rootNode.toString(), false, false];
            case 'ArtifactResponse':
                // @ts-expect-error
                const Response = select("/*[local-name()='ArtifactResponse']/*[local-name()='Response']", rootNode);
                return [true, Response?.[0].toString(), false, false]; // 签名验证成功但未找到断言

            default:
                return [true, null, false, true]; // 签名验证成功但未找到可识别的内容
        }
    }
    return [false, null, false, true]
}

export default {
    verifyAndDecryptSoapMessage
}
