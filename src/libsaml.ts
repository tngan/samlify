/**
 * @file SamlLib.js
 * @author tngan
 * @desc  A simple library including some common functions
 */

import camelCase from 'camelcase';
import nrsa from 'node-rsa';
import { FileKeyInfo, SignedXml } from 'xml-crypto';
import xmlenc from 'xml-encryption';
import { DOMParser } from 'xmldom';
import { select } from 'xpath';
import { getContext } from './api';
import type { Entity } from './entity';
import { SamlifyError, SamlifyErrorCode } from './error';
import { extract, isNode } from './extractor';
import type { Metadata } from './metadata';
import { algorithms, names, wording } from './urn';
import {
	base64Encode,
	flattenDeep,
	getPublicKeyPemFromCertificate,
	isNonEmptyArray,
	isString,
	normalizeCerString,
	readPrivateKey,
} from './utility';

export type { EncryptionAlgorithm, KeyEncryptionAlgorithm } from 'xml-encryption';

export type RequestSignatureAlgorithm =
	| 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
	| 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
	| 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';

export type SignatureConfig = Parameters<SignedXml['computeSignature']>[1];

export interface SAMLDocumentTemplate {
	context?: string;
}
export interface LoginResponseAttribute {
	name: string;
	nameFormat: string;
	valueXsiType: string;
	valueTag: string;
	valueXmlnsXs?: string;
	valueXmlnsXsi?: string;
}
export interface LoginResponseTemplate extends Required<SAMLDocumentTemplate> {
	attributes?: LoginResponseAttribute[];
}
export type LoginRequestTemplate = Required<SAMLDocumentTemplate>;

export type LogoutRequestTemplate = Required<SAMLDocumentTemplate>;

export type LogoutResponseTemplate = Required<SAMLDocumentTemplate>;

export interface CustomTagReplacement<
	Values extends Record<string, number | string> = Record<string, number | string>
> {
	(template: string, values: Values): readonly [template?: string, values?: Values];
}

const signatureAlgorithms = algorithms.signature;
const digestAlgorithms = algorithms.digest;
const certUse = wording.certUse;
const urlParams = wording.urlParams;
const dom = DOMParser;

// class MyFileKeyInfo extends FileKeyInfo {
// 	constructor(private _getKey: () => Buffer) {
// 		super();
// 	}
// 	getKey(): Buffer {
// 		return this._getKey();
// 	}
// 	getKeyInfo(key = '', prefix = '') {
// 		return `<${prefix}X509Data><${prefix}X509Certificate>${key}</${prefix}X509Certificate></${prefix}X509Data>`;
// 	}
// }

interface SignatureConstructor {
	rawSamlMessage: string;
	referenceTagXPath?: string;
	privateKey: string;
	privateKeyPass?: string;
	signatureAlgorithm?: RequestSignatureAlgorithm;
	signingCert: string | Buffer;
	isBase64Output?: boolean;
	signatureConfig?: SignatureConfig;
	isMessageSigned?: boolean;
	transformationAlgorithms?: string[];
}

interface SignatureVerifierOptions {
	metadata?: Metadata;
	keyFile?: string;
	signatureAlgorithm?: RequestSignatureAlgorithm;
}

type KeyUse = 'signing' | 'encryption';

interface KeyComponent {
	[key: string]: any;
}

const libSaml = () => {
	/**
	 * @desc helper function to get back the query param for redirect binding for SLO/SSO
	 * @type {string}
	 */
	function getQueryParamByType(type: string) {
		if (([urlParams.logoutRequest, urlParams.samlRequest] as string[]).includes(type)) {
			return 'SAMLRequest';
		}
		if (([urlParams.logoutResponse, urlParams.samlResponse] as string[]).includes(type)) {
			return 'SAMLResponse';
		}
		throw new SamlifyError(SamlifyErrorCode.UndefinedQueryParams);
	}
	/**
	 *
	 */
	const nrsaAliasMapping = {
		[signatureAlgorithms.RSA_SHA1]: 'pkcs1-sha1',
		[signatureAlgorithms.RSA_SHA256]: 'pkcs1-sha256',
		[signatureAlgorithms.RSA_SHA512]: 'pkcs1-sha512',
	} as const;
	/**
	 *
	 */
	const defaultSignatureAlgorithm = signatureAlgorithms.RSA_SHA1;
	/**
	 * @desc Default login request template
	 * @type {LoginRequestTemplate}
	 */
	const defaultLoginRequestTemplate: LoginRequestTemplate = {
		context:
			'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="{AssertionConsumerServiceURL}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format="{NameIDFormat}" AllowCreate="{AllowCreate}"/></samlp:AuthnRequest>',
	} as const;
	/**
	 * @desc Default logout request template
	 * @type {LogoutRequestTemplate}
	 */
	const defaultLogoutRequestTemplate: LogoutRequestTemplate = {
		context:
			'<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}"><saml:Issuer>{Issuer}</saml:Issuer><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID></samlp:LogoutRequest>',
	};
	/**
	 * @desc Default login response template
	 * @type {LoginResponseTemplate}
	 */
	const defaultLoginResponseTemplate: LoginResponseTemplate = {
		context:
			'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status><saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}" InResponseTo="{InResponseTo}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{AuthnStatement}{AttributeStatement}</saml:Assertion></samlp:Response>',
	};
	/**
	 * @desc Default logout response template
	 * @type {LogoutResponseTemplate}
	 */
	const defaultLogoutResponseTemplate: LogoutResponseTemplate = {
		context:
			'<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="{StatusCode}"/></samlp:Status></samlp:LogoutResponse>',
	};
	/**
	 * @private
	 * @desc Get the signing scheme alias by signature algorithms, used by the node-rsa module
	 * @param {string} sigAlg    signature algorithm
	 * @return {string} signing algorithm short-hand for the module node-rsa
	 */
	function getSigningScheme(sigAlg?: RequestSignatureAlgorithm): nrsa.Options['signingScheme'] {
		if (sigAlg) {
			const algAlias = nrsaAliasMapping[sigAlg];
			if (algAlias != null) return algAlias;
		}
		return nrsaAliasMapping[defaultSignatureAlgorithm]; // default value
	}
	/**
	 * @private
	 * @desc Get the digest algorithms by signature algorithms
	 * @param {string} sigAlg    signature algorithm
	 * @return {string/null} digest algorithm
	 */
	function getDigestMethod(sigAlg: keyof typeof digestAlgorithms) {
		return digestAlgorithms[sigAlg];
	}
	/**
	 * @public
	 * @desc Create XPath
	 * @param  {string/object} local     parameters to create XPath
	 * @param  {boolean} isExtractAll    define whether returns whole content according to the XPath
	 * @return {string} xpath
	 */
	function createXPath(local: string | { name: string; attr: string }, isExtractAll?: boolean): string {
		if (isString(local)) {
			return isExtractAll === true ? "//*[local-name(.)='" + local + "']/text()" : "//*[local-name(.)='" + local + "']";
		}
		return "//*[local-name(.)='" + local.name + "']/@" + local.attr;
	}

	/**
	 * @private
	 * @desc Tag normalization
	 * @param {string} prefix     prefix of the tag
	 * @param {content} content   normalize it to capitalized camel case
	 * @return {string}
	 */
	function tagging(prefix: string, content: string): string {
		const camelContent = camelCase(content);
		return prefix + camelContent.charAt(0).toUpperCase() + camelContent.slice(1);
	}

	return {
		createXPath,
		getQueryParamByType,
		defaultSignatureAlgorithm,
		defaultLoginRequestTemplate,
		defaultLoginResponseTemplate,
		defaultLogoutRequestTemplate,
		defaultLogoutResponseTemplate,

		/**
		 * @desc Repalce the tag (e.g. {tag}) inside the raw XML
		 * @param  {string} rawXML                 raw XML string used to do keyword replacement
		 * @param  {Record<string, any>} tagValues tag values
		 * @return {string}
		 */
		replaceTagsByValue(rawXML: string, tagValues: Record<string, any>): string {
			Object.keys(tagValues).forEach((t) => {
				rawXML = rawXML.replace(new RegExp(`{${t}}`, 'g'), tagValues[t]); // eslint-disable-line
			});
			return rawXML;
		},
		/**
		 * @desc Helper function to build the AttributeStatement tag
		 * @param  {LoginResponseAttribute} attributes    an array of attribute configuration
		 * @return {string}
		 */
		attributeStatementBuilder(attributes: LoginResponseAttribute[]): string {
			const attr = attributes
				.map(({ name, nameFormat, valueTag, valueXsiType, valueXmlnsXs, valueXmlnsXsi }) => {
					const defaultValueXmlnsXs = 'http://www.w3.org/2001/XMLSchema';
					const defaultValueXmlnsXsi = 'http://www.w3.org/2001/XMLSchema-instance';
					return `<saml:Attribute Name="${name}" NameFormat="${nameFormat}"><saml:AttributeValue xmlns:xs="${
						valueXmlnsXs ? valueXmlnsXs : defaultValueXmlnsXs
					}" xmlns:xsi="${valueXmlnsXsi ? valueXmlnsXsi : defaultValueXmlnsXsi}" xsi:type="${valueXsiType}">{${tagging(
						'attr',
						valueTag
					)}}</saml:AttributeValue></saml:Attribute>`;
				})
				.join('');
			return `<saml:AttributeStatement>${attr}</saml:AttributeStatement>`;
		},
		/* @desc Helper function to build the AttributeStatement tag values
		 * @param  {LoginResponseAttribute} attributes    an array of attribute configuration
		 * @param  {any} user                             The user
		 * @return {any}
		 */
		attributeStatementTagBuilder(
			attributes: LoginResponseAttribute[],
			user: Record<string, string>
		): Record<string, string> {
			return attributes.reduce((r, { valueTag }) => {
				const key = tagging('attr', valueTag);
				const value = user[valueTag.replace('user.', '')];
				if (key != null && value != null) r[key] = value;
				return r;
			}, {} as Record<string, string>);
		},
		/**
		 * @desc Construct the XML signature for POST binding
		 * @param  {string} rawSamlMessage      request/response xml string
		 * @param  {string} referenceTagXPath    reference uri
		 * @param  {string} privateKey           declares the private key
		 * @param  {string} passphrase           passphrase of the private key [optional]
		 * @param  {string|buffer} signingCert   signing certificate
		 * @param  {string} signatureAlgorithm   signature algorithm
		 * @param  {string[]} transformationAlgorithms   canonicalization and transformation Algorithms
		 * @return {string} base64 encoded string
		 */
		constructSAMLSignature(opts: SignatureConstructor) {
			const {
				rawSamlMessage,
				referenceTagXPath,
				privateKey,
				privateKeyPass,
				signatureAlgorithm = signatureAlgorithms.RSA_SHA256,
				transformationAlgorithms = [
					'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
					'http://www.w3.org/2001/10/xml-exc-c14n#',
				],
				signingCert,
				signatureConfig,
				isBase64Output = true,
				isMessageSigned = false,
			} = opts;
			const sig = new SignedXml();
			// Add assertion sections as reference
			if (referenceTagXPath) {
				sig.addReference(referenceTagXPath, opts.transformationAlgorithms, getDigestMethod(signatureAlgorithm));
			}
			if (isMessageSigned) {
				sig.addReference(
					// reference to the root node
					'/*',
					transformationAlgorithms,
					getDigestMethod(signatureAlgorithm),
					'',
					'',
					'',
					false
				);
			}
			sig.signatureAlgorithm = signatureAlgorithm;
			// @ts-expect-error todo
			sig.keyInfoProvider = this.getKeyInfoProvider(signingCert, signatureConfig);
			sig.signingKey = readPrivateKey(privateKey, privateKeyPass, true);
			if (signatureConfig) {
				sig.computeSignature(rawSamlMessage, signatureConfig);
			} else {
				sig.computeSignature(rawSamlMessage);
			}
			return isBase64Output !== false ? base64Encode(sig.getSignedXml()) : sig.getSignedXml();
		},
		/**
		 * @desc Verify the XML signature
		 * @param  {string} xml xml
		 * @param  {signature} signature context of XML signature
		 * @param  {SignatureVerifierOptions} opts cert declares the X509 certificate
		 * @return {boolean} verification result
		 */
		verifySignature(xml: string, opts: SignatureVerifierOptions) {
			const doc = new dom().parseFromString(xml);
			// In order to avoid the wrapping attack, we have changed to use absolute xpath instead of naively fetching the signature element
			// message signature (logout response / saml response)
			const messageSignatureXpath =
				"/*[contains(local-name(), 'Response') or contains(local-name(), 'Request')]/*[local-name(.)='Signature']";
			// assertion signature (logout response / saml response)
			const assertionSignatureXpath =
				"/*[contains(local-name(), 'Response') or contains(local-name(), 'Request')]/*[local-name(.)='Assertion']/*[local-name(.)='Signature']";
			// check if there is a potential malicious wrapping signature
			const wrappingElementsXPath =
				"/*[contains(local-name(), 'Response')]/*[local-name(.)='Assertion']/*[local-name(.)='Subject']/*[local-name(.)='SubjectConfirmation']/*[local-name(.)='SubjectConfirmationData']//*[local-name(.)='Assertion' or local-name(.)='Signature']";

			// select the signature node
			let assertionNode: string | null = null;
			const messageSignatureNode = select(messageSignatureXpath, doc);
			const assertionSignatureNode = select(assertionSignatureXpath, doc);
			const wrappingElementNode = select(wrappingElementsXPath, doc);

			// try to catch potential wrapping attack
			if (wrappingElementNode.length !== 0) {
				throw new SamlifyError(SamlifyErrorCode.PotentialWrappingAttack);
			}

			const selection = [...messageSignatureNode, ...assertionSignatureNode].filter(isNode);

			// guarantee to have a signature in saml response
			if (selection.length === 0) {
				throw new SamlifyError(SamlifyErrorCode.ZeroSignature);
			}

			const sig = new SignedXml();
			let verified = true;
			// need to refactor later on
			selection.forEach((signatureNode) => {
				sig.signatureAlgorithm = opts.signatureAlgorithm as string;

				if (!opts.keyFile && !opts.metadata) {
					throw new SamlifyError(SamlifyErrorCode.MissingOptionsForSignatureVerification);
				}

				if (opts.keyFile) {
					sig.keyInfoProvider = new FileKeyInfo(opts.keyFile);
				}

				if (opts.metadata) {
					const certificateNode = select(".//*[local-name(.)='X509Certificate']", signatureNode) as any;
					// no certificate node in response
					if (certificateNode.length === 0) {
						throw new SamlifyError(SamlifyErrorCode.CertificateNotFound);
					}

					// certificate in metadata
					let certs: string[];
					const metadataCert = opts.metadata.getX509Certificate(certUse.signing);
					// flattens the nested array of Certificates from each KeyDescriptor
					if (Array.isArray(metadataCert)) {
						certs = flattenDeep(metadataCert).map(normalizeCerString);
					} else {
						certs = [normalizeCerString(metadataCert)];
					}

					const x509CertificateData = certificateNode[0].firstChild.data;
					const x509Certificate = normalizeCerString(x509CertificateData);

					if (certs.length >= 1 && !certs.find((cert) => cert === x509Certificate)) {
						// keep this restriction for rolling certificate usage
						// to make sure the response certificate is one of those specified in metadata
						throw new SamlifyError(SamlifyErrorCode.MismatchedCertificateDeclarationInMetadata);
					}
					// @ts-expect-error todo
					sig.keyInfoProvider = this.getKeyInfoProvider(x509Certificate);
				}

				sig.loadSignature(signatureNode);

				doc.removeChild(signatureNode);

				verified = verified && sig.checkSignature(doc.toString());

				// immediately throw error when any one of the signature is failed to get verified
				if (!verified) {
					throw new SamlifyError(SamlifyErrorCode.FailedToVerifySignature);
				}
			});

			// response must be signed, either entire document or assertion
			// default we will take the assertion section under root
			if (messageSignatureNode.length === 1) {
				const node = select(
					"/*[contains(local-name(), 'Response') or contains(local-name(), 'Request')]/*[local-name(.)='Assertion']",
					doc
				);
				if (node.length === 1 && node[0] != null) {
					assertionNode = node[0].toString();
				}
			}

			if (assertionSignatureNode.length === 1 && assertionSignatureNode[0] != null) {
				const verifiedAssertionInfo = extract(assertionSignatureNode[0].toString(), [
					{
						key: 'refURI',
						localPath: ['Signature', 'SignedInfo', 'Reference'],
						attributes: ['URI'],
					},
				]);
				// get the assertion supposed to be the one should be verified
				const desiredAssertionInfo = extract(doc.toString(), [
					{
						key: 'id',
						localPath: ['~Response', 'Assertion'],
						attributes: ['ID'],
					},
				]);
				// 5.4.2 References
				// SAML assertions and protocol messages MUST supply a value for the ID attribute on the root element of
				// the assertion or protocol message being signed. The assertion’s or protocol message's root element may
				// or may not be the root element of the actual XML document containing the signed assertion or protocol
				// message (e.g., it might be contained within a SOAP envelope).
				// Signatures MUST contain a single <ds:Reference> containing a same-document reference to the ID
				// attribute value of the root element of the assertion or protocol message being signed. For example, if the
				// ID attribute value is "foo", then the URI attribute in the <ds:Reference> element MUST be "#foo".
				if (verifiedAssertionInfo.refURI !== `#${desiredAssertionInfo.id}`) {
					throw new SamlifyError(SamlifyErrorCode.PotentialWrappingAttack);
				}
				const verifiedDoc = extract(doc.toString(), [
					{
						key: 'assertion',
						localPath: ['~Response', 'Assertion'],
						attributes: [],
						context: true,
					},
				]);
				// eslint-disable-next-line @typescript-eslint/no-unsafe-call
				assertionNode = verifiedDoc.assertion?.toString();
			}

			return [verified, assertionNode];
		},
		/**
		 * @desc Helper function to create the key section in metadata (abstraction for signing and encrypt use)
		 * @param  {string} use          type of certificate (e.g. signing, encrypt)
		 * @param  {string} certString    declares the certificate String
		 * @return {object} object used in xml module
		 */
		createKeySection(use: KeyUse, certString: string | Buffer): KeyComponent {
			return {
				['KeyDescriptor']: [
					{
						_attr: { use },
					},
					{
						['ds:KeyInfo']: [
							{
								_attr: {
									'xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
								},
							},
							{
								['ds:X509Data']: [
									{
										'ds:X509Certificate': normalizeCerString(certString),
									},
								],
							},
						],
					},
				],
			};
		},
		/**
		 * @desc Constructs SAML message
		 * @param  {string} octetString        see "Bindings for the OASIS Security Assertion Markup Language (SAML V2.0)" P.17/46
		 * @param  {string|Buffer} key         declares the pem-formatted private key
		 * @param  {string} passphrase         passphrase of private key [optional]
		 * @param  {string} signingAlgorithm   signing algorithm
		 * @return {string|Buffer} message signature
		 */
		constructMessageSignature(
			octetString: string,
			key: string | Buffer,
			passphrase?: string,
			signingAlgorithm?: RequestSignatureAlgorithm
		): Buffer {
			// Default returning base64 encoded signature
			// Embed with node-rsa module
			const decryptedKey = new nrsa(readPrivateKey(key, passphrase), undefined, {
				signingScheme: getSigningScheme(signingAlgorithm),
			});
			// Use private key to sign data
			return decryptedKey.sign(octetString);
		},
		/**
		 * @desc Verifies message signature
		 * @param  {Metadata} metadata                 metadata object of identity provider or service provider
		 * @param  {string} octetString                see "Bindings for the OASIS Security Assertion Markup Language (SAML V2.0)" P.17/46
		 * @param  {string} signature                  context of XML signature
		 * @param  {string} verifyAlgorithm            algorithm used to verify
		 * @return {boolean} verification result
		 */
		verifyMessageSignature(
			metadata: Metadata,
			octetString: nrsa.Data,
			signature: Buffer,
			verifyAlgorithm?: RequestSignatureAlgorithm
		) {
			const signCert = metadata.getX509Certificate(certUse.signing);
			const signingScheme = getSigningScheme(verifyAlgorithm);
			const key = new nrsa(getPublicKeyPemFromCertificate(signCert), undefined, {
				signingScheme,
			});
			return key.verify(octetString, signature);
		},
		/**
		 * @desc Get the public key in string format
		 * @param  {string | Buffer} x509Certificate certificate
		 * @return {string} public key
		 */
		getKeyInfoProvider(x509Certificate: string | Buffer, signatureConfig: SignatureConfig) {
			return {
				getKeyInfo: () => {
					const prefix = signatureConfig?.prefix ? `${signatureConfig.prefix}:` : '';
					return `<${prefix}X509Data><${prefix}X509Certificate>${x509Certificate}</${prefix}X509Certificate></${prefix}X509Data>`;
				},
				getKey: () => {
					return getPublicKeyPemFromCertificate(x509Certificate).toString();
				},
			};
		},
		/**
		 * @desc Encrypt the assertion section in Response
		 * @param  {Entity} sourceEntity             source entity
		 * @param  {Entity} targetEntity             target entity
		 * @param  {string} xml                      response in xml string format
		 * @return {Promise<string>} a promise to resolve the finalized xml
		 */
		encryptAssertion(sourceEntity: Entity, targetEntity: Entity, xml?: string): Promise<string> {
			// Implement encryption after signature if it has
			return new Promise<string>((resolve, reject) => {
				if (!xml) {
					return reject(new SamlifyError(SamlifyErrorCode.UndefinedAssertion));
				}

				const sourceEntitySetting = sourceEntity.getEntitySettings();
				const targetEntityMetadata = targetEntity.getEntityMeta();
				const doc = new dom().parseFromString(xml);
				const assertions = select("//*[local-name(.)='Assertion']", doc) as Node[];
				if (!isNonEmptyArray(assertions) || assertions[0] == null) {
					throw new SamlifyError(SamlifyErrorCode.UndefinedAssertion);
				}
				if (assertions.length > 1) {
					throw new SamlifyError(SamlifyErrorCode.MultipleAssertion);
				}
				const assertion = assertions[0];
				// Perform encryption depends on the setting, default is false
				if (sourceEntitySetting.isAssertionEncrypted) {
					if (!sourceEntitySetting.dataEncryptionAlgorithm) {
						throw new SamlifyError(SamlifyErrorCode.MissingDataEncryptionAlgorithm);
					}
					if (!sourceEntitySetting.keyEncryptionAlgorithm) {
						throw new SamlifyError(SamlifyErrorCode.MissingKeyEncryptionAlgorithm);
					}
					xmlenc.encrypt(
						assertion.toString(),
						{
							// use xml-encryption module
							rsa_pub: Buffer.from(
								getPublicKeyPemFromCertificate(targetEntityMetadata.getX509Certificate(certUse.encrypt)).replace(
									/\r?\n|\r/g,
									''
								)
							), // public key from certificate
							pem: Buffer.from(`
-----BEGIN CERTIFICATE-----
${targetEntityMetadata.getX509Certificate(certUse.encrypt)}
-----END CERTIFICATE-----
`),
							encryptionAlgorithm: sourceEntitySetting.dataEncryptionAlgorithm,
							keyEncryptionAlgorithm: sourceEntitySetting.keyEncryptionAlgorithm,
						},
						(err, res) => {
							if (err) {
								console.error(err);
								return reject(new SamlifyError(SamlifyErrorCode.ExceptionOfAssertionEncryption));
							}
							if (!res) {
								return reject(new SamlifyError(SamlifyErrorCode.UndefinedAssertion));
							}
							const encAssertionPrefix = sourceEntitySetting.tagPrefix?.encryptedAssertion;
							const encryptAssertionNode = new dom().parseFromString(
								`<${encAssertionPrefix}:EncryptedAssertion xmlns:${encAssertionPrefix}="${names.assertion}">${res}</${encAssertionPrefix}:EncryptedAssertion>`
							);
							doc.replaceChild(encryptAssertionNode, assertion);
							return resolve(base64Encode(doc.toString()));
						}
					);
				} else {
					return resolve(base64Encode(xml)); // No need to do encrpytion
				}
			});
		},
		/**
		 * @desc Decrypt the assertion section in Response
		 * @param  {string} type             only accept SAMLResponse to proceed decryption
		 * @param  {Entity} here             this entity
		 * @param  {Entity} from             from the entity where the message is sent
		 * @param {string} entireXML         response in xml string format
		 * @return {function} a promise to get back the entire xml with decrypted assertion
		 */
		decryptAssertion(here: Entity, entireXML: string) {
			return new Promise<[string, any]>((resolve, reject) => {
				// Implement decryption first then check the signature
				if (!entireXML) {
					return reject(new SamlifyError(SamlifyErrorCode.UndefinedAssertion));
				}
				// Perform encryption depends on the setting of where the message is sent, default is false
				const hereSetting = here.getEntitySettings();
				const xml = new dom().parseFromString(entireXML);
				const encryptedAssertions = select(
					"/*[contains(local-name(), 'Response')]/*[local-name(.)='EncryptedAssertion']",
					xml
				) as Node[];
				if (!isNonEmptyArray(encryptedAssertions) || encryptedAssertions[0] == null) {
					throw new SamlifyError(SamlifyErrorCode.UndefinedAssertion);
				}
				if (encryptedAssertions.length !== 1) {
					throw new SamlifyError(SamlifyErrorCode.MultipleAssertion);
				}
				const encryptedAssertion = encryptedAssertions[0];
				if (!hereSetting.encPrivateKey) {
					throw new SamlifyError(
						SamlifyErrorCode.MissingEncPrivateKey,
						`${here.constructor.name} is trying to decrypt assertion, but encPrivateKey was not provided.`
					);
				}
				return xmlenc.decrypt(
					encryptedAssertion.toString(),
					{
						key: readPrivateKey(hereSetting.encPrivateKey, hereSetting.encPrivateKeyPass),
					},
					(err, res) => {
						if (err) {
							console.error(err);
							return reject(new SamlifyError(SamlifyErrorCode.ExceptionOfAssertionDecryption));
						}
						if (!res) {
							return reject(new SamlifyError(SamlifyErrorCode.UndefinedAssertion));
						}
						const assertionNode = new dom().parseFromString(res);
						xml.replaceChild(assertionNode, encryptedAssertion);
						return resolve([xml.toString(), res]);
					}
				);
			});
		},
		/**
		 * @desc Check if the xml string is valid and bounded
		 */
		async isValidXml(input: string) {
			// check if global api contains the validate function
			const { validate } = getContext();

			/**
			 * user can write a validate function that always returns
			 * a resolved promise and skip the validator even in
			 * production, user will take the responsibility if
			 * they intend to skip the validation
			 */
			if (!validate) {
				// otherwise, an error will be thrown
				throw new SamlifyError(
					SamlifyErrorCode.MissingValidation,
					'Your application is potentially vulnerable because no validation function found. Please read the documentation on how to setup the validator. (https://github.com/tngan/samlify#installation)'
				);
			}
			return validate(input);
		},
	};
};

export const libsaml = libSaml();
