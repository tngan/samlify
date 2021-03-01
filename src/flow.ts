import type { Entity, ESamlHttpRequest } from './entity';
import { SamlifyError, SamlifyErrorCode } from './error';
import {
	extract,
	ExtractorFields,
	loginRequestFields,
	loginResponseFields,
	loginResponseStatusFields,
	logoutRequestFields,
	logoutResponseFields,
	logoutResponseStatusFields,
} from './extractor';
import libsaml from './libsaml';
import { BindingNamespace, MessageSignatureOrder, ParserType, StatusCode, wording } from './urn';
import { base64Decode, inflateString } from './utility';
import { verifyTime } from './validator';

const urlParams = wording.urlParams;

export interface FlowOptions<From extends Entity = Entity, Self extends Entity = Entity> {
	from: From;
	self: Self;
	checkSignature?: boolean;
	parserType: ParserType;
	type: 'login' | 'logout';
	binding: BindingNamespace;
	request: ESamlHttpRequest;
	supportBindings?: BindingNamespace[];
}

export interface FlowResult<Extract = unknown> {
	samlContent: string;
	extract: Extract;
}

// get the default extractor fields based on the parserType
function getDefaultExtractorFields(parserType: ParserType, assertion?: any): ExtractorFields {
	switch (parserType) {
		case ParserType.SAMLRequest:
			return loginRequestFields;
		case ParserType.SAMLResponse:
			if (!assertion) {
				// unexpected hit
				throw new SamlifyError(SamlifyErrorCode.EmptyAssertion);
			}
			return loginResponseFields(assertion);
		case ParserType.LogoutRequest:
			return logoutRequestFields;
		case ParserType.LogoutResponse:
			return logoutResponseFields;
		default:
			throw new SamlifyError(SamlifyErrorCode.UnsupportedParserType);
	}
}

// proceed the redirect binding flow
async function redirectFlow(options: FlowOptions): Promise<FlowResult> {
	const { request, parserType, checkSignature = true, from } = options;
	const { query, octetString } = request;
	const { SigAlg: sigAlg, Signature: signature } = query;

	const targetEntityMetadata = from.getEntityMeta();

	// ?SAMLRequest= or ?SAMLResponse=
	const direction = libsaml.getQueryParamByType(parserType);
	const content = query[direction];

	// query must contain the saml content
	if (content === undefined) {
		throw new SamlifyError(SamlifyErrorCode.RedirectFlowBadArgs);
	}

	const xmlString = inflateString(decodeURIComponent(content));

	// validate the xml (remarks: login response must be gone through post flow)
	if (
		parserType === urlParams.samlRequest ||
		parserType === urlParams.logoutRequest ||
		parserType === urlParams.logoutResponse
	) {
		try {
			await libsaml.isValidXml(xmlString);
		} catch (e) {
			throw new SamlifyError(SamlifyErrorCode.InvalidXML);
		}
	}

	const extractorFields = getDefaultExtractorFields(parserType);

	const parseResult: { samlContent: string; extract: any; sigAlg: string | null } = {
		samlContent: xmlString,
		sigAlg: null,
		extract: extract(xmlString, extractorFields),
	};

	// check status based on different scenarios
	await checkStatus(xmlString, parserType);

	// see if signature check is required
	// only verify message signature is enough
	if (checkSignature) {
		if (!octetString) {
			throw new SamlifyError(SamlifyErrorCode.MissingQueryOctetString);
		}
		if (!signature || !sigAlg) {
			throw new SamlifyError(SamlifyErrorCode.MissingSigAlg);
		}

		// put the below two assignemnts into verifyMessageSignature function
		const base64Signature = Buffer.from(decodeURIComponent(signature), 'base64');
		const decodeSigAlg = decodeURIComponent(sigAlg);

		const verified = libsaml.verifyMessageSignature(targetEntityMetadata, octetString, base64Signature, sigAlg);

		if (!verified) {
			// Fail to verify message signature
			throw new SamlifyError(SamlifyErrorCode.FailedMessageSignatureVerification);
		}

		parseResult.sigAlg = decodeSigAlg;
	}

	return parseResult;
}

// proceed the post flow
async function postFlow(options: FlowOptions): Promise<FlowResult> {
	const { request, from, self, parserType, checkSignature = true } = options;

	const { body } = request;

	const fromEntitySetting = from.getEntitySettings();
	const direction = libsaml.getQueryParamByType(parserType);
	const encodedRequest = body[direction];

	let samlContent = String(base64Decode(encodedRequest));

	const verificationOptions = {
		metadata: from.getEntityMeta(),
		signatureAlgorithm: fromEntitySetting.requestSignatureAlgorithm,
	};

	const decryptRequired = fromEntitySetting.isAssertionEncrypted;

	let extractorFields: ExtractorFields = [];

	// validate the xml first
	await libsaml.isValidXml(samlContent);

	if (parserType !== urlParams.samlResponse) {
		extractorFields = getDefaultExtractorFields(parserType, null);
	}

	// check status based on different scenarios
	await checkStatus(samlContent, parserType);

	// verify the signatures (the repsonse is encrypted then signed, then verify first then decrypt)
	if (checkSignature && fromEntitySetting.messageSigningOrder === MessageSignatureOrder.ETS) {
		const [verified, verifiedAssertionNode] = libsaml.verifySignature(samlContent, verificationOptions);
		if (!verified) {
			throw new SamlifyError(SamlifyErrorCode.FailedToVerifySignatureETS);
		}
		if (!decryptRequired) {
			extractorFields = getDefaultExtractorFields(parserType, verifiedAssertionNode);
		}
	}

	if (parserType === ParserType.SAMLResponse && decryptRequired) {
		const result = await libsaml.decryptAssertion(self, samlContent);
		samlContent = result[0];
		extractorFields = getDefaultExtractorFields(parserType, result[1]);
	}

	// verify the signatures (the repsonse is signed then encrypted, then decrypt first then verify)
	if (checkSignature && fromEntitySetting.messageSigningOrder === MessageSignatureOrder.STE) {
		const [verified, verifiedAssertionNode] = libsaml.verifySignature(samlContent, verificationOptions);
		if (verified) {
			extractorFields = getDefaultExtractorFields(parserType, verifiedAssertionNode);
		} else {
			throw new SamlifyError(SamlifyErrorCode.FailedToVerifySignatureSTE);
		}
	}

	const parseResult = { samlContent, extract: extract(samlContent, extractorFields) };

	/**
	 *  Validation part: validate the context of response after signature is verified and decrpyted (optional)
	 */
	const initEntitySetting = self.getEntitySettings();
	const targetEntityMetadata = from.getEntityMeta();
	const issuer = targetEntityMetadata.getEntityID();
	const extractedProperties = parseResult.extract;

	// unmatched issuer
	if (
		(parserType === ParserType.LogoutResponse || parserType === ParserType.SAMLResponse) &&
		extractedProperties &&
		extractedProperties.issuer !== issuer
	) {
		throw new SamlifyError(SamlifyErrorCode.MismatchedIssuer);
	}

	// invalid session time
	// only run the verifyTime when `SessionNotOnOrAfter` exists
	if (
		parserType === ParserType.SAMLResponse &&
		extractedProperties.sessionIndex.sessionNotOnOrAfter &&
		!verifyTime(undefined, extractedProperties.sessionIndex.sessionNotOnOrAfter, initEntitySetting.clockDrifts)
	) {
		throw new SamlifyError(SamlifyErrorCode.ExpiredSession);
	}

	// invalid time
	// 2.4.1.2 https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
	if (
		parserType === ParserType.SAMLResponse &&
		extractedProperties.conditions &&
		!verifyTime(
			extractedProperties.conditions.notBefore,
			extractedProperties.conditions.notOnOrAfter,
			initEntitySetting.clockDrifts
		)
	) {
		throw new SamlifyError(SamlifyErrorCode.SubjectUnconfirmed);
	}

	return parseResult;
}

async function checkStatus(content: string, parserType: string) {
	// only check response parser
	if (parserType !== urlParams.samlResponse && parserType !== urlParams.logoutResponse) {
		return 'SKIPPED';
	}

	const fields = parserType === urlParams.samlResponse ? loginResponseStatusFields : logoutResponseStatusFields;

	const { top, second } = extract(content, fields);

	// only resolve when top-tier status code is success
	if (top === StatusCode.Success) {
		return 'OK';
	}

	if (!top) {
		throw new SamlifyError(SamlifyErrorCode.MissingStatus);
	}

	// returns a detailed error for two-tier error code
	throw new SamlifyError(SamlifyErrorCode.FailedStatus, `with top tier code: ${top}, second tier code: ${second}`);
}

export function flow(options: FlowOptions): Promise<FlowResult> {
	const binding = options.binding;
	const parserType = options.parserType;

	options.supportBindings = [BindingNamespace.Redirect, BindingNamespace.Post];
	// saml response only allows POST
	if (parserType === ParserType.SAMLResponse) {
		options.supportBindings = [BindingNamespace.Post];
	}

	if (binding === BindingNamespace.Post) {
		return postFlow(options);
	}

	if (binding === BindingNamespace.Redirect) {
		return redirectFlow(options);
	}

	throw new SamlifyError(SamlifyErrorCode.UnexpectedFlow);
}
