export enum SamlifyErrorCode {
	/**
	 * catch-all for all unknown codes, including missing codes.
	 */
	Unknown = 'Unknown',
	CertificateNotFound = 'CertificateNotFound',
	EmptyAssertion = 'EmptyAssertion',
	ExceptionOfAssertionDecryption = 'ExceptionOfAssertionDecryption',
	ExceptionOfAssertionEncryption = 'ExceptionOfAssertionEncryption',
	ExpiredSession = 'ExpiredSession',
	FailedMessageSignatureVerification = 'FailedMessageSignatureVerification',
	FailedStatus = 'FailedStatus',
	FailedToVerifySignature = 'FailedToVerifySignature',
	FailedToVerifySignatureETS = 'FailedToVerifySignatureETS',
	FailedToVerifySignatureSTE = 'FailedToVerifySignatureSTE',
	InvalidXML = 'InvalidXML',
	MetadataConflictRequestSignedFlag = 'MetadataConflictRequestSignedFlag',
	MetadataIdpMissingSingleSignOnService = 'MetadataIdpMissingSingleSignOnService',
	MismatchedCertificateDeclarationInMetadata = 'MismatchedCertificateDeclarationInMetadata',
	MismatchedIssuer = 'MismatchedIssuer',
	MissingDataEncryptionAlgorithm = 'MissingDataEncryptionAlgorithm',
	MissingEncPrivateKey = 'MissingEncPrivateKey',
	MissingKeyEncryptionAlgorithm = 'MissingKeyEncryptionAlgorithm',
	MissingMetadata = 'MissingMetadata',
	MissingOptionsForSignatureVerification = 'MissingOptionsForSignatureVerification',
	MissingPrivateKey = 'MissingPrivateKey',
	MissingQueryOctetString = 'MissingQueryOctetString',
	MissingSigAlg = 'MissingSigAlg',
	MissingStatus = 'MissingStatus',
	MissingValidation = 'MissingValidation',
	MultipleAssertion = 'MultipleAssertion',
	MultipleMetadataEntityDescriptor = 'MultipleMetadataEntityDescriptor',
	PotentialWrappingAttack = 'PotentialWrappingAttack',
	RedirectFlowBadArgs = 'RedirectFlowBadArgs',
	SingleLogoutLocationNotFound = 'SingleLogoutLocationNotFound',
	SingleSignOnLocationNotFound = 'SingleSignOnLocationNotFound',
	SubjectUnconfirmed = 'SubjectUnconfirmed',
	TypeError = 'TypeError',
	UndefinedAssertion = 'UndefinedAssertion',
	UndefinedQueryParams = 'UndefinedQueryParams',
	UnexpectedFlow = 'UnexpectedFlow',
	UnsupportedBinding = 'UnsupportedBinding',
	UnsupportedEntityType = 'UnsupportedEntityType',
	UnsupportedParserType = 'UnsupportedParserType',
	ZeroSignature = 'ZeroSignature',
}

export class SamlifyError extends Error {
	public code: SamlifyErrorCode;
	constructor(code: SamlifyErrorCode = SamlifyErrorCode.Unknown, message?: string) {
		super(message);
		this.code = code;
		this.name = `SamlifyError(${code})`;
	}
}

// shorthand
export function isSamlifyError(error: unknown): error is SamlifyError {
	return error instanceof SamlifyError;
}
