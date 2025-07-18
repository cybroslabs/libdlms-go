package base

const (
	DlmsVersion = 0x06

	VAANameLN = 0x0007
	VAANameSN = 0xFA00
)

type Authentication byte

const (
	AuthenticationNone       Authentication = 0 // No authentication is used.
	AuthenticationLow        Authentication = 1 // Low authentication is used.
	AuthenticationHigh       Authentication = 2 // High authentication is used.
	AuthenticationHighMD5    Authentication = 3 // High authentication is used. Password is hashed with MD5.
	AuthenticationHighSHA1   Authentication = 4 // High authentication is used. Password is hashed with SHA1.
	AuthenticationHighGmac   Authentication = 5 // High authentication is used. Password is hashed with GMAC.
	AuthenticationHighSha256 Authentication = 6 // High authentication is used. Password is hashed with SHA-256.
	AuthenticationHighEcdsa  Authentication = 7 // High authentication is used. Password is hashed with ECDSA.
)

type DlmsSecurity byte

const (
	SecurityNone           DlmsSecurity = 0    // Transport security is not used.
	SecurityAuthentication DlmsSecurity = 0x10 // Authentication security is used.
	SecurityEncryption     DlmsSecurity = 0x20 // Encryption security is used.
	SecurityCompression    DlmsSecurity = 0x80 // Compression security is used.
	SecuritySuite0         DlmsSecurity = 0
	SecuritySuite1         DlmsSecurity = 1
	SecuritySuite2         DlmsSecurity = 2
	SecuritySuiteMask      DlmsSecurity = 0x0F
)

type AssociationResult byte

const (
	AssociationResultAccepted          AssociationResult = 0
	AssociationResultPermanentRejected AssociationResult = 1
	AssociationResultTransientRejected AssociationResult = 2
)

func (a AssociationResult) String() string {
	switch a {
	case AssociationResultAccepted:
		return "accepted"
	case AssociationResultPermanentRejected:
		return "permanent-rejected"
	case AssociationResultTransientRejected:
		return "transient-rejected"
	default:
		return "unknown"
	}
}

type SourceDiagnostic byte

const (
	SourceDiagnosticNone                                       SourceDiagnostic = 0
	SourceDiagnosticNoReasonGiven                              SourceDiagnostic = 1
	SourceDiagnosticApplicationContextNameNotSupported         SourceDiagnostic = 2
	SourceDiagnosticCallingAPTitleNotRecognized                SourceDiagnostic = 3
	SourceDiagnosticCallingAPInvocationIdentifierNotRecognized SourceDiagnostic = 4
	SourceDiagnosticCallingAEQualifierNotRecognized            SourceDiagnostic = 5
	SourceDiagnosticCallingAEInvocationIdentifierNotRecognized SourceDiagnostic = 6
	SourceDiagnosticCalledAPTitleNotRecognized                 SourceDiagnostic = 7
	SourceDiagnosticCalledAPInvocationIdentifierNotRecognized  SourceDiagnostic = 8
	SourceDiagnosticCalledAEQualifierNotRecognized             SourceDiagnostic = 9
	SourceDiagnosticCalledAEInvocationIdentifierNotRecognized  SourceDiagnostic = 10
	SourceDiagnosticAuthenticationMechanismNameNotRecognized   SourceDiagnostic = 11
	SourceDiagnosticAuthenticationMechanismNameRequired        SourceDiagnostic = 12
	SourceDiagnosticAuthenticationFailure                      SourceDiagnostic = 13
	SourceDiagnosticAuthenticationRequired                     SourceDiagnostic = 14
)

func (s SourceDiagnostic) String() string {
	switch s {
	case SourceDiagnosticNone:
		return "none"
	case SourceDiagnosticNoReasonGiven:
		return "no-reason-given"
	case SourceDiagnosticApplicationContextNameNotSupported:
		return "application-context-name-not-supported"
	case SourceDiagnosticCallingAPTitleNotRecognized:
		return "calling-ap-title-not-recognized"
	case SourceDiagnosticCallingAPInvocationIdentifierNotRecognized:
		return "calling-ap-invocation-identifier-not-recognized"
	case SourceDiagnosticCallingAEQualifierNotRecognized:
		return "calling-ae-qualifier-not-recognized"
	case SourceDiagnosticCallingAEInvocationIdentifierNotRecognized:
		return "calling-ae-invocation-identifier-not-recognized"
	case SourceDiagnosticCalledAPTitleNotRecognized:
		return "called-ap-title-not-recognized"
	case SourceDiagnosticCalledAPInvocationIdentifierNotRecognized:
		return "called-ap-invocation-identifier-not-recognized"
	case SourceDiagnosticCalledAEQualifierNotRecognized:
		return "called-ae-qualifier-not-recognized"
	case SourceDiagnosticCalledAEInvocationIdentifierNotRecognized:
		return "called-ae-invocation-identifier-not-recognized"
	case SourceDiagnosticAuthenticationMechanismNameNotRecognized:
		return "authentication-mechanism-name-not-recognized"
	case SourceDiagnosticAuthenticationMechanismNameRequired:
		return "authentication-mechanism-name-required"
	case SourceDiagnosticAuthenticationFailure:
		return "authentication-failure"
	case SourceDiagnosticAuthenticationRequired:
		return "authentication-required"
	default:
		return "unknown"
	}
}

type ApplicationContext byte

// Application context definitions
const (
	ApplicationContextLNNoCiphering ApplicationContext = 1
	ApplicationContextSNNoCiphering ApplicationContext = 2
	ApplicationContextLNCiphering   ApplicationContext = 3
	ApplicationContextSNCiphering   ApplicationContext = 4
)

const (
	PduTypeProtocolVersion            = 0
	PduTypeApplicationContextName     = 1
	PduTypeCalledAPTitle              = 2
	PduTypeCalledAEQualifier          = 3
	PduTypeCalledAPInvocationID       = 4
	PduTypeCalledAEInvocationID       = 5
	PduTypeCallingAPTitle             = 6
	PduTypeCallingAEQualifier         = 7
	PduTypeCallingAPInvocationID      = 8
	PduTypeCallingAEInvocationID      = 9
	PduTypeSenderAcseRequirements     = 10
	PduTypeMechanismName              = 11
	PduTypeCallingAuthenticationValue = 12
	PduTypeImplementationInformation  = 29
	PduTypeUserInformation            = 30
)

const (
	BERTypeContext     = 0x80
	BERTypeApplication = 0x40
	BERTypeConstructed = 0x20
)

const (
	StateErrorServiceNotAllower = 0x01
	StateErrorServiceUnknown    = 0x02
)

const (
	ServiceErrorOperationNotPossible   = 0x01
	ServiceErrorServiceNotSupported    = 0x02
	ServiceErrorOtherReason            = 0x03
	ServiceErrorPduTooLong             = 0x04
	ServiceErrorDecipheringError       = 0x05
	ServiceErrorInvocationCounterError = 0x06
)

// Conformance block
const (
	ConformanceBlockReservedZero         uint32 = 0b100000000000000000000000
	ConformanceBlockGeneralProtection    uint32 = 0b010000000000000000000000
	ConformanceBlockGeneralBlockTransfer uint32 = 0b001000000000000000000000
	ConformanceBlockRead                 uint32 = 0b000100000000000000000000

	ConformanceBlockWrite            uint32 = 0b000010000000000000000000
	ConformanceBlockUnconfirmedWrite uint32 = 0b000001000000000000000000
	ConformanceBlockReservedSix      uint32 = 0b000000100000000000000000
	ConformanceBlockReservedSeven    uint32 = 0b000000010000000000000000

	ConformanceBlockAttribute0SupportedWithSet uint32 = 0b000000001000000000000000
	ConformanceBlockPriorityMgmtSupported      uint32 = 0b000000000100000000000000
	ConformanceBlockAttribute0SupportedWithGet uint32 = 0b000000000010000000000000
	ConformanceBlockBlockTransferWithGetOrRead uint32 = 0b000000000001000000000000

	ConformanceBlockBlockTransferWithSetOrWrite uint32 = 0b000000000000100000000000
	ConformanceBlockBlockTransferWithAction     uint32 = 0b000000000000010000000000
	ConformanceBlockMultipleReferences          uint32 = 0b000000000000001000000000
	ConformanceBlockInformationReport           uint32 = 0b000000000000000100000000

	ConformanceBlockDataNotification   uint32 = 0b000000000000000010000000
	ConformanceBlockAccess             uint32 = 0b000000000000000001000000
	ConformanceBlockParametrizedAccess uint32 = 0b000000000000000000100000
	ConformanceBlockGet                uint32 = 0b000000000000000000010000

	ConformanceBlockSet               uint32 = 0b000000000000000000001000
	ConformanceBlockSelectiveAccess   uint32 = 0b000000000000000000000100
	ConformanceBlockEventNotification uint32 = 0b000000000000000000000010
	ConformanceBlockAction            uint32 = 0b000000000000000000000001
)

type CosemTag byte

const (
	// ---- standardized DLMS APDUs
	TagInitiateRequest          CosemTag = 1
	TagReadRequest              CosemTag = 5
	TagWriteRequest             CosemTag = 6
	TagInitiateResponse         CosemTag = 8
	TagReadResponse             CosemTag = 12
	TagWriteResponse            CosemTag = 13
	TagConfirmedServiceError    CosemTag = 14
	TagDataNotification         CosemTag = 15
	TagUnconfirmedWriteRequest  CosemTag = 22
	TagInformationReportRequest CosemTag = 24
	TagGloInitiateRequest       CosemTag = 33
	TagGloInitiateResponse      CosemTag = 40
	TagGloConfirmedServiceError CosemTag = 46
	TagAARQ                     CosemTag = 96
	TagAARE                     CosemTag = 97
	TagRLRQ                     CosemTag = 98
	TagRLRE                     CosemTag = 99
	// --- APDUs used for data communication services
	TagGetRequest               CosemTag = 192
	TagSetRequest               CosemTag = 193
	TagEventNotificationRequest CosemTag = 194
	TagActionRequest            CosemTag = 195
	TagGetResponse              CosemTag = 196
	TagSetResponse              CosemTag = 197
	TagActionResponse           CosemTag = 199
	// --- global ciphered pdus
	TagGloReadRequest              CosemTag = 37
	TagGloWriteRequest             CosemTag = 38
	TagGloReadResponse             CosemTag = 44
	TagGloWriteResponse            CosemTag = 45
	TagGloGetRequest               CosemTag = 200
	TagGloSetRequest               CosemTag = 201
	TagGloEventNotificationRequest CosemTag = 202
	TagGloActionRequest            CosemTag = 203
	TagGloGetResponse              CosemTag = 204
	TagGloSetResponse              CosemTag = 205
	TagGloActionResponse           CosemTag = 207
	// --- dedicated ciphered pdus
	TagDedReadRequest              CosemTag = 69
	TagDedWriteRequest             CosemTag = 70
	TagDedReadResponse             CosemTag = 76
	TagDedWriteResponse            CosemTag = 77
	TagDedGetRequest               CosemTag = 208
	TagDedSetRequest               CosemTag = 209
	TagDedEventNotificationRequest CosemTag = 210
	TagDedActionRequest            CosemTag = 211
	TagDedGetResponse              CosemTag = 212
	TagDedSetResponse              CosemTag = 213
	TagDedActionResponse           CosemTag = 215
	TagExceptionResponse           CosemTag = 216
	// --- general
	TagGeneralGloCiphering  CosemTag = 219
	TagGeneralDedCiphering  CosemTag = 220
	TagGeneralCiphering     CosemTag = 221
	TagGeneralSigning       CosemTag = 223
	TagGeneralBlockTransfer CosemTag = 224
)

type DlmsResultTag byte

const (
	// DataAccessResult
	TagResultSuccess                 DlmsResultTag = 0
	TagResultHardwareFault           DlmsResultTag = 1
	TagResultTemporaryFailure        DlmsResultTag = 2
	TagResultReadWriteDenied         DlmsResultTag = 3
	TagResultObjectUndefined         DlmsResultTag = 4
	TagResultObjectClassInconsistent DlmsResultTag = 9
	TagResultObjectUnavailable       DlmsResultTag = 11
	TagResultTypeUnmatched           DlmsResultTag = 12
	TagResultScopeAccessViolated     DlmsResultTag = 13
	TagResultDataBlockUnavailable    DlmsResultTag = 14
	TagResultLongGetAborted          DlmsResultTag = 15
	TagResultNoLongGetInProgress     DlmsResultTag = 16
	TagResultLongSetAborted          DlmsResultTag = 17
	TagResultNoLongSetInProgress     DlmsResultTag = 18
	TagResultDataBlockNumberInvalid  DlmsResultTag = 19
	TagResultOtherReason             DlmsResultTag = 250
)

func (s DlmsResultTag) String() string {
	switch s {
	case TagResultSuccess:
		return "success"
	case TagResultHardwareFault:
		return "hardware-fault"
	case TagResultTemporaryFailure:
		return "temporary-failure"
	case TagResultReadWriteDenied:
		return "read-write-denied"
	case TagResultObjectUndefined:
		return "object-undefined"
	case TagResultObjectClassInconsistent:
		return "object-class-inconsistent"
	case TagResultObjectUnavailable:
		return "object-unavailable"
	case TagResultTypeUnmatched:
		return "type-unmatched"
	case TagResultScopeAccessViolated:
		return "scope-of-access-violated"
	case TagResultDataBlockUnavailable:
		return "data-block-unavailable"
	case TagResultLongGetAborted:
		return "long-get-aborted"
	case TagResultNoLongGetInProgress:
		return "no-long-get-in-progress"
	case TagResultLongSetAborted:
		return "long-set-aborted"
	case TagResultNoLongSetInProgress:
		return "no-long-set-in-progress"
	case TagResultDataBlockNumberInvalid:
		return "data-block-number-invalid"
	case TagResultOtherReason:
		return "other-reason"
	default:
		return "unknown"
	}
}

type ReleaseRequestReason byte

const (
	ReleaseRequestReasonNormal      ReleaseRequestReason = 0
	ReleaseRequestReasonUrgent      ReleaseRequestReason = 1
	ReleaseRequestReasonUserDefined ReleaseRequestReason = 30
)
