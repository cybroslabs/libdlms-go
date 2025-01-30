package dlmsal

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

type getRequestTag byte

const (
	TagGetRequestNormal   getRequestTag = 0x1
	TagGetRequestNext     getRequestTag = 0x2
	TagGetRequestWithList getRequestTag = 0x3
)

type getResponseTag byte

const (
	TagGetResponseNormal        getResponseTag = 0x1
	TagGetResponseWithDataBlock getResponseTag = 0x2
	TagGetResponseWithList      getResponseTag = 0x3
)

type setRequestTag byte

const (
	TagSetRequestNormal                    setRequestTag = 0x1
	TagSetRequestWithFirstDataBlock        setRequestTag = 0x2
	TagSetRequestWithDataBlock             setRequestTag = 0x3
	TagSetRequestWithList                  setRequestTag = 0x4
	TagSetRequestWithListAndFirstDataBlock setRequestTag = 0x5
)

type setResponseTag byte

const (
	TagSetResponseNormal                setResponseTag = 0x1
	TagSetResponseDataBlock             setResponseTag = 0x2
	TagSetResponseLastDataBlock         setResponseTag = 0x3
	TagSetResponseLastDataBlockWithList setResponseTag = 0x4
	TagSetResponseWithList              setResponseTag = 0x5
)

type actionRequestTag byte

const (
	TagActionRequestNormal                 actionRequestTag = 0x1
	TagActionRequestNextPBlock             actionRequestTag = 0x2
	TagActionRequestWithList               actionRequestTag = 0x3
	TagActionRequestWithFirstPBlock        actionRequestTag = 0x4
	TagActionRequestWithListAndFirstPBlock actionRequestTag = 0x5
	TagActionRequestWithPBlock             actionRequestTag = 0x6
)

type actionResponseTag byte

const (
	TagActionResponseNormal     actionResponseTag = 0x1
	TagActionResponseWithPBlock actionResponseTag = 0x2
	TagActionResponseWithList   actionResponseTag = 0x3
	TagActionResponseNextPBlock actionResponseTag = 0x4
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
