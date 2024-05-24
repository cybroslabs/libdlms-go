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

type AccessResultTag byte

const (
	// DataAccessResult
	TagAccSuccess                 AccessResultTag = 0
	TagAccHardwareFault           AccessResultTag = 1
	TagAccTemporaryFailure        AccessResultTag = 2
	TagAccReadWriteDenied         AccessResultTag = 3
	TagAccObjectUndefined         AccessResultTag = 4
	TagAccObjectClassInconsistent AccessResultTag = 9
	TagAccObjectUnavailable       AccessResultTag = 11
	TagAccTypeUnmatched           AccessResultTag = 12
	TagAccScopeAccessViolated     AccessResultTag = 13
	TagAccDataBlockUnavailable    AccessResultTag = 14
	TagAccLongGetAborted          AccessResultTag = 15
	TagAccNoLongGetInProgress     AccessResultTag = 16
	TagAccLongSetAborted          AccessResultTag = 17
	TagAccNoLongSetInProgress     AccessResultTag = 18
	TagAccDataBlockNumberInvalid  AccessResultTag = 19
	TagAccOtherReason             AccessResultTag = 250
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

func (s AccessResultTag) String() string {
	switch s {
	case TagAccSuccess:
		return "success"
	case TagAccHardwareFault:
		return "hardware-fault"
	case TagAccTemporaryFailure:
		return "temporary-failure"
	case TagAccReadWriteDenied:
		return "read-write-denied"
	case TagAccObjectUndefined:
		return "object-undefined"
	case TagAccObjectClassInconsistent:
		return "object-class-inconsistent"
	case TagAccObjectUnavailable:
		return "object-unavailable"
	case TagAccTypeUnmatched:
		return "type-unmatched"
	case TagAccScopeAccessViolated:
		return "scope-of-access-violated"
	case TagAccDataBlockUnavailable:
		return "data-block-unavailable"
	case TagAccLongGetAborted:
		return "long-get-aborted"
	case TagAccNoLongGetInProgress:
		return "no-long-get-in-progress"
	case TagAccLongSetAborted:
		return "long-set-aborted"
	case TagAccNoLongSetInProgress:
		return "no-long-set-in-progress"
	case TagAccDataBlockNumberInvalid:
		return "data-block-number-invalid"
	case TagAccOtherReason:
		return "other-reason"
	default:
		return "unknown"
	}
}
