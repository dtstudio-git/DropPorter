#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT) || defined(AWDLWIN_AP_COEXISTENCE)
#define AWDLWIN_AF_MAX_BODY 265u
#else
#define AWDLWIN_AF_MAX_BODY 64u
#endif
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
#define AWDLWIN_AF_RAW_METADATA_SIZE 16u
#define AWDLWIN_AF_RAW_80211_HEADER_SIZE 24u
#define AWDLWIN_AF_RAW_BODY_MIN_LENGTH 16u
#define AWDLWIN_AF_RAW_BODY_OFFSET 40u
#define AWDLWIN_AF_RAW_MAX_FRAME_LENGTH 1600u
#define AWDLWIN_AF_RAW_RATE_6_MBPS 12u
/* MgntSendSpecificPacket: management frames are copied without a software FCS. */
#define AWDLWIN_AF_RAW_INNER_OID 0xff0101c8u
#define AWDLWIN_AF_WPS_INNER_OID 0xff0101d0u
#define AWDLWIN_AF_ENCRYPTION_STATUS_INNER_OID 0x0d01011bu
#define AWDLWIN_AF_WPS_IE_CAPACITY 512u
#endif
#define AWDLWIN_AF_REQUEST_PREFIX_SIZE 46u
#define AWDLWIN_AF_ABORT_SIZE 30u

typedef unsigned char AWDLWIN_AF_U8;
typedef unsigned short AWDLWIN_AF_U16;
typedef unsigned int AWDLWIN_AF_U32;
typedef unsigned long long AWDLWIN_AF_U64;

/* Portable CompletionGate transition policy. The LWF owns synchronization and
 * supplies driver-derived completion/quiescence facts to these transitions. */
#define AWDLWIN_CG_NEXT_ADMISSIBLE 0u
#define AWDLWIN_CG_ISSUED 1u
#define AWDLWIN_CG_M3_ACCEPTED 2u
#define AWDLWIN_CG_WAIT_QUIESCENCE 3u
#define AWDLWIN_CG_QUIESCENCE_VERIFIED 4u
#define AWDLWIN_CG_STOP 5u

#define AWDLWIN_CG_STOP_NONE 0u
#define AWDLWIN_CG_STOP_M3_FAILED 1u
#define AWDLWIN_CG_STOP_M3_TIMEOUT 2u
#define AWDLWIN_CG_STOP_MALFORMED_COMPLETION 3u
#define AWDLWIN_CG_STOP_ABORTED 4u
#define AWDLWIN_CG_STOP_LIFECYCLE_CHANGED 5u
#define AWDLWIN_CG_STOP_ID_EXHAUSTED 6u
#define AWDLWIN_CG_STOP_CHALLENGE_EXHAUSTED 7u
#define AWDLWIN_CG_STOP_QUIESCENCE_LOST 8u

#define AWDLWIN_CG_EVIDENCE_REALTEK 1u
#define AWDLWIN_CG_EVIDENCE_WIFI_MAINTAINED 2u
#define AWDLWIN_CG_REALTEK_WORKER_ENDED 0x00000001u
#define AWDLWIN_CG_REALTEK_HELD_LIST_EMPTY 0x00000002u
#define AWDLWIN_CG_REALTEK_BASELINE_NONBUSY 0x00000004u
#define AWDLWIN_CG_REALTEK_WDI_JOBS_EMPTY 0x00000008u
#define AWDLWIN_CG_REALTEK_WDI_COMMANDS_EMPTY 0x00000010u
#define AWDLWIN_CG_REALTEK_REQUIRED_FLAGS 0x0000001fu
#define AWDLWIN_CG_WIFI_MAINTAINED 0x00000001u
#define AWDLWIN_CG_WIFI_NO_RESET 0x00000002u
#define AWDLWIN_CG_WIFI_NO_ERROR 0x00000004u
#define AWDLWIN_CG_WIFI_REQUIRED_FLAGS 0x00000007u
#define AWDLWIN_CG_SOURCE_MANUAL_REALTEK 1u
#define AWDLWIN_CG_SOURCE_MANUAL_WIFI 2u

typedef struct _AWDLWIN_CG_POLICY {
    AWDLWIN_AF_U64 Challenge;
    AWDLWIN_AF_U32 Stage;
    AWDLWIN_AF_U32 EvidenceMask;
    AWDLWIN_AF_U32 StopReason;
    AWDLWIN_AF_U8 PermissionArmed;
    AWDLWIN_AF_U8 EverIssued;
    AWDLWIN_AF_U8 Reserved[2];
} AWDLWIN_CG_POLICY;

typedef struct _AWDLWIN_AF_PARAMETERS {
    AWDLWIN_AF_U16 PortId;
    AWDLWIN_AF_U32 TransactionId;
    AWDLWIN_AF_U32 ChannelNumber;
    AWDLWIN_AF_U32 BandId;
    AWDLWIN_AF_U8 Peer[6];
    AWDLWIN_AF_U32 SendTimeoutMs;
    AWDLWIN_AF_U32 PostAckDwellMs;
    AWDLWIN_AF_U16 BodyLength;
    AWDLWIN_AF_U8 Body[AWDLWIN_AF_MAX_BODY];
} AWDLWIN_AF_PARAMETERS;

typedef enum _AWDLWIN_AF_STATE {
    AwdlWinAfConstructed = 0,
    AwdlWinAfOidPending = 1,
    AwdlWinAfTaskStarted = 2, /* Historical; no longer emitted. */
    AwdlWinAfAbortPending = 3,
    AwdlWinAfTaskCompleted = 4, /* Historical; M4 is diagnostic only. */
    AwdlWinAfFailedBeforeStart = 5,
    AwdlWinAfM3StuckQuarantined = 6,
    AwdlWinAfRequestAccepted = 7,
    AwdlWinAfAbortRejected = 8
} AWDLWIN_AF_STATE;

typedef enum _AWDLWIN_AF_M4_RESULT {
    AwdlWinAfM4OtherTask = 0,
    AwdlWinAfM4Accepted = 1,
    AwdlWinAfM4Duplicate = 2,
    AwdlWinAfM4AfterFailedM3 = 3
} AWDLWIN_AF_M4_RESULT;

typedef struct _AWDLWIN_AF_TRACKER {
    AWDLWIN_AF_STATE State;
    AWDLWIN_AF_U16 PortId;
    AWDLWIN_AF_U32 TransactionId;
    AWDLWIN_AF_U8 M3Seen;
    AWDLWIN_AF_U8 M3Success;
    AWDLWIN_AF_U8 M4Seen;
    AWDLWIN_AF_U8 AbortIssued;
    AWDLWIN_AF_U8 AbortCompleted;
    AWDLWIN_AF_U8 PauseRequested;
    AWDLWIN_AF_U8 Quarantined;
    AWDLWIN_AF_U8 M3TimeoutObserved;
    AWDLWIN_AF_U8 Inconsistent;
    AWDLWIN_AF_U8 AbortSuccess;
} AWDLWIN_AF_TRACKER;

int AwdlWinAfSerializeRequest(const AWDLWIN_AF_PARAMETERS *parameters,
                              AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written);
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
int AwdlWinAfSerializeResponse(const AWDLWIN_AF_PARAMETERS *parameters,
                               AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written);
/* Builds the 16-byte vendor prefix plus a complete 802.11 frame without FCS. */
int AwdlWinAfSerializeRawFrame(const AWDLWIN_AF_PARAMETERS *parameters,
                               const AWDLWIN_AF_U8 sourceMac[6],
                               AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written);
/* Fixed FF0101C8 Set envelope; acceptance is not RF completion. */
int AwdlWinAfSerializeRawRequest(const AWDLWIN_AF_PARAMETERS *parameters,
                                 const AWDLWIN_AF_U8 sourceMac[6],
                                 AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written);
int AwdlWinAfSerializeRawBodyRequest(const AWDLWIN_AF_PARAMETERS *parameters,
                                 const AWDLWIN_AF_U8 *body, size_t bodyLength,
                                 const AWDLWIN_AF_U8 sourceMac[6],
                                 AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written);
/* IE payload includes the WPS OUI/type, excludes the DD element header.
 * Disable also supplies an IE; it is not restoration of a previous IE. */
int AwdlWinAfSerializeWpsRequest(AWDLWIN_AF_U32 transactionId, int enabled,
    const AWDLWIN_AF_U8 *ie, size_t ieLength,
    AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written);
/* Fixed one-byte disable/clear request for the pinned Realtek image.
 * Its expected INVALID_LENGTH completion is not itself proof of clearing. */
int AwdlWinAfSerializeWpsClearRequest(AWDLWIN_AF_U32 transactionId,
    AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written);
/* Fixed EncryptionDisabled (DWORD 1) only; not an arbitrary cipher/OID API. */
int AwdlWinAfSerializeEncryptionDisabledRequest(AWDLWIN_AF_U32 transactionId,
    AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written);
/* Caller builds the MPDU with the existing AWDL codec. Only plain AWDL IPv6
 * Data is accepted; MAC/AWDL sequence bytes are preserved. 12 Mbps, no FCS. */
int AwdlWinAfSerializeRawDataRequest(AWDLWIN_AF_U32 transactionId,
    const AWDLWIN_AF_U8 sourceMac[6], const AWDLWIN_AF_U8 *frame, size_t frameLength,
    AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written);
#endif
int AwdlWinAfSerializeAbort(AWDLWIN_AF_U16 portId, AWDLWIN_AF_U32 abortTransactionId,
                            AWDLWIN_AF_U32 originalTransactionId,
                            AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written);
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
int AwdlWinAfSerializeResponseAbort(AWDLWIN_AF_U16 portId,
                                    AWDLWIN_AF_U32 abortTransactionId,
                                    AWDLWIN_AF_U32 originalTransactionId,
                                    AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written);
#endif
void AwdlWinAfInitialize(AWDLWIN_AF_TRACKER *tracker, AWDLWIN_AF_U16 portId,
                         AWDLWIN_AF_U32 transactionId);
int AwdlWinAfOnM3(AWDLWIN_AF_TRACKER *tracker, int success);
AWDLWIN_AF_M4_RESULT AwdlWinAfOnM4(AWDLWIN_AF_TRACKER *tracker,
                                     AWDLWIN_AF_U16 portId,
                                     AWDLWIN_AF_U32 transactionId);
int AwdlWinAfBeginAbort(AWDLWIN_AF_TRACKER *tracker);
int AwdlWinAfOnAbortCompletion(AWDLWIN_AF_TRACKER *tracker, int success);
void AwdlWinAfMarkM3Stuck(AWDLWIN_AF_TRACKER *tracker);
void AwdlWinAfRequestPause(AWDLWIN_AF_TRACKER *tracker);
int AwdlWinAfCanDrain(const AWDLWIN_AF_TRACKER *tracker);
int AwdlWinAfCanStartNextTask(const AWDLWIN_AF_TRACKER *tracker);
int AwdlWinAfObservationEnded(const AWDLWIN_AF_TRACKER *tracker);

void AwdlWinCgInitialize(AWDLWIN_CG_POLICY *policy);
int AwdlWinCgSetStage(AWDLWIN_CG_POLICY *policy, AWDLWIN_AF_U32 stage);
void AwdlWinCgStop(AWDLWIN_CG_POLICY *policy, AWDLWIN_AF_U32 stopReason);
int AwdlWinCgRefresh(AWDLWIN_CG_POLICY *policy, int m3Seen, int m3Success,
                     int m3Timeout, int malformedCompletion,
                     int issueInProgress, int driverQuiescent);
int AwdlWinCgInvalidateObservation(AWDLWIN_CG_POLICY *policy);

#ifdef __cplusplus
}
#endif
