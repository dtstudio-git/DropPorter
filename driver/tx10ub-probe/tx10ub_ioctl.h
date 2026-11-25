#pragma once

#define AWDLWIN_IOCTL_BASE 0x800
#define IOCTL_AWDLWIN_VALIDATE_AP_PSF \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 30, METHOD_BUFFERED, FILE_READ_DATA)

#define IOCTL_AWDLWIN_GET_VERSION \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_AWDLWIN_ISSUE_READONLY_WDI_QUERY \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AWDLWIN_GET_OID_OBSERVATIONS \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 6, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_AWDLWIN_EXPERIMENT_ACTION_FRAME \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 7, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AWDLWIN_EXPERIMENT_ABORT_ACTION \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 8, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AWDLWIN_GET_ACTION_RESULT \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 9, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_AWDLWIN_GET_ACTION_FRAME_STATUS_LOG \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 10, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_AWDLWIN_GET_TWO_REQUEST_STATE \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 11, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_AWDLWIN_EXPERIMENT_PERMIT_SECOND_ACTION \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 12, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AWDLWIN_GET_COMPLETION_GATE_STATE \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 13, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_AWDLWIN_SUBMIT_COMPLETION_GATE_EVIDENCE \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 14, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AWDLWIN_ARM_COMPLETION_GATE_NEXT \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 15, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AWDLWIN_EXPERIMENT_MANUAL_INTERNAL_ACTION \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 16, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AWDLWIN_GET_REALTEK_CENSUS \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 17, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_AWDLWIN_NATIVE_RX_CONTROL \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 18, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AWDLWIN_GET_NATIVE_RX_SNAPSHOT \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 19, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_AWDLWIN_RX_CAM_CONTROL \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 20, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AWDLWIN_DATA_BROWSE_QUERY \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 21, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AWDLWIN_GET_DATA_QUERY_STATE \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 22, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_AWDLWIN_GET_DATA_QUERY_TRACE \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 24, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_AWDLWIN_GET_DATA_QUERY_CORRELATION \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 25, METHOD_BUFFERED, FILE_READ_DATA)
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
#define IOCTL_AWDLWIN_EXPERIMENT_RAW_ACTION_FRAME \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 23, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AWDLWIN_EXPERIMENT_VENDOR_WPS \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 26, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AWDLWIN_EXPERIMENT_RAW_DATA \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 27, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AWDLWIN_EXPERIMENT_ENCRYPTION_DISABLED \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 28, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AWDLWIN_EXPERIMENT_VENDOR_WPS_CLEAR \
    CTL_CODE(FILE_DEVICE_NETWORK, AWDLWIN_IOCTL_BASE + 29, METHOD_BUFFERED, FILE_WRITE_DATA)
#endif

typedef struct _AWDLWIN_DATA_QUERY_STATE_REQUEST_V1 {
    ULONG Size, Version, TargetIfIndex, Reserved;
    ULONGLONG TargetNetLuidValue;
} AWDLWIN_DATA_QUERY_STATE_REQUEST_V1;

typedef struct _AWDLWIN_DATA_QUERY_STATE_V1 {
    ULONG Size, Version, Running, RestartReady, PoolReady, BackFillKnown;
    ULONG DataBackFillSize, ContextBackFillSize, RestartCount, PreparationReason;
    ULONG AttributeLength, AttributeType, AttributeRevision, AttributeSize;
    ULONG AdvertisedDataBackFillSize, AdvertisedContextBackFillSize;
} AWDLWIN_DATA_QUERY_STATE_V1;

/* Read-only diagnostics. No kernel addresses or packet payload are exported. */
#define AWDLWIN_DATA_QUERY_TRACE_VERSION 1u
#define AWDLWIN_DATA_QUERY_TRACE_CAPACITY 64u
#define AWDLWIN_DQT_SEND_BEFORE 1u
#define AWDLWIN_DQT_SEND_RETURN 2u
#define AWDLWIN_DQT_COMPLETE_SEEN 3u
#define AWDLWIN_DQT_COMPLETE_APPLIED 4u
#define AWDLWIN_DQT_WAIT_END 5u
#define AWDLWIN_DQT_NBL_MATCH 1u
#define AWDLWIN_DQT_SOURCE_MATCH 2u
#define AWDLWIN_DQT_SIGNATURE_MATCH 4u
#define AWDLWIN_DQT_OWNER_MATCH 8u
typedef struct _AWDLWIN_DATA_QUERY_TRACE_RECORD_V1 {
    ULONGLONG Sequence, TransactionId, InterruptTime100ns;
    /* Irql precedes acquisition of the diagnostic lock. Status is the
     * returned NBL status for completion, waitStatus for wait_end, and zero
     * (not a send result) for send_before/send_return. Detail is completion
     * flags for complete_seen, FinishLocked's result for complete_applied.
     * BeforeOutstanding is populated only for complete_applied. */
    ULONG Event, Irql, RestartCount, Flags, Status, Detail, BeforeOutstanding;
    ULONG Running, RestartReady, Outstanding, SubmissionInProgress, CallerActive, Completed;
    ULONG IdleEventSignaled, NdisStatus;
    /* send_before only; other events leave these zero. FrameLength identifies
     * the three validated question templates. */
    ULONG FrameLength, PortNumber, SendFlags, DataBackFillSize, ContextBackFillSize;
    ULONG Dot11Type, Dot11Revision, Dot11Size, Exemption, PhyId, Dot11Flags;
} AWDLWIN_DATA_QUERY_TRACE_RECORD_V1;
typedef struct _AWDLWIN_DATA_QUERY_TRACE_V1 {
    ULONG Size, Version, TargetIfIndex, RecordCount;
    /* ModuleId distinguishes filter attaches within one driver load. */
    ULONGLONG TargetNetLuidValue, ModuleId, TransactionId, Sequence;
    ULONGLONG OverwrittenRecords, CallbackCount;
    ULONG RestartCount, Running, Outstanding, SubmissionInProgress, CallerActive, Completed;
    ULONG NdisStatus, IdleEventSignaled;
    AWDLWIN_DATA_QUERY_TRACE_RECORD_V1 Records[AWDLWIN_DATA_QUERY_TRACE_CAPACITY];
} AWDLWIN_DATA_QUERY_TRACE_V1;

/* Experimental, admin/SYSTEM-only control device: the self-created NBL address
 * is intentionally exported for equality with WDI WPP's pNBL, never dereferenced
 * after submission. Existing state/result/trace V1 layouts remain unchanged. */
#define AWDLWIN_DATA_QUERY_CORRELATION_VERSION 1u
#define AWDLWIN_DATA_QUERY_CORRELATION_CAPACITY 16u
typedef struct _AWDLWIN_DATA_QUERY_CORRELATION_RECORD_V1 {
    ULONGLONG TransactionId, NblAddress, InterruptTime100ns, SystemTime100ns;
    LONGLONG PerformanceCounter, PerformanceFrequency;
    ULONG RestartCount, FrameLength;
} AWDLWIN_DATA_QUERY_CORRELATION_RECORD_V1;
typedef struct _AWDLWIN_DATA_QUERY_CORRELATION_V1 {
    ULONG Size, Version, TargetIfIndex, RecordCount;
    ULONGLONG TargetNetLuidValue, ModuleId, OverwrittenRecords;
    AWDLWIN_DATA_QUERY_CORRELATION_RECORD_V1 Records[AWDLWIN_DATA_QUERY_CORRELATION_CAPACITY];
} AWDLWIN_DATA_QUERY_CORRELATION_V1;

#define AWDLWIN_DATA_QUERY_VERSION 2u
#define AWDLWIN_DATA_QUERY_CONFIRM_MAGIC 0x32515444u /* DTQ2 */
#define AWDLWIN_DATA_QUERY_AIRDROP_FRAME_LENGTH 125u
#define AWDLWIN_DATA_QUERY_APP_SVC_PRE_PAIR_FRAME_LENGTH 131u
#define AWDLWIN_DATA_QUERY_APPLICATION_SERVICE_PAIRING_FRAME_LENGTH 143u
#define AWDLWIN_DATA_QUERY_FRAME_CAPACITY \
    AWDLWIN_DATA_QUERY_APPLICATION_SERVICE_PAIRING_FRAME_LENGTH
typedef struct _AWDLWIN_DATA_QUERY_REQUEST_V1 {
    ULONG Size;
    ULONG Version;
    ULONG TargetIfIndex;
    ULONG ConfirmMagic;
    ULONGLONG TargetNetLuidValue;
    ULONG FrameLength;
    ULONG Reserved;
    UCHAR Frame[AWDLWIN_DATA_QUERY_FRAME_CAPACITY];
} AWDLWIN_DATA_QUERY_REQUEST_V1;
typedef struct _AWDLWIN_DATA_QUERY_RESULT_V1 {
    ULONG Size;
    ULONG Version;
    ULONG Submitted;
    ULONG Completed;
    ULONG NdisStatus;
    ULONG TimedOut;
    ULONG DataBackFillSize;
    ULONG ContextBackFillSize;
} AWDLWIN_DATA_QUERY_RESULT_V1;

#define AWDLWIN_TX_PROBE_DIAGNOSTIC 0u
#define AWDLWIN_TX_PROBE_VENDOR_ID 1u
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
/* Fixed MAC RX filter experiments; no caller-supplied register/value/duration. */
#define AWDLWIN_TX_PROBE_RX_FILTER_IHV 4u
#define AWDLWIN_TX_PROBE_RX_DATA_FILTER_IHV 16u
#define AWDLWIN_TX_PROBE_RX_CAM_CTRL_IHV 17u
#define AWDLWIN_TX_PROBE_RX_CAM_DIS_IHV 18u
#define AWDLWIN_IS_RX_REGISTER_PROBE(k) ((k) == AWDLWIN_TX_PROBE_RX_FILTER_IHV || \
    ((k) >= AWDLWIN_TX_PROBE_RX_DATA_FILTER_IHV && (k) <= AWDLWIN_TX_PROBE_RX_CAM_DIS_IHV))

#define AWDLWIN_RX_CAM_VERSION 1u
#define AWDLWIN_RX_CAM_ENABLE 1u
#define AWDLWIN_RX_CAM_REFRESH 2u
#define AWDLWIN_RX_CAM_DISABLE 3u
typedef struct _AWDLWIN_RX_CAM_CONTROL_REQUEST {
    ULONG Size;
    ULONG Version;
    ULONG Operation;
    ULONG TargetIfIndex;
    ULONGLONG TargetNetLuidValue;
    ULONG Reserved[2];
} AWDLWIN_RX_CAM_CONTROL_REQUEST;
typedef struct _AWDLWIN_RX_CAM_CONTROL_RESULT {
    ULONG Baseline;
    ULONG Relaxed;
    ULONG Restored;
    ULONG Samples;
    ULONG Reapplied;
    ULONG RestoreStatus;
    ULONG Current;
    ULONG Active;
    ULONG FailureStage;
    ULONG FailureClassification;
    ULONG FailureNdisStatus;
    ULONG FailureWdiStatus;
    ULONG FailureValue;
    ULONG OperationStatus;
} AWDLWIN_RX_CAM_CONTROL_RESULT;
#endif
#define AWDLWIN_TX_PROBE_WDI_STATISTICS 2u
#define AWDLWIN_TX_RESPONSE_CAPACITY (64u * 1024u)
#define AWDLWIN_TX_WDI_HEADER_SIZE 16u
#if defined(AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT) || defined(AWDLWIN_AP_COEXISTENCE)
/* Distinct ABI: ordinary CLI/driver pairs must reject this larger request. */
#define AWDLWIN_ACTION_VERSION 2u
#define AWDLWIN_ACTION_BODY_CAPACITY 265u
#else
#define AWDLWIN_ACTION_VERSION 1u
#define AWDLWIN_ACTION_BODY_CAPACITY 64u
#endif
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
/* Version 2 rejects stale FF0111CD CLI/driver pairs. */
#define AWDLWIN_RAW_ACTION_VERSION 2u
#define AWDLWIN_RAW_ACTION_CONFIRM_MAGIC 0x32574152u /* RAW2 */
#define AWDLWIN_TX_PROBE_RAW_ACTION 6u
typedef struct _AWDLWIN_RAW_ACTION_REQUEST_V1 {
    ULONG Size;
    ULONG Version;
    ULONG ConfirmMagic;
    ULONG TargetIfIndex;
    ULONGLONG TargetNetLuidValue;
    ULONG ExpectedChannel;
    ULONG BodyLength;
    UCHAR Body[AWDLWIN_ACTION_BODY_CAPACITY];
} AWDLWIN_RAW_ACTION_REQUEST_V1, *PAWDLWIN_RAW_ACTION_REQUEST_V1;
typedef struct _AWDLWIN_RAW_ACTION_RESULT_V1 {
    ULONG Size;
    ULONG Version;
    ULONG OidIssued;
    ULONG CompletionObserved;
    ULONG VendorRequestAccepted;
    ULONG ResponseValidated;
    ULONG AdmissionBusyReason;
    ULONG OperationStatus;
    ULONG SubmitNdisStatus;
    ULONG FinalNdisStatus;
    ULONG WdiHeaderStatus;
    ULONG TransactionId;
    ULONG InputLength;
    ULONG BytesWritten;
    ULONG BytesRead;
    ULONG BytesNeeded;
} AWDLWIN_RAW_ACTION_RESULT_V1, *PAWDLWIN_RAW_ACTION_RESULT_V1;
#define AWDLWIN_RAW_ACTION_BUSY_NONE 0u
#define AWDLWIN_RAW_ACTION_BUSY_ACTION 1u
#define AWDLWIN_RAW_ACTION_BUSY_SELF_OID 2u
#define AWDLWIN_RAW_ACTION_BUSY_DATA_QUERY 3u
/* These IOCTLs return RAW_ACTION_RESULT_V1/version 2: vendor acceptance only.
 * They neither change channel nor automatically enable WPS or restore its IE. */
#define AWDLWIN_VENDOR_WPS_VERSION 1u
#define AWDLWIN_VENDOR_WPS_CONFIRM_MAGIC 0x31535057u /* WPS1 */
#define AWDLWIN_VENDOR_WPS_CLEAR_VERSION 1u
#define AWDLWIN_VENDOR_WPS_CLEAR_CONFIRM_MAGIC 0x31435057u /* WPC1 */
#define AWDLWIN_RAW_DATA_VERSION 1u
#define AWDLWIN_RAW_DATA_CONFIRM_MAGIC 0x31544144u /* DAT1 */
#define AWDLWIN_ENCRYPTION_DISABLED_VERSION 1u
#define AWDLWIN_ENCRYPTION_DISABLED_CONFIRM_MAGIC 0x31434e45u /* ENC1 */

/* Explicit adapter-wide cipher disable. No automatic WPS/channel changes,
 * transmission, or restoration; no caller-selected cipher or OID. */
typedef struct _AWDLWIN_ENCRYPTION_DISABLED_REQUEST_V1 {
    ULONG Size;
    ULONG Version;
    ULONG ConfirmMagic;
    ULONG TargetIfIndex;
    ULONGLONG TargetNetLuidValue;
} AWDLWIN_ENCRYPTION_DISABLED_REQUEST_V1;
typedef struct _AWDLWIN_VENDOR_WPS_REQUEST_V1 {
    ULONG Size;
    ULONG Version;
    ULONG ConfirmMagic;
    ULONG TargetIfIndex;
    ULONGLONG TargetNetLuidValue;
    ULONG Enabled;
    ULONG IeLength;
    UCHAR Ie[512]; /* OUI/type plus WPS attributes; no DD element header. */
} AWDLWIN_VENDOR_WPS_REQUEST_V1;
typedef struct _AWDLWIN_VENDOR_WPS_CLEAR_REQUEST_V1 {
    ULONG Size;
    ULONG Version;
    ULONG ConfirmMagic;
    ULONG TargetIfIndex;
    ULONGLONG TargetNetLuidValue;
} AWDLWIN_VENDOR_WPS_CLEAR_REQUEST_V1;
/* Raw OID status is preserved. KnownError identifies only the fixed clear
 * request's documented INVALID_LENGTH result. Readback fields expose summary
 * values only; no kernel address or IE bytes leave the driver. */
typedef struct _AWDLWIN_VENDOR_WPS_CLEAR_RESULT_V1 {
    AWDLWIN_RAW_ACTION_RESULT_V1 Raw;
    ULONG ClearRequested;
    ULONG KnownError;
    ULONG ObservationValid;
    ULONG Cleared;
    ULONG Enabled;
    ULONG RelatedFlag;
    ULONG IeLength;
    ULONG IeBytesZero;
    ULONG ObservationStatus;
} AWDLWIN_VENDOR_WPS_CLEAR_RESULT_V1, *PAWDLWIN_VENDOR_WPS_CLEAR_RESULT_V1;
typedef struct _AWDLWIN_RAW_DATA_REQUEST_V1 {
    ULONG Size;
    ULONG Version;
    ULONG ConfirmMagic;
    ULONG TargetIfIndex;
    ULONGLONG TargetNetLuidValue;
    ULONG ExpectedChannel; /* Caller observation, not a retune instruction. */
    ULONG FrameLength;
    UCHAR Frame[1600]; /* Complete ordinary AWDL IPv6 MPDU, without FCS. */
} AWDLWIN_RAW_DATA_REQUEST_V1;
#endif
#define AWDLWIN_ACTION_EXPERIMENT_MAGIC 0x31584641u
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
#define AWDLWIN_ACTION_RESPONSE_EXPERIMENT_MAGIC 0x31525341u /* ASR1 */
#endif
#define AWDLWIN_TWO_REQUEST_VERSION 1u
#define AWDLWIN_TWO_REQUEST_PERMIT_MAGIC 0x32584641u
#define AWDLWIN_COMPLETION_GATE_VERSION 1u
#define AWDLWIN_COMPLETION_GATE_ARM_MAGIC 0x31474341u
#define AWDLWIN_MANUAL_INTERNAL_VERSION 1u
#define AWDLWIN_MANUAL_INTERNAL_CONFIRM_MAGIC 0x314d4141u
#define AWDLWIN_MANUAL_INTERNAL_ACK_UNKNOWN_HISTORY 0x00000001u
#define AWDLWIN_MANUAL_INTERNAL_ACK_REQUIRED_FLAGS 0x00000001u

#define AWDLWIN_MANUAL_INTERNAL_ALL_WORKERS_FREE 0x00000001u
#define AWDLWIN_MANUAL_INTERNAL_QUEUES_EMPTY 0x00000002u
#define AWDLWIN_MANUAL_INTERNAL_REGISTRY_EMPTY 0x00000004u
#define AWDLWIN_MANUAL_INTERNAL_BASELINE_NONBUSY 0x00000008u
#define AWDLWIN_MANUAL_INTERNAL_WDI_JOBS_EMPTY 0x00000010u
#define AWDLWIN_MANUAL_INTERNAL_WDI_COMMANDS_EMPTY 0x00000020u
#define AWDLWIN_MANUAL_INTERNAL_WDI_EVENTS_EMPTY 0x00000040u
#define AWDLWIN_MANUAL_INTERNAL_WIFI_MAINTAINED 0x00000080u
#define AWDLWIN_MANUAL_INTERNAL_WIFI_NO_RESET 0x00000100u
#define AWDLWIN_MANUAL_INTERNAL_WIFI_NO_ERROR 0x00000200u
#define AWDLWIN_MANUAL_INTERNAL_REQUIRED_FLAGS 0x000003ffu

#define AWDLWIN_COMPLETION_GATE_EVIDENCE_REALTEK 1u
#define AWDLWIN_COMPLETION_GATE_EVIDENCE_WIFI_MAINTAINED 2u
#define AWDLWIN_COMPLETION_GATE_REALTEK_WORKER_ENDED 0x00000001u
#define AWDLWIN_COMPLETION_GATE_REALTEK_HELD_LIST_EMPTY 0x00000002u
#define AWDLWIN_COMPLETION_GATE_REALTEK_BASELINE_NONBUSY 0x00000004u
#define AWDLWIN_COMPLETION_GATE_REALTEK_WDI_JOBS_EMPTY 0x00000008u
#define AWDLWIN_COMPLETION_GATE_REALTEK_WDI_COMMANDS_EMPTY 0x00000010u
#define AWDLWIN_COMPLETION_GATE_REALTEK_REQUIRED_FLAGS 0x0000001fu
#define AWDLWIN_COMPLETION_GATE_WIFI_MAINTAINED 0x00000001u
#define AWDLWIN_COMPLETION_GATE_WIFI_NO_RESET 0x00000002u
#define AWDLWIN_COMPLETION_GATE_WIFI_NO_ERROR 0x00000004u
#define AWDLWIN_COMPLETION_GATE_WIFI_REQUIRED_FLAGS 0x00000007u
#define AWDLWIN_COMPLETION_GATE_SOURCE_MANUAL_REALTEK 1u
#define AWDLWIN_COMPLETION_GATE_SOURCE_MANUAL_WIFI 2u
#define AWDLWIN_REALTEK_CENSUS_SOURCE_KERNEL_RESOURCE 0x1001u
#define AWDLWIN_COMPLETION_GATE_STOP_NONE 0u
#define AWDLWIN_COMPLETION_GATE_STOP_M3_FAILED 1u
#define AWDLWIN_COMPLETION_GATE_STOP_M3_TIMEOUT 2u
#define AWDLWIN_COMPLETION_GATE_STOP_MALFORMED_COMPLETION 3u
#define AWDLWIN_COMPLETION_GATE_STOP_ABORTED 4u
#define AWDLWIN_COMPLETION_GATE_STOP_LIFECYCLE_CHANGED 5u
#define AWDLWIN_COMPLETION_GATE_STOP_ID_EXHAUSTED 6u
#define AWDLWIN_COMPLETION_GATE_STOP_CHALLENGE_EXHAUSTED 7u
#define AWDLWIN_COMPLETION_GATE_STOP_QUIESCENCE_LOST 8u
#define AWDLWIN_COMPLETION_GATE_STOP_HISTORY_EXHAUSTED 9u
#define AWDLWIN_COMPLETION_GATE_STOP_CORRELATION_LOST 10u

typedef enum _AWDLWIN_COMPLETION_GATE_STAGE {
    AwdlWinCompletionGateNextAdmissible = 0,
    AwdlWinCompletionGateIssued = 1,
    AwdlWinCompletionGateM3Accepted = 2,
    AwdlWinCompletionGateWaitQuiescence = 3,
    AwdlWinCompletionGateQuiescenceVerified = 4,
    AwdlWinCompletionGateStop = 5
} AWDLWIN_COMPLETION_GATE_STAGE;

typedef struct _AWDLWIN_COMPLETION_GATE_ID_V1 {
    UCHAR LoadId[16];
    ULONGLONG FilterId;
    ULONGLONG ActionId;
    ULONG TransactionId;
    USHORT PortId;
    USHORT Reserved;
    ULONGLONG LifecycleGeneration;
} AWDLWIN_COMPLETION_GATE_ID_V1;

typedef struct _AWDLWIN_COMPLETION_GATE_TARGET_V1 {
    ULONG Size;
    ULONG Version;
    ULONG TargetIfIndex;
    ULONG Reserved;
    ULONGLONG TargetNetLuidValue;
} AWDLWIN_COMPLETION_GATE_TARGET_V1;

/* Read-only, optional fixed-image experimental build. No permission/evidence
 * mutation. ObservedMask uses the four resource bits only, NOT worker-ended,
 * WDI jobs/commands/events, Wi-Fi continuity or absence of past Reset/error. */
typedef struct _AWDLWIN_REALTEK_CENSUS_REQUEST_V1 {
    AWDLWIN_COMPLETION_GATE_TARGET_V1 Target;
    AWDLWIN_COMPLETION_GATE_ID_V1 Identity;
    ULONGLONG ObservationGeneration;
    ULONGLONG ObservationChallenge;
} AWDLWIN_REALTEK_CENSUS_REQUEST_V1;

typedef struct _AWDLWIN_REALTEK_CENSUS_RESULT_V1 {
    ULONG Size;
    ULONG Version;
    AWDLWIN_COMPLETION_GATE_ID_V1 Identity;
    ULONGLONG ObservationGeneration;
    ULONGLONG ObservationChallenge;
    ULONGLONG CapturedInterruptTime100ns;
    ULONG Source; /* AWDLWIN_REALTEK_CENSUS_SOURCE_KERNEL_RESOURCE */
    ULONG ObservedMask; /* 0xF: workers free, queues/registry empty, nonbusy */
    ULONG FreeWorkers;
    ULONG FreeSlotMask;
} AWDLWIN_REALTEK_CENSUS_RESULT_V1;

typedef struct _AWDLWIN_COMPLETION_GATE_EVIDENCE_V1 {
    ULONG Size;
    ULONG Version;
    ULONG TargetIfIndex;
    ULONG EvidenceKind;
    ULONG EvidenceFlags;
    ULONG EvidenceSource;
    ULONG Reserved0;
    ULONG Reserved1;
    ULONGLONG TargetNetLuidValue;
    AWDLWIN_COMPLETION_GATE_ID_V1 Identity;
    ULONGLONG ObservationGeneration;
    ULONGLONG ObservationChallenge;
    ULONGLONG ObservedUtcFileTime100ns;
} AWDLWIN_COMPLETION_GATE_EVIDENCE_V1;

typedef struct _AWDLWIN_COMPLETION_GATE_ARM_V1 {
    ULONG Size;
    ULONG Version;
    ULONG TargetIfIndex;
    ULONG Reserved0;
    ULONGLONG TargetNetLuidValue;
    AWDLWIN_COMPLETION_GATE_ID_V1 Identity;
    ULONGLONG ObservationGeneration;
    ULONGLONG ObservationChallenge;
    ULONG ArmMagic;
    ULONG Reserved1;
} AWDLWIN_COMPLETION_GATE_ARM_V1;

typedef struct _AWDLWIN_COMPLETION_GATE_STATE_V1 {
    ULONG Size;
    ULONG Version;
    ULONG Stage;
    ULONG EvidenceMask;
    ULONG StopReason;
    ULONG PermissionArmed;
    ULONG TargetIfIndex;
    ULONG Reserved;
    ULONGLONG TargetNetLuidValue;
    AWDLWIN_COMPLETION_GATE_ID_V1 Identity;
    ULONGLONG ObservationGeneration;
    ULONGLONG ObservationChallenge;
    ULONG M3CallbackRefs;
    ULONG CallbackRefs;
    ULONG IssueInProgress;
    ULONG SubmissionInProgress;
    ULONG AbortSubmissionInProgress;
    ULONG DriverQuiescent;
    ULONG M3Seen;
    ULONG M3Success;
    ULONG FinalNdisStatus;
    ULONG WdiHeaderStatus;
    ULONG M4Seen;
    ULONG RetiredActionCount;
    ULONG HistoryCount;
    ULONG Reserved2;
    ULONG EvidenceSource[2];
    ULONGLONG ObservedUtcFileTime100ns[2];
    ULONGLONG ReceiptInterruptTime100ns[2];
} AWDLWIN_COMPLETION_GATE_STATE_V1, *PAWDLWIN_COMPLETION_GATE_STATE_V1;

/* Opaque identities, not kernel pointers. Existing V1 Action ABI is unchanged. */
typedef struct _AWDLWIN_TWO_REQUEST_ID_V1 {
    UCHAR LoadId[16];
    ULONGLONG FilterId;
    ULONGLONG ActionId;
    ULONG TransactionId;
    USHORT PortId;
    USHORT Reserved;
} AWDLWIN_TWO_REQUEST_ID_V1;

typedef struct _AWDLWIN_TWO_REQUEST_CONTROL_V1 {
    ULONG Size;
    ULONG Version;
    ULONG PermitMagic;
    ULONG TargetIfIndex;
    ULONGLONG TargetNetLuidValue;
    AWDLWIN_TWO_REQUEST_ID_V1 Identity;
} AWDLWIN_TWO_REQUEST_CONTROL_V1;

typedef struct _AWDLWIN_TWO_REQUEST_STATE_V1 {
    ULONG Size;
    ULONG Version;
    ULONG Enabled;
    ULONG IssuedCount;
    ULONG PermitEverGranted;
    ULONG PermitArmed;
    ULONG PermitEligible;
    ULONG RetiredActionCount;
    AWDLWIN_TWO_REQUEST_ID_V1 Identity;
    ULONG M3Seen;
    ULONG M4Seen;
    ULONG CallbackRefs;
    ULONG IssueInProgress;
    ULONG SubmissionInProgress;
    ULONG AbortSubmissionInProgress;
} AWDLWIN_TWO_REQUEST_STATE_V1;

typedef struct _AWDLWIN_ACTION_REQUEST_V1 {
    ULONG Size;
    ULONG Version;
    ULONG ExperimentMagic;
    ULONG TargetIfIndex;
    ULONGLONG TargetNetLuidValue;
    ULONG ChannelNumber;
    ULONG BandId;
    ULONG SendTimeoutMs;
    ULONG PostAckDwellMs;
    USHORT PortId;
    USHORT BodyLength;
    UCHAR Peer[6];
    UCHAR Body[AWDLWIN_ACTION_BODY_CAPACITY];
} AWDLWIN_ACTION_REQUEST_V1, *PAWDLWIN_ACTION_REQUEST_V1;

/* Single-call experimental manual issue. Snapshot assertions are not
 * CompletionGate evidence and do not advance its evidence mask. */
typedef struct _AWDLWIN_MANUAL_INTERNAL_ACTION_V1 {
    ULONG Size;
    ULONG Version;
    ULONG ConfirmMagic;
    ULONG SnapshotFlags;
    ULONG AcknowledgementFlags;
    ULONG Reserved;
    AWDLWIN_COMPLETION_GATE_ID_V1 PriorIdentity;
    ULONGLONG ObservationGeneration;
    ULONGLONG ObservationChallenge;
    ULONGLONG ObservedUtcFileTime100ns;
    AWDLWIN_ACTION_REQUEST_V1 Action;
} AWDLWIN_MANUAL_INTERNAL_ACTION_V1;

typedef struct _AWDLWIN_ACTION_CONTROL_V1 {
    ULONG Size;
    ULONG Version;
    ULONG ExperimentMagic;
    ULONG TargetIfIndex;
    ULONGLONG TargetNetLuidValue;
    ULONG TransactionId;
    USHORT PortId;
    USHORT Reserved;
} AWDLWIN_ACTION_CONTROL_V1, *PAWDLWIN_ACTION_CONTROL_V1;

typedef struct _AWDLWIN_ACTION_RESULT_V1 {
    ULONG Size;
    ULONG Version;
    ULONG Classification;
    ULONG OidIssued;
    ULONG TargetIfIndex;
    ULONGLONG TargetNetLuidValue;
    ULONG TransactionId;
    ULONG AbortTransactionId;
    USHORT PortId;
    USHORT TaskState;
    ULONG M3Seen;
    ULONG M4Seen;
    ULONG AbortIssued;
    ULONG AbortCompleted;
    ULONG SubmitNdisStatus;
    ULONG FinalNdisStatus;
    ULONG WdiHeaderStatus;
    ULONG M4HeaderStatus;
    ULONG AbortNdisStatus;
    ULONG WrongM4Count;
    ULONG DuplicateM4Count;
    ULONG StopReason;
    ULONG LastM4RejectionReason;
} AWDLWIN_ACTION_RESULT_V1, *PAWDLWIN_ACTION_RESULT_V1;

#define AWDLWIN_ACTION_CLASS_NOT_ISSUED 0u
#define AWDLWIN_ACTION_CLASS_OID_PENDING 1u
#define AWDLWIN_ACTION_CLASS_TASK_STARTED 2u /* Historical; no longer emitted. */
#define AWDLWIN_ACTION_CLASS_TASK_COMPLETED 3u /* Historical; no longer emitted. */
#define AWDLWIN_ACTION_CLASS_FAILED_BEFORE_START 4u
#define AWDLWIN_ACTION_CLASS_UNVERIFIED 5u /* Historical; no longer emitted. */
#define AWDLWIN_ACTION_CLASS_STOP 6u
#define AWDLWIN_ACTION_CLASS_REQUEST_ACCEPTED 7u
#define AWDLWIN_ACTION_CLASS_ABORT_REJECTED 8u
#define AWDLWIN_ACTION_CLASS_ABORT_PENDING 9u
#define AWDLWIN_ACTION_STOP_NONE 0u
#define AWDLWIN_ACTION_STOP_M3_STUCK 1u
#define AWDLWIN_ACTION_STOP_M4_UNOBSERVED 2u /* Historical; no longer emitted. */
#define AWDLWIN_ACTION_STOP_INCONSISTENT_COMPLETION 3u
#define AWDLWIN_ACTION_M4_REJECTION_NONE 0u
#define AWDLWIN_ACTION_M4_REJECTION_DUPLICATE 1u
#define AWDLWIN_ACTION_M4_REJECTION_AFTER_FAILED_M3 2u

#define AWDLWIN_ACTION_FRAME_STATUS_LOG_VERSION_V1 1u
#define AWDLWIN_ACTION_FRAME_STATUS_LOG_VERSION 2u
#define AWDLWIN_ACTION_FRAME_STATUS_LOG_CAPACITY 32u
#define AWDLWIN_ACTION_FRAME_STATUS_PREFIX_CAPACITY_V1 512u
#define AWDLWIN_ACTION_FRAME_STATUS_PREFIX_CAPACITY 4138u

typedef struct _AWDLWIN_ACTION_FRAME_STATUS_RECORD_V1 {
    ULONGLONG Sequence;
    ULONGLONG InterruptTime100ns;
    ULONGLONG TargetNetLuidValue;
    ULONGLONG FilterNetLuidValue;
    ULONG TargetIfIndex;
    ULONG FilterIfIndex;
    ULONG StatusCode;
    ULONG PortNumber;
    ULONG OriginalLength;
    ULONG CopiedLength;
    UCHAR Prefix[AWDLWIN_ACTION_FRAME_STATUS_PREFIX_CAPACITY_V1];
} AWDLWIN_ACTION_FRAME_STATUS_RECORD_V1, *PAWDLWIN_ACTION_FRAME_STATUS_RECORD_V1;

typedef struct _AWDLWIN_ACTION_FRAME_STATUS_LOG_V1 {
    ULONG Size;
    ULONG Version;
    ULONG Count;
    ULONG Reserved;
    AWDLWIN_ACTION_FRAME_STATUS_RECORD_V1 Records[AWDLWIN_ACTION_FRAME_STATUS_LOG_CAPACITY];
} AWDLWIN_ACTION_FRAME_STATUS_LOG_V1, *PAWDLWIN_ACTION_FRAME_STATUS_LOG_V1;

typedef struct _AWDLWIN_ACTION_FRAME_STATUS_RECORD_V2 {
    ULONGLONG Sequence;
    ULONGLONG InterruptTime100ns;
    ULONGLONG TargetNetLuidValue;
    ULONGLONG FilterNetLuidValue;
    ULONG TargetIfIndex;
    ULONG FilterIfIndex;
    ULONG StatusCode;
    ULONG PortNumber;
    ULONG OriginalLength;
    ULONG CopiedLength;
    UCHAR Prefix[AWDLWIN_ACTION_FRAME_STATUS_PREFIX_CAPACITY];
} AWDLWIN_ACTION_FRAME_STATUS_RECORD_V2, *PAWDLWIN_ACTION_FRAME_STATUS_RECORD_V2;

typedef struct _AWDLWIN_ACTION_FRAME_STATUS_LOG_V2 {
    ULONG Size;
    ULONG Version;
    ULONG Count;
    ULONG Reserved;
    AWDLWIN_ACTION_FRAME_STATUS_RECORD_V2 Records[AWDLWIN_ACTION_FRAME_STATUS_LOG_CAPACITY];
} AWDLWIN_ACTION_FRAME_STATUS_LOG_V2, *PAWDLWIN_ACTION_FRAME_STATUS_LOG_V2;

#define AWDLWIN_G2_VERSION 1u
#define AWDLWIN_G2_OUTPUT_CAPACITY (1024u * 1024u)
#define AWDLWIN_G2_MAX_TLV_COUNT 4096u
#define AWDLWIN_G2_MAX_TARGET_DIAGNOSTICS 16u
#define AWDLWIN_G2_REQUEST_FLAG_DIAGNOSTIC_ONLY 0x00000001u
#define AWDLWIN_G2_REQUEST_FLAG_RX_READBACK 0x00000002u

typedef struct _AWDLWIN_G2_REQUEST_V1 {
    ULONG Version;
    ULONG Flags;
    ULONG TargetIfIndex;
    ULONGLONG TargetNetLuidValue;
    ULONG ProbeKind;
    USHORT ObservedPortId;
    USHORT Reserved;
} AWDLWIN_G2_REQUEST_V1, *PAWDLWIN_G2_REQUEST_V1;

typedef enum _AWDLWIN_G2_CLASSIFICATION {
    AwdlWinG2ClassificationNone = 0,
    AwdlWinG2Reachable = 1,
    AwdlWinG2RejectedNdis = 2,
    AwdlWinG2RejectedWdi = 3,
    AwdlWinG2MalformedResponse = 4,
    AwdlWinG2OidTimeoutCanceled = 5,
    AwdlWinG2OidStuckAfterCancel = 6,
    AwdlWinG2Unstable = 7,
    AwdlWinG2TargetNotFound = 8,
    AwdlWinG2TargetAmbiguous = 9,
    AwdlWinG2DeviceNotReady = 10,
    AwdlWinG2DeviceBusy = 11,
    AwdlWinG2InsufficientResources = 12,
    AwdlWinG2TargetSelected = 13
} AWDLWIN_G2_CLASSIFICATION;

typedef enum _AWDLWIN_G2_COMPLETION_MODE {
    AwdlWinG2CompletionNone = 0,
    AwdlWinG2CompletionImmediate = 1,
    AwdlWinG2CompletionPending = 2,
    AwdlWinG2CompletionCanceled = 3,
    AwdlWinG2CompletionStuck = 4
} AWDLWIN_G2_COMPLETION_MODE;

typedef struct _AWDLWIN_G2_TARGET_DIAGNOSTIC {
    ULONG IfIndex;
    ULONGLONG NetLuidValue;
    ULONG BaseMiniportIfIndex;
    ULONGLONG BaseMiniportNetLuidValue;
    ULONG LowerIfIndex;
    ULONGLONG LowerIfNetLuidValue;
    ULONG State;
} AWDLWIN_G2_TARGET_DIAGNOSTIC, *PAWDLWIN_G2_TARGET_DIAGNOSTIC;

typedef struct _AWDLWIN_G2_RESULT_V1 {
    ULONG Size;
    ULONG Version;
    ULONG Classification;
    ULONG OidIssued;
    ULONG CompletionMode;
    ULONG SubmitNdisStatus;
    ULONG FinalNdisStatus;
    ULONG WdiHeaderStatus;
    ULONG BytesWritten;
    ULONG BytesNeeded;
    ULONG SupportedRevision;
    ULONG TransactionId;
    ULONG TlvCount;
    ULONG HasInterfaceAttributes;
    ULONG HasStationAttributes;
    ULONG HasApAttributes;
    ULONG HasP2pAttributes;
    ULONG BandInfoCount;
    ULONG PhyInfoCount;
    ULONG TargetMatchCount;
    ULONG TargetDiagnosticCount;
    ULONG TargetDiagnosticsTruncated;
    ULONG TargetSelectionStatus;
    AWDLWIN_G2_TARGET_DIAGNOSTIC TargetDiagnostics[AWDLWIN_G2_MAX_TARGET_DIAGNOSTICS];
    ULONG ProbeKind;
    ULONG Oid;
    ULONG RequestType;
    USHORT PortId;
    USHORT Reserved;
    ULONG BytesRead;
    ULONG CompletionCallbackObserved;
    ULONG VendorId;
    ULONG MacStatisticsTlvCount;
    ULONG PhyStatisticsTlvCount;
    ULONG ResponseLength;
    UCHAR Response[AWDLWIN_TX_RESPONSE_CAPACITY];
} AWDLWIN_G2_RESULT_V1, *PAWDLWIN_G2_RESULT_V1;

typedef struct _AWDLWIN_VERSION_OUTPUT {
    ULONG Size;
    ULONG Version;
    ULONG Flags;
} AWDLWIN_VERSION_OUTPUT, *PAWDLWIN_VERSION_OUTPUT;

#define AWDLWIN_OID_OBSERVATION_VERSION 2u
#define AWDLWIN_OID_OBSERVATION_CAPACITY 256u
#define AWDLWIN_OID_OBSERVATION_PHASE_REQUEST 1u
#define AWDLWIN_OID_OBSERVATION_PHASE_COMPLETION 2u

typedef struct _AWDLWIN_OID_OBSERVATION_RECORD_V1 {
    ULONGLONG Sequence;
    ULONG Oid;
    ULONG RequestType;
    ULONG PortNumber;
    ULONG InputBufferLength;
    ULONG OutputBufferLength;
    ULONG MethodId;
    ULONG Phase;
    ULONG Reserved;
} AWDLWIN_OID_OBSERVATION_RECORD_V1, *PAWDLWIN_OID_OBSERVATION_RECORD_V1;

typedef struct _AWDLWIN_OID_OBSERVATIONS_V1 {
    ULONG Size;
    ULONG Version;
    ULONG Count;
    ULONG Reserved;
    AWDLWIN_OID_OBSERVATION_RECORD_V1 Records[AWDLWIN_OID_OBSERVATION_CAPACITY];
} AWDLWIN_OID_OBSERVATIONS_V1, *PAWDLWIN_OID_OBSERVATIONS_V1;

// V2 captures all incoming OID metadata. Only a WDI candidate's fixed 16-byte
// header is copied; request TLVs can contain connection secrets.
typedef struct _AWDLWIN_OID_OBSERVATION_RECORD_V2 {
    ULONGLONG Sequence;
    ULONGLONG InterruptTime100ns;
    ULONGLONG FilterNetLuidValue;
    ULONGLONG BaseMiniportNetLuidValue;
    ULONG FilterIfIndex;
    ULONG BaseMiniportIfIndex;
    ULONG Oid;
    ULONG RequestType;
    ULONG PortNumber;
    ULONG InputBufferLength;
    ULONG OutputBufferLength;
    ULONG MethodId;
    ULONG Phase;
    ULONG PrefixLength;
    UCHAR Prefix[AWDLWIN_TX_WDI_HEADER_SIZE];
} AWDLWIN_OID_OBSERVATION_RECORD_V2, *PAWDLWIN_OID_OBSERVATION_RECORD_V2;

typedef struct _AWDLWIN_OID_OBSERVATIONS_V2 {
    ULONG Size;
    ULONG Version;
    ULONG Count;
    ULONG Reserved;
    AWDLWIN_OID_OBSERVATION_RECORD_V2 Records[AWDLWIN_OID_OBSERVATION_CAPACITY];
} AWDLWIN_OID_OBSERVATIONS_V2, *PAWDLWIN_OID_OBSERVATIONS_V2;

#define AWDLWIN_NATIVE_RX_VERSION 1u
#define AWDLWIN_NATIVE_RX_SNAPSHOT_VERSION 2u
#define AWDLWIN_NATIVE_RX_PORT_CAPACITY 16u
#define AWDLWIN_NATIVE_RX_STATUS_CAPACITY 32u
#define AWDLWIN_NATIVE_RX_STATUS_PAYLOAD_CAPACITY 4124u
#define AWDLWIN_NATIVE_RX_STATUS_FLAG_TRUNCATED 1u
#define AWDLWIN_NATIVE_RX_STATUS_FLAG_MISSING_BUFFER 2u
#define AWDLWIN_NATIVE_RX_STATUS_MEDIA_SPECIFIC 0x40010012u
#define AWDLWIN_NATIVE_RX_CONFIRM_MAGIC 0x3158524Eu /* NRX1 */
#define AWDLWIN_NATIVE_RX_RECORD_CAPACITY 32u
#define AWDLWIN_NATIVE_RX_FRAME_CAPACITY 4124u
#define AWDLWIN_NATIVE_RX_ORIGIN_NATIVE80211_MPDU 1u
#define AWDLWIN_NATIVE_RX_OPERATION_STATUS 0u
#define AWDLWIN_NATIVE_RX_OPERATION_ENABLE 1u
#define AWDLWIN_NATIVE_RX_OPERATION_DISABLE 2u
#define AWDLWIN_NATIVE_RX_OPERATION_OBSERVE 3u /* Capture only; no filter OID. */
#define AWDLWIN_NATIVE_RX_FILTER_STATE_DISABLED 0u
#define AWDLWIN_NATIVE_RX_FILTER_STATE_ENABLED 1u
#define AWDLWIN_NATIVE_RX_FILTER_STATE_RESTORE_PENDING 2u
#define AWDLWIN_NATIVE_RX_FILTER_STATE_RESTORE_FAILED 3u
#define AWDLWIN_NATIVE_RX_FCS_UNKNOWN 0u
#define AWDLWIN_NATIVE_RX_FCS_ABSENT 1u
#define AWDLWIN_NATIVE_RX_FCS_PRESENT 2u
#define AWDLWIN_NATIVE_RX_STATUS_NOT_ATTEMPTED 0xffffffffu
#define AWDLWIN_NATIVE_RX_RECORD_FLAG_LOOPBACK 0x00000001u
#define AWDLWIN_NATIVE_RX_RECORD_FLAG_LOCAL_SOURCE 0x00000002u
#define AWDLWIN_NATIVE_RX_RECORD_FLAG_TRUNCATED 0x00000004u
#define AWDLWIN_NATIVE_RX_RECORD_FLAG_DOT11_METADATA_VALID 0x00000008u
#define AWDLWIN_NATIVE_RX_RECORD_FLAG_AWDL_CANDIDATE 0x00000010u

typedef struct _AWDLWIN_NATIVE_RX_CONTROL_REQUEST_V1 {
    ULONG Size;
    ULONG Version;
    ULONG Operation;
    ULONG TargetIfIndex;
    ULONGLONG TargetNetLuidValue;
    ULONG ConfirmMagic;
    ULONG Reserved;
} AWDLWIN_NATIVE_RX_CONTROL_REQUEST_V1, *PAWDLWIN_NATIVE_RX_CONTROL_REQUEST_V1;

typedef struct _AWDLWIN_NATIVE_RX_CONTROL_RESULT_V1 {
    ULONG Size;
    ULONG Version;
    ULONG Operation;
    ULONG TargetIfIndex;
    ULONGLONG TargetNetLuidValue;
    ULONG Enabled;
    ULONG FilterState;
    ULONG OriginalHostFilterKnown;
    ULONG OriginalHostFilter;
    ULONG EffectiveFilter;
    ULONG RestoreMask;
    ULONG LastNdisStatus;
    ULONG RestoreStatus;
    ULONG FilterGeneration;
    ULONG PendingHostFilterSets;
} AWDLWIN_NATIVE_RX_CONTROL_RESULT_V1, *PAWDLWIN_NATIVE_RX_CONTROL_RESULT_V1;

typedef struct _AWDLWIN_NATIVE_RX_SNAPSHOT_REQUEST_V1 {
    ULONG Size;
    ULONG Version;
    ULONG TargetIfIndex;
    ULONG Reserved;
    ULONGLONG TargetNetLuidValue;
} AWDLWIN_NATIVE_RX_SNAPSHOT_REQUEST_V1, *PAWDLWIN_NATIVE_RX_SNAPSHOT_REQUEST_V1;

typedef struct _AWDLWIN_NATIVE_RX_RECORD_V1 {
    ULONGLONG Sequence;
    ULONGLONG InterruptTime100ns;
    ULONGLONG TargetNetLuidValue;
    ULONGLONG FilterNetLuidValue;
    ULONG TargetIfIndex;
    ULONG FilterIfIndex;
    ULONG PortNumber;
    ULONG OriginalLength;
    ULONG CopiedLength;
    ULONG Origin;
    ULONG ReceiveFlags;
    ULONG NblFlags;
    ULONG Dot11MetadataFlags;
    ULONG Dot11ReceiveFlags;
    ULONG Dot11ChCenterFrequencyMHz;
    ULONG Dot11PhyId;
    ULONG FcsPresence;
    ULONG Flags;
    UCHAR RawBytes[AWDLWIN_NATIVE_RX_FRAME_CAPACITY];
} AWDLWIN_NATIVE_RX_RECORD_V1, *PAWDLWIN_NATIVE_RX_RECORD_V1;

typedef struct _AWDLWIN_NATIVE_RX_PORT_COUNTER_V2 {
    ULONG PortNumber; /* NDIS port number, never WDI/vendor port ID. */
    ULONG Reserved;
    ULONGLONG CallbackCount;
    ULONGLONG NetBufferListCount;
    ULONGLONG NetBufferCount;
    ULONGLONG CapturedMpduCount;
} AWDLWIN_NATIVE_RX_PORT_COUNTER_V2;

typedef struct _AWDLWIN_NATIVE_RX_STATUS_RECORD_V2 {
    ULONGLONG Sequence;
    ULONGLONG InterruptTime100ns;
    ULONG PortNumber;
    ULONG StatusCode;
    ULONG OriginalLength;
    ULONG CopiedLength;
    ULONG Flags;
    ULONG Reserved;
    UCHAR Payload[AWDLWIN_NATIVE_RX_STATUS_PAYLOAD_CAPACITY];
} AWDLWIN_NATIVE_RX_STATUS_RECORD_V2;

typedef struct _AWDLWIN_NATIVE_RX_SNAPSHOT_V2 {
    ULONG Size;
    ULONG Version;
    ULONG Origin;
    ULONG Count;
    ULONGLONG TargetNetLuidValue;
    ULONG TargetIfIndex;
    ULONG FilterIfIndex;
    ULONGLONG NetBufferListCount;
    ULONGLONG CallbackCount;
    ULONGLONG NetBufferCount;
    ULONGLONG ManagementActionCount;
    ULONGLONG AwdlCandidateCount;
    ULONGLONG CopyFailureCount;
    ULONGLONG OversizeCount;
    ULONGLONG InvalidMetadataCount;
    ULONGLONG LoopbackCount;
    ULONGLONG LocalSourceCount;
    ULONG PortCount;
    ULONG StatusCount;
    ULONGLONG UntrackedPortCallbacks;
    ULONGLONG StatusSequence;
    ULONGLONG StatusOverwriteCount;
    AWDLWIN_NATIVE_RX_PORT_COUNTER_V2 Ports[AWDLWIN_NATIVE_RX_PORT_CAPACITY];
    AWDLWIN_NATIVE_RX_STATUS_RECORD_V2 StatusRecords[AWDLWIN_NATIVE_RX_STATUS_CAPACITY];
    AWDLWIN_NATIVE_RX_RECORD_V1 Records[AWDLWIN_NATIVE_RX_RECORD_CAPACITY];
} AWDLWIN_NATIVE_RX_SNAPSHOT_V2, *PAWDLWIN_NATIVE_RX_SNAPSHOT_V2;
