#include "tx10ub_action_core.h"

static void AwdlWinAfWrite16(AWDLWIN_AF_U8 *bytes, AWDLWIN_AF_U16 value)
{
    bytes[0] = (AWDLWIN_AF_U8)value;
    bytes[1] = (AWDLWIN_AF_U8)(value >> 8);
}

static void AwdlWinAfWrite32(AWDLWIN_AF_U8 *bytes, AWDLWIN_AF_U32 value)
{
    bytes[0] = (AWDLWIN_AF_U8)value;
    bytes[1] = (AWDLWIN_AF_U8)(value >> 8);
    bytes[2] = (AWDLWIN_AF_U8)(value >> 16);
    bytes[3] = (AWDLWIN_AF_U8)(value >> 24);
}

static int AwdlWinAfSerializeAction(const AWDLWIN_AF_PARAMETERS *p,
                                    AWDLWIN_AF_U8 *buffer, size_t capacity,
                                    size_t *written, AWDLWIN_AF_U16 parameterTlv,
                                    int response)
{
    size_t required;
    size_t i;
    if (written != NULL) *written = 0;
    if (p == NULL || buffer == NULL || written == NULL ||
        p->PortId == 0xffffu || p->TransactionId == 0 ||
        p->BodyLength < 2 || p->BodyLength > AWDLWIN_AF_MAX_BODY ||
        p->ChannelNumber == 0 || p->SendTimeoutMs == 0 ||
        p->SendTimeoutMs > 1000u || p->PostAckDwellMs > 100u) return 0;
#if defined(AWDLWIN_AP_COEXISTENCE)
    {
        static const AWDLWIN_AF_U8 psfHeader[] = {0x7f, 0, 0x17, 0xf2, 8, 0x10, 0, 0};
        if (response || p->PortId != 0 || p->BandId != (p->ChannelNumber == 6 ? 1u : 2u) ||
            (p->ChannelNumber != 6 && p->ChannelNumber != 44 && p->ChannelNumber != 149) ||
            p->PostAckDwellMs != 0 || p->BodyLength <= 16) return 0;
        for (i = 0; i < sizeof(psfHeader); ++i) if (p->Body[i] != psfHeader[i]) return 0;
        for (i = 0; i < 6; ++i) if (p->Peer[i] != 0xff) return 0;
        /* Check the bounds of every discovery TLV before submitting the PSF. */
        for (i = 16; i < p->BodyLength; ) {
            size_t length;
            if (p->BodyLength - i < 3) return 0;
            length = p->Body[i + 1] | ((size_t)p->Body[i + 2] << 8);
            i += 3;
            if (length > p->BodyLength - i) return 0;
            i += length;
        }
    }
#elif defined(AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT)
    if (p->Body[0] != 0x04 && p->Body[0] != 0x7f) return 0;
    if ((p->Peer[0] & 1) != 0) {
        for (i = 0; i < 6 && p->Peer[i] == 0xff; ++i) { }
        if (i != 6) return 0;
    }
#else
    if (p->Body[0] != 0x04 || (p->Peer[0] & 1) != 0) return 0;
#endif
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
    if (response) {
        if (p->Body[0] != 0x7f || p->PostAckDwellMs != 0) return 0;
        for (i = 0; i < 6 && p->Peer[i] == 0xff; ++i) { }
        if (i != 6) return 0;
    }
#else
    (void)response;
#endif
    for (i = 0; i < 6 && p->Peer[i] == 0; ++i) { }
    if (i == 6) return 0;
    required = AWDLWIN_AF_REQUEST_PREFIX_SIZE + (size_t)p->BodyLength;
    if (required < AWDLWIN_AF_REQUEST_PREFIX_SIZE || capacity < required) return 0;
    for (i = 0; i < required; ++i) buffer[i] = 0;
    AwdlWinAfWrite16(buffer + 0, p->PortId);
    AwdlWinAfWrite32(buffer + 8, p->TransactionId);
    AwdlWinAfWrite16(buffer + 16, parameterTlv);
    AwdlWinAfWrite16(buffer + 18, 22u);
    AwdlWinAfWrite32(buffer + 20, p->ChannelNumber);
    AwdlWinAfWrite32(buffer + 24, p->BandId);
    for (i = 0; i < 6; ++i) buffer[28 + i] = p->Peer[i];
    AwdlWinAfWrite32(buffer + 34, p->SendTimeoutMs);
    AwdlWinAfWrite32(buffer + 38, p->PostAckDwellMs);
    AwdlWinAfWrite16(buffer + 42, 0x00beu);
    AwdlWinAfWrite16(buffer + 44, p->BodyLength);
    for (i = 0; i < p->BodyLength; ++i) buffer[46 + i] = p->Body[i];
    *written = required;
    return 1;
}

int AwdlWinAfSerializeRequest(const AWDLWIN_AF_PARAMETERS *p,
                              AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written)
{
    return AwdlWinAfSerializeAction(p, buffer, capacity, written, 0x00bfu, 0);
}

#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
int AwdlWinAfSerializeResponse(const AWDLWIN_AF_PARAMETERS *p,
                               AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written)
{
    return AwdlWinAfSerializeAction(p, buffer, capacity, written, 0x00e2u, 1);
}

static int AwdlWinAfSerializeActionBody(const AWDLWIN_AF_PARAMETERS *p,
                               const AWDLWIN_AF_U8 *body, size_t bodyLength,
                               const AWDLWIN_AF_U8 sourceMac[6],
                               AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written)
{
    static const AWDLWIN_AF_U8 awdlBssid[6] = { 0x00, 0x25, 0x00, 0xff, 0x94, 0x73 };
    static const AWDLWIN_AF_U8 bodyPrefix[5] = { 0x7f, 0x00, 0x17, 0xf2, 0x08 };
    size_t frameLength;
    size_t required;
    size_t i;

    if (written != NULL) *written = 0;
    if (p == NULL || sourceMac == NULL || buffer == NULL || written == NULL || body == NULL ||
        p->PostAckDwellMs != 0 || bodyLength < AWDLWIN_AF_RAW_BODY_MIN_LENGTH ||
        bodyLength > AWDLWIN_AF_RAW_MAX_FRAME_LENGTH - AWDLWIN_AF_RAW_80211_HEADER_SIZE ||
        body[5] != 0x10u || (body[6] != 0u && body[6] != 3u)) return 0;
    for (i = 0; i < 6; ++i) {
        if (p->Peer[i] != 0xff) return 0;
    }
    if ((sourceMac[0] & 1u) != 0) return 0;
    for (i = 0; i < 6 && sourceMac[i] == 0; ++i) { }
    if (i == 6) return 0;
    for (i = 0; i < sizeof(bodyPrefix); ++i) {
        if (body[i] != bodyPrefix[i]) return 0;
    }

    frameLength = AWDLWIN_AF_RAW_80211_HEADER_SIZE + bodyLength;
    required = AWDLWIN_AF_RAW_METADATA_SIZE + frameLength;
    if (capacity < required) return 0;

    for (i = 0; i < AWDLWIN_AF_RAW_BODY_OFFSET; ++i) buffer[i] = 0;
    AwdlWinAfWrite16(buffer, (AWDLWIN_AF_U16)frameLength);
    buffer[2] = AWDLWIN_AF_RAW_RATE_6_MBPS;
    AwdlWinAfWrite16(buffer + 3, 1u);
    buffer[AWDLWIN_AF_RAW_METADATA_SIZE] = 0xd0u;
    buffer[AWDLWIN_AF_RAW_METADATA_SIZE + 1u] = 0x00u;
    /* Duration (18..19) and sequence control (38..39) remain zero. */
    for (i = 0; i < 6; ++i) {
        buffer[AWDLWIN_AF_RAW_METADATA_SIZE + 4u + i] = 0xff;
        buffer[AWDLWIN_AF_RAW_METADATA_SIZE + 10u + i] = sourceMac[i];
        buffer[AWDLWIN_AF_RAW_METADATA_SIZE + 16u + i] = awdlBssid[i];
    }
    for (i = 0; i < bodyLength; ++i)
        buffer[AWDLWIN_AF_RAW_BODY_OFFSET + i] = body[i];
    *written = required;
    return 1;
}
int AwdlWinAfSerializeRawFrame(const AWDLWIN_AF_PARAMETERS *p, const AWDLWIN_AF_U8 sourceMac[6],
                               AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written)
{
    if (written != NULL) *written = 0;
    if (p == NULL || p->BodyLength > sizeof(p->Body)) return 0;
    return AwdlWinAfSerializeActionBody(p, p->Body, p->BodyLength, sourceMac, buffer, capacity, written);
}
#endif

#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
int AwdlWinAfSerializeRawBodyRequest(const AWDLWIN_AF_PARAMETERS *p,
                                 const AWDLWIN_AF_U8 *body, size_t bodyLength,
                                 const AWDLWIN_AF_U8 sourceMac[6],
                                 AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written)
{
    size_t innerLength = 0;
    size_t required;
    size_t i;
    if (written != NULL) *written = 0;
    if (p == NULL || buffer == NULL || written == NULL ||
        p->PortId == 0xffffu || p->TransactionId == 0 ||
        capacity < 48u ||
        !AwdlWinAfSerializeActionBody(p, body, bodyLength, sourceMac, buffer+48u, capacity-48u, &innerLength)) return 0;
    required = 48u + innerLength;
    for (i = 0; i < 48u; ++i) buffer[i] = 0;
    AwdlWinAfWrite16(buffer, p->PortId);
    AwdlWinAfWrite32(buffer + 8, p->TransactionId);
    AwdlWinAfWrite16(buffer + 16, 0x00bdu);
    AwdlWinAfWrite16(buffer + 18, (AWDLWIN_AF_U16)(28u + innerLength));
    AwdlWinAfWrite32(buffer + 20, (AWDLWIN_AF_U32)(24u + innerLength));
    AwdlWinAfWrite32(buffer + 24, 0xff4ce000u);
    AwdlWinAfWrite32(buffer + 28, 1u);
    AwdlWinAfWrite32(buffer + 32, AWDLWIN_AF_RAW_INNER_OID);
    /* Envelope +0x10/+0x14 are vendor bytes-read/needed output fields. */
    AwdlWinAfWrite32(buffer + 44, (AWDLWIN_AF_U32)innerLength);
    *written = required;
    return 1;
}
int AwdlWinAfSerializeRawRequest(const AWDLWIN_AF_PARAMETERS *p, const AWDLWIN_AF_U8 sourceMac[6],
                                 AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written)
{
    if (written != NULL) *written = 0;
    if (p == NULL || p->BodyLength > sizeof(p->Body)) return 0;
    return AwdlWinAfSerializeRawBodyRequest(p,p->Body,p->BodyLength,sourceMac,buffer,capacity,written);
}
#endif

#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
/* Fixed allowlisted Set envelopes only; there is no caller-selected OID. */
static void AwdlWinAfVendorHeader(AWDLWIN_AF_U32 transactionId,
    AWDLWIN_AF_U32 oid, size_t innerLength, AWDLWIN_AF_U8 *buffer)
{
    size_t i;
    for (i = 0; i < 48u; ++i) buffer[i] = 0;
    AwdlWinAfWrite32(buffer + 8, transactionId);
    AwdlWinAfWrite16(buffer + 16, 0x00bdu);
    AwdlWinAfWrite16(buffer + 18, (AWDLWIN_AF_U16)(28u + innerLength));
    AwdlWinAfWrite32(buffer + 20, (AWDLWIN_AF_U32)(24u + innerLength));
    AwdlWinAfWrite32(buffer + 24, 0xff4ce000u);
    AwdlWinAfWrite32(buffer + 28, 1u);
    AwdlWinAfWrite32(buffer + 32, oid);
    AwdlWinAfWrite32(buffer + 44, (AWDLWIN_AF_U32)innerLength);
}

int AwdlWinAfSerializeEncryptionDisabledRequest(AWDLWIN_AF_U32 transactionId,
    AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written)
{
    if (written != NULL) *written = 0;
    if (transactionId == 0 || buffer == NULL || written == NULL || capacity < 52u)
        return 0;
    AwdlWinAfVendorHeader(transactionId, AWDLWIN_AF_ENCRYPTION_STATUS_INNER_OID,
        4u, buffer);
    /* Ndis802_11EncryptionDisabled == 1; 0 would enable WEP. */
    AwdlWinAfWrite32(buffer + 48, 1u);
    *written = 52u;
    return 1;
}

int AwdlWinAfSerializeWpsClearRequest(AWDLWIN_AF_U32 transactionId,
    AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written)
{
    if (written != NULL) *written = 0;
    if (transactionId == 0 || buffer == NULL || written == NULL || capacity < 49u)
        return 0;
    AwdlWinAfVendorHeader(transactionId, AWDLWIN_AF_WPS_INNER_OID, 1u, buffer);
    buffer[48] = 0;
    *written = 49u;
    return 1;
}

int AwdlWinAfSerializeWpsRequest(AWDLWIN_AF_U32 transactionId, int enabled,
    const AWDLWIN_AF_U8 *ie, size_t ieLength,
    AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written)
{
    size_t offset, length, i;
    if (written != NULL) *written = 0;
    if (transactionId == 0 || (enabled != 0 && enabled != 1) ||
        ie == NULL || buffer == NULL || written == NULL ||
        ieLength < 0x23u || ieLength > AWDLWIN_AF_WPS_IE_CAPACITY ||
        capacity < 50u + ieLength || ie[0] != 0 || ie[1] != 0x50 ||
        ie[2] != 0xf2 || ie[3] != 4) return 0;
    /* WPS attributes have big-endian type and length fields. */
    offset = 4;
    while (offset < ieLength) {
        if (ieLength - offset < 4u) return 0;
        length = ((size_t)ie[offset + 2] << 8) | ie[offset + 3];
        offset += 4;
        if (length > ieLength - offset) return 0;
        offset += length;
    }
    AwdlWinAfVendorHeader(transactionId, AWDLWIN_AF_WPS_INNER_OID,
        2u + ieLength, buffer);
    buffer[48] = (AWDLWIN_AF_U8)(((ieLength >> 8) << 1) | (unsigned)enabled);
    buffer[49] = (AWDLWIN_AF_U8)ieLength;
    for (i = 0; i < ieLength; ++i) buffer[50u + i] = ie[i];
    *written = 50u + ieLength;
    return 1;
}

int AwdlWinAfSerializeRawDataRequest(AWDLWIN_AF_U32 transactionId,
    const AWDLWIN_AF_U8 sourceMac[6], const AWDLWIN_AF_U8 *frame, size_t frameLength,
    AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written)
{
    static const AWDLWIN_AF_U8 bssid[6] = {0, 0x25, 0, 0xff, 0x94, 0x73};
    static const AWDLWIN_AF_U8 appleSnap[8] = {0xaa, 0xaa, 3, 0, 0x17, 0xf2, 8, 0};
    size_t i;
    if (written != NULL) *written = 0;
    if (transactionId == 0 || sourceMac == NULL || frame == NULL ||
        buffer == NULL || written == NULL ||
        frameLength < 80u || frameLength > AWDLWIN_AF_RAW_MAX_FRAME_LENGTH ||
        capacity < 64u + frameLength || (sourceMac[0] & 1u) != 0 ||
        frame[0] != 8 || frame[1] != 0 || (frame[22] & 15u) != 0 ||
        frame[32] != 3 || frame[33] != 4 || frame[36] != 0 || frame[37] != 0 ||
        frame[38] != 0x86 || frame[39] != 0xdd || (frame[40] >> 4) != 6 ||
        80u + (((size_t)frame[44] << 8) | frame[45]) != frameLength) return 0;
    for (i = 0; i < 6 && sourceMac[i] == 0; ++i) { }
    if (i == 6) return 0;
    for (i = 0; i < 6 && frame[4u + i] == 0; ++i) { }
    if (i == 6) return 0;
    for (i = 0; i < 6; ++i)
        if (frame[10u + i] != sourceMac[i] || frame[16u + i] != bssid[i]) return 0;
    for (i = 0; i < 8; ++i)
        if (frame[24u + i] != appleSnap[i]) return 0;
    /* IPv6 multicast maps to 33:33 and the low 32 destination bits. */
    if (frame[64] == 0xff) {
        if (frame[4] != 0x33 || frame[5] != 0x33) return 0;
        for (i = 0; i < 4; ++i)
            if (frame[6u + i] != frame[76u + i]) return 0;
    } else if ((frame[4] & 1u) != 0) return 0;
    AwdlWinAfVendorHeader(transactionId, AWDLWIN_AF_RAW_INNER_OID, 16u + frameLength, buffer);
    for (i = 48u; i < 64u; ++i) buffer[i] = 0;
    AwdlWinAfWrite16(buffer + 48, (AWDLWIN_AF_U16)frameLength);
    buffer[50] = 24u; /* 12 Mbps, in units of 500 kbps. */
    AwdlWinAfWrite16(buffer + 51, 1u);
    for (i = 0; i < frameLength; ++i) buffer[64u + i] = frame[i];
    *written = 64u + frameLength;
    return 1;
}
#endif

static int AwdlWinAfSerializeAbortForTask(AWDLWIN_AF_U16 portId,
                                          AWDLWIN_AF_U32 abortTransactionId,
                                          AWDLWIN_AF_U32 originalTransactionId,
                                          AWDLWIN_AF_U32 originalTaskOid,
                                          AWDLWIN_AF_U8 *buffer, size_t capacity,
                                          size_t *written)
{
    size_t i;
    if (written != NULL) *written = 0;
    if (buffer == NULL || written == NULL || capacity < AWDLWIN_AF_ABORT_SIZE ||
        portId == 0xffffu || abortTransactionId == 0 || originalTransactionId == 0 ||
        abortTransactionId == originalTransactionId) return 0;
    for (i = 0; i < AWDLWIN_AF_ABORT_SIZE; ++i) buffer[i] = 0;
    AwdlWinAfWrite16(buffer + 0, portId);
    AwdlWinAfWrite32(buffer + 8, abortTransactionId);
    AwdlWinAfWrite16(buffer + 16, 0x002bu);
    AwdlWinAfWrite16(buffer + 18, 10u);
    AwdlWinAfWrite32(buffer + 20, originalTaskOid);
    AwdlWinAfWrite32(buffer + 24, originalTransactionId);
    AwdlWinAfWrite16(buffer + 28, portId);
    *written = AWDLWIN_AF_ABORT_SIZE;
    return 1;
}

int AwdlWinAfSerializeAbort(AWDLWIN_AF_U16 portId, AWDLWIN_AF_U32 abortTransactionId,
                            AWDLWIN_AF_U32 originalTransactionId,
                            AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written)
{
    return AwdlWinAfSerializeAbortForTask(portId, abortTransactionId,
        originalTransactionId, 0xe4400066u, buffer, capacity, written);
}

#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
int AwdlWinAfSerializeResponseAbort(AWDLWIN_AF_U16 portId,
                                    AWDLWIN_AF_U32 abortTransactionId,
                                    AWDLWIN_AF_U32 originalTransactionId,
                                    AWDLWIN_AF_U8 *buffer, size_t capacity, size_t *written)
{
    return AwdlWinAfSerializeAbortForTask(portId, abortTransactionId,
        originalTransactionId, 0xe4400069u, buffer, capacity, written);
}
#endif

void AwdlWinAfInitialize(AWDLWIN_AF_TRACKER *t, AWDLWIN_AF_U16 portId,
                         AWDLWIN_AF_U32 transactionId)
{
    AWDLWIN_AF_U8 *bytes = (AWDLWIN_AF_U8 *)t;
    size_t i;
    for (i = 0; i < sizeof(*t); ++i) bytes[i] = 0;
    t->State = AwdlWinAfOidPending;
    t->PortId = portId;
    t->TransactionId = transactionId;
}

int AwdlWinAfOnM3(AWDLWIN_AF_TRACKER *t, int success)
{
    int inconsistent;
    if (t == NULL) return 0;
    if (t->M3Seen) {
        t->Inconsistent = 1;
        t->Quarantined = 1;
        return 0;
    }
    t->M3Seen = 1;
    t->M3Success = success ? 1 : 0;
    inconsistent = !success && t->M4Seen;
    if (inconsistent) t->Inconsistent = 1;
    if (t->M3TimeoutObserved) {
        t->State = AwdlWinAfM3StuckQuarantined;
        return !inconsistent;
    }
    if (inconsistent) {
        return 0;
    } else if (!success) {
        t->State = AwdlWinAfFailedBeforeStart;
    } else {
        t->State = AwdlWinAfRequestAccepted;
    }
    return 1;
}

AWDLWIN_AF_M4_RESULT AwdlWinAfOnM4(AWDLWIN_AF_TRACKER *t,
                                     AWDLWIN_AF_U16 portId,
                                     AWDLWIN_AF_U32 transactionId)
{
    if (t == NULL || t->PortId != portId || t->TransactionId != transactionId)
        return AwdlWinAfM4OtherTask;
    if (t->M4Seen) {
        return AwdlWinAfM4Duplicate;
    }
    if (t->M3Seen && !t->M3Success) {
        t->Inconsistent = 1;
        return AwdlWinAfM4AfterFailedM3;
    }
    t->M4Seen = 1;
    return AwdlWinAfM4Accepted;
}

int AwdlWinAfBeginAbort(AWDLWIN_AF_TRACKER *t)
{
    if (t == NULL || !t->M3Seen || !t->M3Success || t->M4Seen ||
        t->AbortIssued || t->PauseRequested || t->Quarantined ||
        t->M3TimeoutObserved || t->Inconsistent) return 0;
    t->AbortIssued = 1;
    t->State = AwdlWinAfAbortPending;
    return 1;
}

int AwdlWinAfOnAbortCompletion(AWDLWIN_AF_TRACKER *t, int success)
{
    if (t == NULL || !t->AbortIssued || t->AbortCompleted) return 0;
    t->AbortCompleted = 1;
    t->AbortSuccess = success ? 1 : 0;
    t->State = t->M3TimeoutObserved ? AwdlWinAfM3StuckQuarantined :
        (success ? AwdlWinAfRequestAccepted : AwdlWinAfAbortRejected);
    return 1;
}

void AwdlWinAfMarkM3Stuck(AWDLWIN_AF_TRACKER *t)
{
    if (t != NULL) {
        t->Quarantined = 1;
        t->M3TimeoutObserved = 1;
        t->State = AwdlWinAfM3StuckQuarantined;
    }
}

void AwdlWinAfRequestPause(AWDLWIN_AF_TRACKER *t)
{
    if (t != NULL) t->PauseRequested = 1;
}

int AwdlWinAfCanDrain(const AWDLWIN_AF_TRACKER *t)
{
    /* NDIS OID storage only; the LWF separately checks callback/submission refs. */
    if (t == NULL || !t->M3Seen) return 0;
    if (t->AbortIssued && !t->AbortCompleted) return 0;
    return 1;
}

int AwdlWinAfCanStartNextTask(const AWDLWIN_AF_TRACKER *t)
{
    return AwdlWinAfCanDrain(t) && !t->Quarantined && !t->Inconsistent &&
        !t->M3TimeoutObserved && (!t->M3Success || t->M4Seen);
}

int AwdlWinAfObservationEnded(const AWDLWIN_AF_TRACKER *t)
{
    return t != NULL && (AwdlWinAfCanDrain(t) || t->M3TimeoutObserved || t->M3Seen);
}

static void
AwdlWinCgClearEvidence(AWDLWIN_CG_POLICY *policy)
{
    policy->EvidenceMask = 0;
}

void
AwdlWinCgInitialize(AWDLWIN_CG_POLICY *policy)
{
    size_t i;
    AWDLWIN_AF_U8 *bytes;
    if (policy == NULL) return;
    bytes = (AWDLWIN_AF_U8 *)policy;
    for (i = 0; i < sizeof(*policy); ++i) bytes[i] = 0;
    policy->Challenge = 1;
    policy->Stage = AWDLWIN_CG_NEXT_ADMISSIBLE;
    policy->PermissionArmed = 1;
}

void
AwdlWinCgStop(AWDLWIN_CG_POLICY *policy, AWDLWIN_AF_U32 stopReason)
{
    if (policy == NULL || policy->Stage == AWDLWIN_CG_STOP) return;
    if (policy->Challenge < 0x7fffffffffffffffULL) ++policy->Challenge;
    policy->Stage = AWDLWIN_CG_STOP;
    policy->StopReason = stopReason;
    policy->PermissionArmed = 0;
    AwdlWinCgClearEvidence(policy);
}

int
AwdlWinCgSetStage(AWDLWIN_CG_POLICY *policy, AWDLWIN_AF_U32 stage)
{
    if (policy == NULL || stage > AWDLWIN_CG_STOP) return 0;
    if (policy->Stage == AWDLWIN_CG_STOP) return stage == AWDLWIN_CG_STOP;
    if (policy->Stage == stage) return 1;
    if (policy->Challenge >= 0x7fffffffffffffffULL) {
        AwdlWinCgStop(policy, AWDLWIN_CG_STOP_CHALLENGE_EXHAUSTED);
        return 0;
    }
    ++policy->Challenge;
    policy->Stage = stage;
    return 1;
}

int
AwdlWinCgRefresh(AWDLWIN_CG_POLICY *policy, int m3Seen, int m3Success,
                 int m3Timeout, int malformedCompletion,
                 int issueInProgress, int driverQuiescent)
{
    if (policy == NULL || policy->Stage == AWDLWIN_CG_STOP) return 0;
    if (m3Timeout) {
        AwdlWinCgStop(policy, AWDLWIN_CG_STOP_M3_TIMEOUT);
        return 0;
    }
    if (malformedCompletion) {
        AwdlWinCgStop(policy, AWDLWIN_CG_STOP_MALFORMED_COMPLETION);
        return 0;
    }
    if (!m3Seen) return 1;
    if (!m3Success) {
        AwdlWinCgStop(policy, AWDLWIN_CG_STOP_M3_FAILED);
        return 0;
    }
    if (policy->Stage == AWDLWIN_CG_ISSUED &&
        !AwdlWinCgSetStage(policy, AWDLWIN_CG_M3_ACCEPTED)) return 0;
    if (policy->Stage == AWDLWIN_CG_M3_ACCEPTED && !issueInProgress &&
        !AwdlWinCgSetStage(policy, AWDLWIN_CG_WAIT_QUIESCENCE)) return 0;
    if (!driverQuiescent &&
        policy->Stage == AWDLWIN_CG_QUIESCENCE_VERIFIED) {
        AwdlWinCgClearEvidence(policy);
        if (!AwdlWinCgSetStage(policy, AWDLWIN_CG_WAIT_QUIESCENCE)) return 0;
    } else if (driverQuiescent &&
        policy->Stage == AWDLWIN_CG_WAIT_QUIESCENCE &&
        policy->EvidenceMask == 3u) {
        if (!AwdlWinCgSetStage(policy, AWDLWIN_CG_QUIESCENCE_VERIFIED)) return 0;
    }
    return policy->Stage != AWDLWIN_CG_STOP;
}

int
AwdlWinCgInvalidateObservation(AWDLWIN_CG_POLICY *policy)
{
    if (policy == NULL || policy->Stage == AWDLWIN_CG_STOP) return 0;
    if (policy->EverIssued) {
        AwdlWinCgStop(policy, AWDLWIN_CG_STOP_LIFECYCLE_CHANGED);
        return 0;
    }
    if (policy->Challenge >= 0x7fffffffffffffffULL) {
        AwdlWinCgStop(policy, AWDLWIN_CG_STOP_CHALLENGE_EXHAUSTED);
        return 0;
    }
    ++policy->Challenge;
    AwdlWinCgClearEvidence(policy);
    return 1;
}
