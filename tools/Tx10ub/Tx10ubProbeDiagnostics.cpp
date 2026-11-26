#include "Tx10ubProbeDiagnostics.h"

#include <objbase.h>
#include <winioctl.h>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>

#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
#include "Tx10ubBleAdvertisement.h"
#endif

namespace tx10ub::probe {

int ReadObservations(const wchar_t* devicePath) {
    HANDLE device = CreateFileW(devicePath, GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                OPEN_EXISTING, 0, nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        std::wcerr << L"device_open_error=" << GetLastError() << L'\n';
        return 4;
    }
    auto observations = std::make_unique<AWDLWIN_OID_OBSERVATIONS_V2>();
    DWORD bytesReturned = 0;
    const BOOL ok = DeviceIoControl(device, IOCTL_AWDLWIN_GET_OID_OBSERVATIONS,
                                    nullptr, 0, observations.get(), sizeof(*observations),
                                    &bytesReturned, nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(device);
    if (!ok) {
        std::wcerr << L"observation_ioctl_error=" << error << L'\n';
        return 5;
    }
    if (observations->Count > AWDLWIN_OID_OBSERVATION_CAPACITY ||
        !((observations->Version == 1 &&
           bytesReturned == sizeof(AWDLWIN_OID_OBSERVATIONS_V1) &&
           observations->Size == sizeof(AWDLWIN_OID_OBSERVATIONS_V1)) ||
          (observations->Version == 2 &&
           bytesReturned == sizeof(AWDLWIN_OID_OBSERVATIONS_V2) &&
           observations->Size == sizeof(AWDLWIN_OID_OBSERVATIONS_V2)))) {
        std::wcerr << L"invalid_observation_result\n";
        return 6;
    }
    std::wcout << L"observation_version=" << observations->Version << L'\n'
               << L"observation_count=" << observations->Count << L'\n';
    if (observations->Version == 1) {
        const auto* old = reinterpret_cast<const AWDLWIN_OID_OBSERVATIONS_V1*>(observations.get());
        for (ULONG i = 0; i < old->Count; ++i) {
            const auto& record = old->Records[i];
            std::wcout << L"sequence=" << record.Sequence
                       << L" phase=" << record.Phase
                       << L" oid=0x" << std::hex << std::setw(8) << std::setfill(L'0')
                       << record.Oid << std::dec << std::setfill(L' ')
                       << L" request_type=" << record.RequestType
                       << L" ndis_port_number=" << record.PortNumber
                       << L" input_length=" << record.InputBufferLength
                       << L" output_length=" << record.OutputBufferLength
                       << L" method_id=" << record.MethodId << L'\n';
        }
        return 0;
    }
    for (ULONG i = 0; i < observations->Count; ++i) {
        const auto& record = observations->Records[i];
        std::wcout << L"sequence=" << record.Sequence
                   << L" monotonic_100ns=" << record.InterruptTime100ns
                   << L" phase=" << record.Phase
                   << L" oid=0x" << std::hex << std::setw(8) << std::setfill(L'0')
                   << record.Oid << std::dec << std::setfill(L' ')
                   << L" request_type=" << record.RequestType
                   << L" ndis_port_number=" << record.PortNumber
                   << L" input_length=" << record.InputBufferLength
                   << L" output_length=" << record.OutputBufferLength
                   << L" method_id=" << record.MethodId
                   << L" filter_luid=" << record.FilterNetLuidValue
                   << L" base_miniport_luid=" << record.BaseMiniportNetLuidValue
                   << L" filter_if_index=" << record.FilterIfIndex
                   << L" base_miniport_if_index=" << record.BaseMiniportIfIndex
                   << L" prefix_length=" << record.PrefixLength;
        if (record.PrefixLength == AWDLWIN_TX_WDI_HEADER_SIZE) {
            USHORT portId = 0, reserved = 0;
            ULONG headerStatus = 0, transactionId = 0;
            std::memcpy(&portId, record.Prefix, sizeof(portId));
            std::memcpy(&reserved, record.Prefix + 2, sizeof(reserved));
            std::memcpy(&headerStatus, record.Prefix + 4, sizeof(headerStatus));
            std::memcpy(&transactionId, record.Prefix + 8, sizeof(transactionId));
            std::wcout << L" wdi_port_id=" << portId
                       << L" wdi_reserved=" << reserved
                       << L" wdi_header_status=0x" << std::hex << headerStatus << std::dec
                       << L" wdi_transaction_id=" << transactionId
                       << L" prefix_hex=";
            for (ULONG j = 0; j < record.PrefixLength; ++j)
                std::wcout << std::hex << std::setw(2) << std::setfill(L'0')
                           << static_cast<unsigned>(record.Prefix[j]);
            std::wcout << std::dec << std::setfill(L' ');
        }
        std::wcout << L'\n';
    }
    return 0;
}

int ReadStationStatus() {
    NET_LUID luid{};NET_IFINDEX index=0;
    if(!ResolveTarget(luid,index))return 3;
    wchar_t alias[IF_MAX_STRING_SIZE+1]{};
    const auto error=ConvertInterfaceLuidToAlias(&luid,alias,std::size(alias));
    if(error!=NO_ERROR){PrintHex(L"sta_interface_alias_error",error);return 3;}
    std::wcout<<L"sta_interface_alias="<<alias<<L'\n';
    return ReadConnection(L"sta").connected?0:11;
}

int ScanTarget(const wchar_t* guidText) {
    GUID guid{};
    if (FAILED(CLSIDFromString(guidText, &guid))) return 3;
    HANDLE client = nullptr;
    DWORD version = 0;
    const DWORD openError = WlanOpenHandle(2, nullptr, &version, &client);
    if (openError != ERROR_SUCCESS) {
        std::wcerr << L"wlan_open_error=" << openError << L'\n';
        return 4;
    }
    ScanNotificationContext context{guid, CreateEventW(nullptr, TRUE, FALSE, nullptr), 0};
    if (context.event == nullptr) {
        std::wcerr << L"scan_event_error=" << GetLastError() << L'\n';
        WlanCloseHandle(client, nullptr);
        return 5;
    }
    const DWORD registerError = WlanRegisterNotification(
        client, WLAN_NOTIFICATION_SOURCE_ACM, FALSE, OnScanNotification,
        &context, nullptr, nullptr);
    if (registerError != ERROR_SUCCESS) {
        std::wcerr << L"scan_notification_error=" << registerError << L'\n';
        CloseHandle(context.event);
        WlanCloseHandle(client, nullptr);
        return 6;
    }
    const DWORD scanError = WlanScan(client, &guid, nullptr, nullptr, nullptr);
    std::wcout << L"scan_request_error=" << scanError << L'\n';
    DWORD waitResult = WAIT_FAILED;
    if (scanError == ERROR_SUCCESS) waitResult = WaitForSingleObject(context.event, 8000);
    std::wcout << L"scan_notification=" << context.outcome << L'\n'
               << L"scan_wait_result=" << waitResult << L'\n';
    WlanRegisterNotification(client, WLAN_NOTIFICATION_SOURCE_NONE, FALSE,
                             nullptr, nullptr, nullptr, nullptr);
    CloseHandle(context.event);
    WlanCloseHandle(client, nullptr);
    return scanError == ERROR_SUCCESS && context.outcome == 1 ? 0 : 7;
}

static bool ParseCompletionNumber(const wchar_t* value, ULONGLONG& result) {
    if (!value || !*value) return false;
    result = 0;
    for (const wchar_t* p = value; *p; ++p) {
        if (*p < L'0' || *p > L'9') return false;
        const unsigned digit = *p - L'0';
        if (result > (~0ull - digit) / 10) return false;
        result = result * 10 + digit;
    }
    return result != 0;
}

static bool ParseCompletionIdentity(int argc, wchar_t** argv,
    AWDLWIN_COMPLETION_GATE_ID_V1& identity,
    ULONGLONG& observationGeneration, ULONGLONG& challenge) {
    size_t count = 0;
    if (argc < 10 || !ParseHex(argv[2], identity.LoadId, 16, count) || count != 16 ||
        !ParseCompletionNumber(argv[3], identity.FilterId) ||
        !ParseCompletionNumber(argv[4], identity.ActionId) ||
        !ParseCompletionNumber(argv[5], identity.LifecycleGeneration) ||
        !ParsePortId(argv[6], identity.PortId) ||
        !ParseUnsigned(argv[7], identity.TransactionId) || identity.TransactionId == 0 ||
        !ParseCompletionNumber(argv[8], observationGeneration) ||
        !ParseCompletionNumber(argv[9], challenge)) return false;
    UCHAR any = 0;
    for (const UCHAR byte : identity.LoadId) any |= byte;
    return any != 0;
}

static bool ParseManualInternalAction(int argc, wchar_t** argv,
    AWDLWIN_MANUAL_INTERNAL_ACTION_V1& request) {
    if (argc != 30) return false;
    const wchar_t* flags[] = {
        L"--all-workers-free", L"--queues-empty", L"--registry-empty", L"--nonbusy",
        L"--wdi-jobs-empty", L"--wdi-commands-empty", L"--wdi-events-empty",
        L"--wifi-maintained", L"--no-reset", L"--no-error",
        L"--ack-unverified-history", L"--confirm-one-send"
    };
    for (unsigned i = 0; i != 12; ++i)
        if (wcscmp(argv[18 + i], flags[i]) != 0) return false;
    wchar_t* identityArgs[10] = {};
    for (unsigned i = 0; i != 8; ++i) identityArgs[2 + i] = argv[9 + i];
    USHORT requestedPort = 0;
    if (!ParseCompletionIdentity(10, identityArgs, request.PriorIdentity,
            request.ObservationGeneration, request.ObservationChallenge) ||
        !ParseCompletionNumber(argv[17], request.ObservedUtcFileTime100ns) ||
        !ParsePortId(argv[2], requestedPort) || requestedPort != request.PriorIdentity.PortId)
        return false;
    request.Size = sizeof(request);
    request.Version = AWDLWIN_MANUAL_INTERNAL_VERSION;
    request.ConfirmMagic = AWDLWIN_MANUAL_INTERNAL_CONFIRM_MAGIC;
    request.SnapshotFlags = AWDLWIN_MANUAL_INTERNAL_REQUIRED_FLAGS;
    request.AcknowledgementFlags = AWDLWIN_MANUAL_INTERNAL_ACK_UNKNOWN_HISTORY;
    return true;
}

int RunExperimentalAction(int argc, wchar_t** argv) {
    const bool manual = wcscmp(argv[1], L"manual-internal-action") == 0;
    const bool send = manual || wcscmp(argv[1], L"experimental-action") == 0;
    const bool abort = wcscmp(argv[1], L"experimental-abort") == 0;
    const bool statusOnly = wcscmp(argv[1], L"experimental-status") == 0;
    if ((!send && !abort && !statusOnly) || (send && argc != (manual ? 30 : 9)) ||
        (!send && argc != 4)) return 2;

    // Reject malformed assertions before resolving WLAN or opening the device.
    AWDLWIN_MANUAL_INTERNAL_ACTION_V1 manualRequest{};
    if (manual && !ParseManualInternalAction(argc, argv, manualRequest)) return 2;

    NET_LUID luid{};
    NET_IFINDEX index = 0;
    if (!ResolveTarget(luid, index)) {
        std::wcerr << L"target_identity_mismatch; no OID issued\n";
        return 3;
    }
    USHORT portId = 0;
    if (!ParsePortId(argv[2], portId)) return 2;
    AWDLWIN_ACTION_REQUEST_V1 action{};
    AWDLWIN_ACTION_CONTROL_V1 control{};
    DWORD ioctl = 0;
    const void* input = nullptr;
    DWORD inputLength = 0;
    if (send) {
        ULONG channel = 0, band = 0, timeoutMs = 0, dwellMs = 0;
        size_t peerCount = 0, bodyCount = 0;
        if (!ParseUnsigned(argv[3], channel) || !ParseUnsigned(argv[4], band) ||
            !ParseHex(argv[5], action.Peer, sizeof(action.Peer), peerCount) || peerCount != 6 ||
            !ParseHex(argv[6], action.Body, sizeof(action.Body), bodyCount) || bodyCount < 2 ||
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
            (action.Body[0] != 0x04 && action.Body[0] != 0x7f) ||
#else
            action.Body[0] != 0x04 ||
#endif
            !ParseUnsigned(argv[7], timeoutMs) ||
            !ParseUnsigned(argv[8], dwellMs) || channel == 0 ||
            timeoutMs == 0 || timeoutMs > 1000 || dwellMs > 100) return 2;
        action.Size = sizeof(action);
        action.Version = AWDLWIN_ACTION_VERSION;
        action.ExperimentMagic = AWDLWIN_ACTION_EXPERIMENT_MAGIC;
        action.TargetIfIndex = index;
        action.TargetNetLuidValue = luid.Value;
        action.PortId = portId;
        action.ChannelNumber = channel;
        action.BandId = band;
        action.SendTimeoutMs = timeoutMs;
        action.PostAckDwellMs = dwellMs;
        action.BodyLength = static_cast<USHORT>(bodyCount);
        ioctl = IOCTL_AWDLWIN_EXPERIMENT_ACTION_FRAME;
        input = &action;
        inputLength = sizeof(action);
        if (manual) {
            manualRequest.Action = action;
            ioctl = IOCTL_AWDLWIN_EXPERIMENT_MANUAL_INTERNAL_ACTION;
            input = &manualRequest;
            inputLength = sizeof(manualRequest);
        }
    } else {
        ULONG transactionId = 0;
        if (!ParseUnsigned(argv[3], transactionId) || transactionId == 0) return 2;
        control.Size = sizeof(control);
        control.Version = AWDLWIN_ACTION_VERSION;
        control.ExperimentMagic = abort ? AWDLWIN_ACTION_EXPERIMENT_MAGIC : 0;
        control.TargetIfIndex = index;
        control.TargetNetLuidValue = luid.Value;
        control.TransactionId = transactionId;
        control.PortId = portId;
        ioctl = abort ? IOCTL_AWDLWIN_EXPERIMENT_ABORT_ACTION : IOCTL_AWDLWIN_GET_ACTION_RESULT;
        input = &control;
        inputLength = sizeof(control);
    }
    HANDLE device = CreateFileW(kDevice, GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                OPEN_EXISTING, 0, nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        std::wcerr << L"device_open_error=" << GetLastError() << L'\n';
        return 4;
    }
    AWDLWIN_ACTION_RESULT_V1 result{};
    DWORD bytesReturned = 0;
    if (send) {
        if (manual) std::wcout << L"admission=MANUAL_INTERNAL_SNAPSHOT\n"
            << L"prior_completion=UNVERIFIED\nnormal_completion_evidence_registered=0\n";
        FILETIME issuedAt{};
        GetSystemTimePreciseAsFileTime(&issuedAt);
        ULARGE_INTEGER utc{};
        utc.LowPart = issuedAt.dwLowDateTime;
        utc.HighPart = issuedAt.dwHighDateTime;
        std::wcout << L"request_utc_filetime_100ns=" << utc.QuadPart << L'\n'
                   << L"requested_channel=" << action.ChannelNumber << L'\n'
                   << L"requested_band_id=" << action.BandId << L'\n'
                   << L"send_timeout_ms=" << action.SendTimeoutMs << L'\n'
                   << L"post_ack_dwell_ms=" << action.PostAckDwellMs << L'\n'
                   << L"peer_hex=";
        PrintBytes(action.Peer, sizeof(action.Peer));
        std::wcout << L"\nbody_hex=";
        PrintBytes(action.Body, action.BodyLength);
        std::wcout << L'\n' << std::flush;
    }
    const BOOL ok = DeviceIoControl(device, ioctl, const_cast<void*>(input), inputLength,
                                    &result, sizeof(result), &bytesReturned, nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(device);
    std::wcout << L"ioctl_success=" << (ok ? 1 : 0) << L'\n'
               << L"ioctl_error=" << error << L'\n';
    if (bytesReturned == sizeof(result) && result.Size == sizeof(result) &&
        result.Version == AWDLWIN_ACTION_VERSION) PrintActionResult(result);
    return ActionExitCode(ok, bytesReturned, result);
}

int RunPocAction(int argc, wchar_t** argv) {
    if (argc != 6) {
        std::wcerr << L"usage: Tx10ubProbe.exe poc-action <observed-port-id> <channel> <band-id> <peer-mac-hex>\n";
        return 2;
    }
    NET_LUID luid{};
    NET_IFINDEX index = 0;
    if (!ResolveTarget(luid, index)) return 3;
    const auto before = ReadConnection(L"before");
    if (!before.connected) {
        std::wcerr << L"poc_requires_connected_target; no OID issued\n";
        return 11;
    }
    ULONGLONG eventSequence = 0;
    const int logPreflight = ReadActionEvents(0, &eventSequence, false);
    if (logPreflight != 0) return logPreflight;
    // Reuse the measured non-AWDL Public Action body and existing WDI path.
    wchar_t command[] = L"experimental-action";
    wchar_t body[] = L"040aa76c0200000600000102000101";
    wchar_t timeout[] = L"1000";
    wchar_t dwell[] = L"100";
    wchar_t* sendArgs[] = {argv[0], command, argv[2], argv[3], argv[4], argv[5],
                           body, timeout, dwell};
    const int result = RunExperimentalAction(9, sendArgs);
    // This is an observation window, never a task completion or retry permit.
    Sleep(2100);
    const auto after = ReadConnection(L"after");
    const int logResult = ReadActionEvents(eventSequence);
    const bool sameAssociation = before.connected && after.connected &&
        std::memcmp(before.bssid, after.bssid, sizeof(before.bssid)) == 0;
    std::wcout << L"same_association_at_snapshots=" << sameAssociation << L'\n'
               << L"continuous_wifi_traffic=UNVERIFIED\n"
               << L"on_air=UNVERIFIED\n";
    if (result != 0) return result;
    if (logResult != 0) return logResult;
    return sameAssociation ? 0 : 11;
}

bool SaveResponse(const wchar_t* path, const AWDLWIN_G2_RESULT_V1& result) {
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        std::wcerr << L"response_file_error=" << GetLastError() << L'\n';
        return false;
    }
    DWORD written = 0;
    const bool ok = result.ResponseLength <= AWDLWIN_TX_RESPONSE_CAPACITY &&
                    WriteFile(file, result.Response, result.ResponseLength, &written, nullptr) &&
                    written == result.ResponseLength;
    CloseHandle(file);
    if (!ok) {
        std::wcerr << L"response_write_error=" << GetLastError() << L'\n';
        return false;
    }
    std::wcout << L"response_file=" << path << L'\n';
    return true;
}

int RunTwoRequestControl(int argc, wchar_t** argv) {
    const bool permit = wcscmp(argv[1], L"two-request-permit") == 0;
    AWDLWIN_TWO_REQUEST_CONTROL_V1 request{};
    request.Size = sizeof(request);
    request.Version = AWDLWIN_TWO_REQUEST_VERSION;
    if (permit) {
        size_t count = 0;
        auto parseId = [](const wchar_t* value, ULONGLONG& result) {
            if (!value || !*value) return false;
            result = 0;
            for (const wchar_t* p = value; *p; ++p) {
                if (*p < L'0' || *p > L'9') return false;
                const unsigned digit = *p - L'0';
                if (result > (~0ull - digit) / 10) return false;
                result = result * 10 + digit;
            }
            return result != 0;
        };
        if (argc != 8 || wcscmp(argv[7], L"--confirm-observed-end") != 0 ||
            !ParseHex(argv[2], request.Identity.LoadId, 16, count) || count != 16 ||
            !parseId(argv[3], request.Identity.FilterId) ||
            !parseId(argv[4], request.Identity.ActionId) ||
            !ParsePortId(argv[5], request.Identity.PortId) ||
            !ParseUnsigned(argv[6], request.Identity.TransactionId) ||
            request.Identity.TransactionId == 0) return 2;
        request.PermitMagic = AWDLWIN_TWO_REQUEST_PERMIT_MAGIC;
    } else if (argc != 2) return 2;
    NET_LUID luid{};
    NET_IFINDEX index = 0;
    if (!ResolveTarget(luid, index)) return 3;
    request.TargetNetLuidValue = luid.Value;
    request.TargetIfIndex = index;
    HANDLE device = CreateFileW(kDevice, GENERIC_READ | (permit ? GENERIC_WRITE : 0),
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (device == INVALID_HANDLE_VALUE) return 4;
    AWDLWIN_TWO_REQUEST_STATE_V1 state{};
    DWORD bytes = 0;
    const BOOL ok = DeviceIoControl(device, permit ?
        IOCTL_AWDLWIN_EXPERIMENT_PERMIT_SECOND_ACTION :
        IOCTL_AWDLWIN_GET_TWO_REQUEST_STATE,
        &request, sizeof(request), &state, sizeof(state), &bytes, nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(device);
    if (!ok) { std::wcerr << L"two_request_error=" << error << L'\n'; return 5; }
    if (bytes != sizeof(state) || state.Size != sizeof(state) ||
        state.Version != AWDLWIN_TWO_REQUEST_VERSION || state.Enabled != 1) return 6;
    std::wcout << L"load_id="; PrintBytes(state.Identity.LoadId, 16);
    std::wcout << L"\nfilter_id=" << state.Identity.FilterId
        << L"\naction_id=" << state.Identity.ActionId
        << L"\nport_id=" << state.Identity.PortId
        << L"\ntransaction_id=" << state.Identity.TransactionId
        << L"\nissued_count=" << state.IssuedCount
        << L"\npermit_ever_granted=" << state.PermitEverGranted
        << L"\npermit_armed=" << state.PermitArmed
        << L"\npermit_eligible=" << state.PermitEligible
        << L"\nretired_count=" << state.RetiredActionCount
        << L"\nm3_seen=" << state.M3Seen << L"\nm4_seen=" << state.M4Seen
        << L"\ncallback_refs=" << state.CallbackRefs
        << L"\nissue_in_progress=" << state.IssueInProgress
        << L"\nsubmission_in_progress=" << state.SubmissionInProgress
        << L"\nabort_submission_in_progress=" << state.AbortSubmissionInProgress << L'\n';
    return 0;
}

static bool ParseCompletionEvidence(int argc, wchar_t** argv,
    AWDLWIN_COMPLETION_GATE_EVIDENCE_V1& request) {
    if (!ParseCompletionIdentity(argc, argv, request.Identity,
            request.ObservationGeneration, request.ObservationChallenge) || argc < 12 ||
        !ParseCompletionNumber(argv[11], request.ObservedUtcFileTime100ns)) return false;
    if (wcscmp(argv[10], L"realtek") == 0) {
        if (argc != 17 || wcscmp(argv[12], L"--nonbusy") != 0 ||
            wcscmp(argv[13], L"--held-list-empty") != 0 ||
            wcscmp(argv[14], L"--worker-ended") != 0 ||
            wcscmp(argv[15], L"--wdi-jobs-empty") != 0 ||
            wcscmp(argv[16], L"--wdi-commands-empty") != 0) return false;
        request.EvidenceKind = AWDLWIN_COMPLETION_GATE_EVIDENCE_REALTEK;
        request.EvidenceFlags = AWDLWIN_COMPLETION_GATE_REALTEK_REQUIRED_FLAGS;
        request.EvidenceSource = AWDLWIN_COMPLETION_GATE_SOURCE_MANUAL_REALTEK;
    } else if (wcscmp(argv[10], L"wifi") == 0) {
        if (argc != 15 || wcscmp(argv[12], L"--wifi-maintained") != 0 ||
            wcscmp(argv[13], L"--no-reset") != 0 ||
            wcscmp(argv[14], L"--no-error") != 0) return false;
        request.EvidenceKind = AWDLWIN_COMPLETION_GATE_EVIDENCE_WIFI_MAINTAINED;
        request.EvidenceFlags = AWDLWIN_COMPLETION_GATE_WIFI_REQUIRED_FLAGS;
        request.EvidenceSource = AWDLWIN_COMPLETION_GATE_SOURCE_MANUAL_WIFI;
    } else return false;
    request.Size = sizeof(request);
    request.Version = AWDLWIN_COMPLETION_GATE_VERSION;
    return true;
}

static const wchar_t* CompletionStageName(ULONG stage) {
    switch (stage) {
    case AwdlWinCompletionGateIssued: return L"ISSUED";
    case AwdlWinCompletionGateM3Accepted: return L"M3_ACCEPTED";
    case AwdlWinCompletionGateWaitQuiescence: return L"WAIT_QUIESCENCE";
    case AwdlWinCompletionGateQuiescenceVerified: return L"QUIESCENCE_VERIFIED";
    case AwdlWinCompletionGateNextAdmissible: return L"NEXT_ADMISSIBLE";
    case AwdlWinCompletionGateStop: return L"STOP";
    default: return L"UNKNOWN";
    }
}

static bool RealtekCensusResultValid(const AWDLWIN_REALTEK_CENSUS_REQUEST_V1& request,
    const AWDLWIN_REALTEK_CENSUS_RESULT_V1& result, DWORD bytes) {
    return bytes == sizeof(result) && result.Size == sizeof(result) && result.Version == 1 &&
        result.Source == AWDLWIN_REALTEK_CENSUS_SOURCE_KERNEL_RESOURCE && result.ObservedMask == 0xF &&
        result.FreeWorkers == 8 && result.FreeSlotMask == 0xFF &&
        result.CapturedInterruptTime100ns != 0 &&
        std::memcmp(&request.Identity, &result.Identity, sizeof(result.Identity)) == 0 &&
        result.ObservationGeneration == request.ObservationGeneration &&
        result.ObservationChallenge == request.ObservationChallenge;
}

int RunRealtekCensus(int argc, wchar_t** argv) {
    AWDLWIN_REALTEK_CENSUS_REQUEST_V1 request{};
    if (argc != 10 || !ParseCompletionIdentity(argc, argv, request.Identity,
            request.ObservationGeneration, request.ObservationChallenge)) return 2;
    NET_LUID luid{};
    NET_IFINDEX index = 0;
    if (!ResolveTarget(luid, index)) return 3;
    request.Target = {sizeof(request.Target), 1, index, 0, luid.Value};
    HANDLE device = CreateFileW(kDevice, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        std::wcerr << L"device_open_error=" << GetLastError() << L'\n'; return 4;
    }
    AWDLWIN_REALTEK_CENSUS_RESULT_V1 result{};
    DWORD bytes = 0;
    const BOOL ok = DeviceIoControl(device, IOCTL_AWDLWIN_GET_REALTEK_CENSUS,
        &request, sizeof(request), &result, sizeof(result), &bytes, nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(device);
    if (!ok) {std::wcerr << L"realtek_census_error=" << error << L'\n'; return 5;}
    if (!RealtekCensusResultValid(request, result, bytes)) return 6;
    std::wcout << L"source=KERNEL_FIXED_IMAGE_RESOURCE_CENSUS\nload_id=";
    PrintBytes(result.Identity.LoadId, 16);
    std::wcout << L"\nfilter_id=" << result.Identity.FilterId
        << L"\naction_id=" << result.Identity.ActionId
        << L"\nlifecycle_generation=" << result.Identity.LifecycleGeneration
        << L"\nport_id=" << result.Identity.PortId
        << L"\ntransaction_id=" << result.Identity.TransactionId
        << L"\nobservation_generation=" << result.ObservationGeneration
        << L"\nobservation_challenge=" << result.ObservationChallenge
        << L"\ncaptured_interrupt_time_100ns=" << result.CapturedInterruptTime100ns
        << L"\nobserved_resource_mask=" << result.ObservedMask
        << L"\nfree_workers=" << result.FreeWorkers
        << L"\nfree_slot_mask=" << result.FreeSlotMask
        << L"\nworker_end_history=UNVERIFIED\nwdi_jobs_commands_events=UNOBSERVED"
           L"\nwifi_continuity_reset_history=UNOBSERVED\n";
    return 0;
}

int RunCompletionGateControl(int argc, wchar_t** argv) {
    const bool evidence = wcscmp(argv[1], L"completion-gate-evidence") == 0;
    const bool arm = wcscmp(argv[1], L"completion-gate-next") == 0;
    AWDLWIN_COMPLETION_GATE_TARGET_V1 target{};
    target.Size = sizeof(target);
    target.Version = AWDLWIN_COMPLETION_GATE_VERSION;
    AWDLWIN_COMPLETION_GATE_EVIDENCE_V1 record{};
    AWDLWIN_COMPLETION_GATE_ARM_V1 permit{};
    if (evidence) {
        if (!ParseCompletionEvidence(argc, argv, record)) return 2;
    } else if (arm) {
        if (argc != 11 || wcscmp(argv[10], L"--confirm-next") != 0 ||
            !ParseCompletionIdentity(argc, argv, permit.Identity,
                permit.ObservationGeneration, permit.ObservationChallenge)) return 2;
        permit.Size = sizeof(permit);
        permit.Version = AWDLWIN_COMPLETION_GATE_VERSION;
        permit.ArmMagic = AWDLWIN_COMPLETION_GATE_ARM_MAGIC;
    } else if (argc != 2) return 2;
    NET_LUID luid{};
    NET_IFINDEX index = 0;
    if (!ResolveTarget(luid, index)) return 3;
    target.TargetIfIndex = record.TargetIfIndex = permit.TargetIfIndex = index;
    target.TargetNetLuidValue = record.TargetNetLuidValue = permit.TargetNetLuidValue = luid.Value;
    HANDLE device = CreateFileW(kDevice, GENERIC_READ | ((evidence || arm) ? GENERIC_WRITE : 0),
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (device == INVALID_HANDLE_VALUE) return 4;
    DWORD code = IOCTL_AWDLWIN_GET_COMPLETION_GATE_STATE;
    void* input = &target;
    DWORD inputSize = sizeof(target);
    if (evidence) {
        code = IOCTL_AWDLWIN_SUBMIT_COMPLETION_GATE_EVIDENCE;
        input = &record;
        inputSize = sizeof(record);
    } else if (arm) {
        code = IOCTL_AWDLWIN_ARM_COMPLETION_GATE_NEXT;
        input = &permit;
        inputSize = sizeof(permit);
    }
    AWDLWIN_COMPLETION_GATE_STATE_V1 state{};
    DWORD bytes = 0;
    const BOOL ok = DeviceIoControl(device, code, input, inputSize,
        &state, sizeof(state), &bytes, nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(device);
    if (!ok) { std::wcerr << L"completion_gate_error=" << error << L'\n'; return 5; }
    if (bytes != sizeof(state) || state.Size != sizeof(state) ||
        state.Version != AWDLWIN_COMPLETION_GATE_VERSION ||
        state.Stage > AwdlWinCompletionGateStop) return 6;
    std::wcout << L"load_id="; PrintBytes(state.Identity.LoadId, 16);
    std::wcout << L"\nfilter_id=" << state.Identity.FilterId
        << L"\naction_id=" << state.Identity.ActionId
        << L"\nlifecycle_generation=" << state.Identity.LifecycleGeneration
        << L"\nport_id=" << state.Identity.PortId
        << L"\ntransaction_id=" << state.Identity.TransactionId
        << L"\nobservation_generation=" << state.ObservationGeneration
        << L"\nobservation_challenge=" << state.ObservationChallenge
        << L"\nstage=" << CompletionStageName(state.Stage)
        << L"\nevidence_mask=" << state.EvidenceMask
        << L"\nstop_reason=" << state.StopReason
        << L"\npermission_armed=" << state.PermissionArmed
        << L"\nm3_callback_refs=" << state.M3CallbackRefs
        << L"\ncallback_refs=" << state.CallbackRefs
        << L"\nissue_in_progress=" << state.IssueInProgress
        << L"\nsubmission_in_progress=" << state.SubmissionInProgress
        << L"\nabort_submission_in_progress=" << state.AbortSubmissionInProgress
        << L"\ndriver_quiescent=" << state.DriverQuiescent
        << L"\nm3_seen=" << state.M3Seen
        << L"\nm3_success=" << state.M3Success
        << L"\nfinal_ndis_status=" << state.FinalNdisStatus
        << L"\nwdi_header_status=" << state.WdiHeaderStatus
        << L"\nm4_seen=" << state.M4Seen
        << L"\nretired_count=" << state.RetiredActionCount
        << L"\nhistory_count=" << state.HistoryCount << L'\n';
    for (unsigned i = 0; i < 2; ++i) {
        std::wcout << L"evidence_kind=" << i + 1
            << L" source=" << state.EvidenceSource[i]
            << L" origin=" << (state.EvidenceSource[i] == 0 ? L"UNOBSERVED" :
                (state.EvidenceSource[i] == (i == 0 ?
                    AWDLWIN_COMPLETION_GATE_SOURCE_MANUAL_REALTEK :
                    AWDLWIN_COMPLETION_GATE_SOURCE_MANUAL_WIFI) ? L"MANUAL" : L"UNKNOWN"))
            << L" observed_utc_filetime_100ns=" << state.ObservedUtcFileTime100ns[i]
            << L" receipt_interrupt_100ns=" << state.ReceiptInterruptTime100ns[i] << L'\n';
    }
    return 0;
}

#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
int ReadDataQueryTrace(const wchar_t* devicePath, ULONG index, ULONGLONG luid) {
    const auto device=CreateFileW(devicePath,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,
        nullptr,OPEN_EXISTING,0,nullptr);
    if(device==INVALID_HANDLE_VALUE)return 4;
    AWDLWIN_DATA_QUERY_STATE_REQUEST_V1 input{};
    input.Size=sizeof(input);input.Version=AWDLWIN_DATA_QUERY_TRACE_VERSION;
    input.TargetIfIndex=index;input.TargetNetLuidValue=luid;
    AWDLWIN_DATA_QUERY_TRACE_V1 trace{};DWORD bytes=0;
    const auto ok=DeviceIoControl(device,IOCTL_AWDLWIN_GET_DATA_QUERY_TRACE,&input,sizeof(input),
        &trace,sizeof(trace),&bytes,nullptr);
    const auto error=ok?ERROR_SUCCESS:GetLastError();CloseHandle(device);
    if(!ok||bytes!=sizeof(trace)||trace.Size!=sizeof(trace)||
       trace.Version!=AWDLWIN_DATA_QUERY_TRACE_VERSION||
       trace.RecordCount>AWDLWIN_DATA_QUERY_TRACE_CAPACITY||
       trace.TargetIfIndex!=index||trace.TargetNetLuidValue!=luid) {
        std::wcerr<<L"data_query_trace_error="<<error<<L'\n';return 4;
    }
    std::wcout<<L"data_query_trace_module="<<trace.ModuleId<<L" transaction="<<trace.TransactionId
        <<L" ifindex="<<trace.TargetIfIndex<<L" luid="<<trace.TargetNetLuidValue
        <<L" sequence="<<trace.Sequence<<L" overwritten="<<trace.OverwrittenRecords
        <<L" callbacks="<<trace.CallbackCount<<L" restarts="<<trace.RestartCount
        <<L" running="<<trace.Running<<L" outstanding="<<trace.Outstanding
        <<L" submitting="<<trace.SubmissionInProgress<<L" caller="<<trace.CallerActive
        <<L" completed="<<trace.Completed<<L" idle="<<trace.IdleEventSignaled
        <<L" ndis_status=0x"<<std::hex<<trace.NdisStatus<<std::dec<<L'\n';
    for(ULONG i=0;i<trace.RecordCount;++i) {
        const auto& r=trace.Records[i];
        const wchar_t* name=L"unknown";
        switch(r.Event) {
        case AWDLWIN_DQT_SEND_BEFORE:name=L"send_before";break;
        case AWDLWIN_DQT_SEND_RETURN:name=L"send_return";break;
        case AWDLWIN_DQT_COMPLETE_SEEN:name=L"complete_seen";break;
        case AWDLWIN_DQT_COMPLETE_APPLIED:name=L"complete_applied";break;
        case AWDLWIN_DQT_WAIT_END:name=L"wait_end";break;
        }
        std::wcout<<L"data_query_trace_event="<<name<<L" seq="<<r.Sequence
            <<L" transaction="<<r.TransactionId<<L" interrupt_100ns="<<r.InterruptTime100ns
            <<L" irql="<<r.Irql<<L" restarts="<<r.RestartCount<<L" match_flags="<<r.Flags
            <<L" status=0x"<<std::hex<<r.Status<<L" ndis_status=0x"<<r.NdisStatus<<std::dec
            <<L" detail="<<r.Detail<<L" before_outstanding="<<r.BeforeOutstanding
            <<L" running="<<r.Running<<L" ready="<<r.RestartReady<<L" outstanding="<<r.Outstanding
            <<L" submitting="<<r.SubmissionInProgress<<L" caller="<<r.CallerActive
            <<L" completed="<<r.Completed<<L" idle="<<r.IdleEventSignaled;
        if(r.Event==AWDLWIN_DQT_SEND_BEFORE)
            std::wcout<<L" frame_length="<<r.FrameLength<<L" port="<<r.PortNumber
                <<L" send_flags="<<r.SendFlags<<L" data_backfill="<<r.DataBackFillSize
                <<L" context_backfill="<<r.ContextBackFillSize<<L" dot11_type="<<r.Dot11Type
                <<L" dot11_revision="<<r.Dot11Revision<<L" dot11_size="<<r.Dot11Size
                <<L" exemption="<<r.Exemption<<L" phy="<<r.PhyId<<L" dot11_flags="<<r.Dot11Flags;
        std::wcout<<L'\n';
    }
    return 0;
}

int ReadDataQueryCorrelation(const wchar_t* devicePath, ULONG index, ULONGLONG luid) {
    const auto device=CreateFileW(devicePath,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,
        nullptr,OPEN_EXISTING,0,nullptr);
    if(device==INVALID_HANDLE_VALUE)return 4;
    AWDLWIN_DATA_QUERY_STATE_REQUEST_V1 input{};
    input.Size=sizeof(input);input.Version=AWDLWIN_DATA_QUERY_CORRELATION_VERSION;
    input.TargetIfIndex=index;input.TargetNetLuidValue=luid;
    AWDLWIN_DATA_QUERY_CORRELATION_V1 output{};DWORD bytes=0;
    const auto ok=DeviceIoControl(device,IOCTL_AWDLWIN_GET_DATA_QUERY_CORRELATION,&input,sizeof(input),
        &output,sizeof(output),&bytes,nullptr);
    const auto error=ok?ERROR_SUCCESS:GetLastError();CloseHandle(device);
    if(!ok||bytes!=sizeof(output)||output.Size!=sizeof(output)||
       output.Version!=AWDLWIN_DATA_QUERY_CORRELATION_VERSION||
       output.RecordCount>AWDLWIN_DATA_QUERY_CORRELATION_CAPACITY||
       output.TargetIfIndex!=index||output.TargetNetLuidValue!=luid) {
        std::wcerr<<L"data_query_correlation_error="<<error<<L'\n';return 4;
    }
    std::wcout<<L"data_query_correlation_module="<<output.ModuleId<<L" ifindex="<<index
        <<L" luid="<<luid<<L" count="<<output.RecordCount
        <<L" overwritten="<<output.OverwrittenRecords<<L'\n';
    for(ULONG i=0;i<output.RecordCount;++i) {
        const auto& r=output.Records[i];
        std::wcout<<L"data_query_correlation transaction="<<r.TransactionId
            <<L" nbl=0x"<<std::hex<<r.NblAddress<<std::dec
            <<L" interrupt_100ns="<<r.InterruptTime100ns<<L" utc_filetime_100ns="<<r.SystemTime100ns
            <<L" qpc="<<r.PerformanceCounter<<L" qpc_frequency="<<r.PerformanceFrequency
            <<L" restarts="<<r.RestartCount<<L" frame_length="<<r.FrameLength<<L'\n';
    }
    return 0;
}

int RunPocAwdlAction(int argc, wchar_t** argv) {
    if (argc != 9) {
        std::wcerr << L"usage: Tx10ubProbe.exe poc-awdl-action <port> <channel> <band> <peer-hex> <body-hex> <timeout-ms> <dwell-ms>\n";
        return 2;
    }
    USHORT port = 0;
    ULONG channel = 0, band = 0, timeout = 0, dwell = 0;
    UCHAR peer[6]{}, body[AWDLWIN_ACTION_BODY_CAPACITY]{};
    size_t peerSize = 0, bodySize = 0;
    if (!ParsePortId(argv[2], port) || !ParseUnsigned(argv[3], channel) ||
        !ParseUnsigned(argv[4], band) || channel == 0 || channel > 233 ||
        band != (channel <= 14 ? 1u : 2u) ||
        !ParseHex(argv[5], peer, sizeof(peer), peerSize) || peerSize != 6 ||
        !ParseHex(argv[6], body, sizeof(body), bodySize) || bodySize < 2 ||
        (body[0] != 0x04 && body[0] != 0x7f) ||
        !ParseUnsigned(argv[7], timeout) || timeout == 0 || timeout > 1000 ||
        !ParseUnsigned(argv[8], dwell) || dwell > 100) return 2;
    const UCHAR broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const UCHAR zero[6]{};
    if (std::memcmp(peer, zero, 6) == 0 ||
        ((peer[0] & 1) != 0 && std::memcmp(peer, broadcast, 6) != 0)) return 2;
    const auto before = ReadConnection(L"before");
    if (!before.connected || before.channel != channel) {
        std::wcerr << L"awdl_format_requires_connected_on_channel_target; no OID issued\n";
        return 11;
    }
    ULONGLONG sequence = 0;
    const int preflight = ReadActionEvents(0, &sequence, false);
    if (preflight != 0) return preflight;
    wchar_t command[] = L"experimental-action";
    wchar_t* args[] = {argv[0], command, argv[2], argv[3], argv[4], argv[5],
                       argv[6], argv[7], argv[8]};
    std::wcout << L"awdl_format_single_send=1\nbody_bytes=" << bodySize << L'\n';
    const int result = RunExperimentalAction(9, args);
    // Observation only: this delay never supplies a next-task permit.
    Sleep(2100);
    const auto after = ReadConnection(L"after");
    const int events = ReadActionEvents(sequence);
    const bool same = after.connected && after.channel == before.channel &&
        std::memcmp(before.bssid, after.bssid, 6) == 0;
    std::wcout << L"same_association_at_snapshots=" << same << L'\n'
               << L"continuous_wifi_traffic=UNVERIFIED\non_air=UNVERIFIED\n"
               << L"address3=UNVERIFIED\napple_interop=UNVERIFIED\n";
    if (result != 0) return result;
    if (events != 0) return events;
    return same ? 0 : 11;
}

// Experimental preparation only: public WLAN association, no Action/OID
// submission and no profile/credential retrieval or modification.
int RunStaConnect(int argc,wchar_t** argv, const wchar_t* guidText) {
    UCHAR bssid[6]{};
    size_t bytes=0;
    ULONG channel=0;
    const UCHAR zero[6]{};
    if(argc!=5||!argv[2][0]||wcslen(argv[2])>=WLAN_MAX_NAME_LENGTH||
       !ParseHex(argv[3],bssid,sizeof(bssid),bytes)||bytes!=6||
       (bssid[0]&1)!=0||std::memcmp(bssid,zero,6)==0||
       !ParseUnsigned(argv[4],channel)||(channel!=6&&channel!=44&&channel!=149)) {
        std::wcerr<<L"usage: sta-connect <existing-profile> <bssid-hex> <6|44|149>\n";return 2;
    }
    NET_LUID luid{};NET_IFINDEX index=0;
    if(!ResolveTarget(luid,index))return 3;
    GUID guid{};HANDLE wlan=nullptr;DWORD version=0;
    if(FAILED(CLSIDFromString(guidText,&guid))||
       WlanOpenHandle(2,nullptr,&version,&wlan)!=ERROR_SUCCESS)return 4;
    DOT11_BSSID_LIST desired{};
    desired.Header.Type=NDIS_OBJECT_TYPE_DEFAULT;
    desired.Header.Revision=DOT11_BSSID_LIST_REVISION_1;
    desired.Header.Size=sizeof(desired);
    desired.uNumOfEntries=desired.uTotalNumOfEntries=1;
    std::copy_n(bssid,6,desired.BSSIDs[0]);
    WLAN_CONNECTION_PARAMETERS parameters{};
    parameters.wlanConnectionMode=wlan_connection_mode_profile;
    parameters.strProfile=argv[2];
    parameters.pDesiredBssidList=&desired;
    parameters.dot11BssType=dot11_BSS_type_infrastructure;
    const auto error=WlanConnect(wlan,&guid,&parameters,nullptr);
    std::wcout<<L"sta_connect_error="<<error<<L'\n';
    bool connected=false;
    if(error==ERROR_SUCCESS) {
        const auto deadline=GetTickCount64()+30000;
        do {
            Sleep(250);
            connected=StaStillAssociated(wlan,guid,bssid)&&StaUsesChannel(wlan,guid,channel);
        }while(!connected&&GetTickCount64()<deadline);
    }
    WlanCloseHandle(wlan,nullptr);
    std::wcout<<L"sta_requested_connection_ready="<<connected<<L"\naction_requests=0\n";
    ReadConnection(L"sta_connect_after");
    return connected?0:11;
}

int RunBleV2Advertise(const wchar_t* stopPath) {
    std::wcout << std::unitbuf;
    const auto initial = GetFileAttributesW(stopPath);
    const auto initialError = GetLastError();
    if (initial != INVALID_FILE_ATTRIBUTES || initialError != ERROR_FILE_NOT_FOUND) {
        std::wcerr << L"ble_stop_path_must_be_absent error=" << initialError << L'\n';
        return 2;
    }
    tx10ub::BleAdvertisement advertisement;
    if (!advertisement.start(tx10ub::BleProfile::everyone_v2_comparison)) return 4;
    std::wcout << L"ble_only_waiting_for_stop=1\n";
    int result = 0;
    for (;;) {
        const auto attributes = GetFileAttributesW(stopPath);
        const auto error = GetLastError();
        if (attributes != INVALID_FILE_ATTRIBUTES) break;
        if (error != ERROR_FILE_NOT_FOUND) { result = 4; break; }
        if (!advertisement.healthy()) { result = 4; break; }
        Sleep(100);
    }
    if (!advertisement.close()) result = 4;
    std::wcout << L"ble_only_exit=" << result << L'\n';
    return result;
}
#endif

}
