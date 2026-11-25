#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
#include <winsock2.h>
#include <ws2ipdef.h>
#endif
#include <windows.h>
#include <winioctl.h>
#include <iphlpapi.h>
#include <objbase.h>
#include <wlanapi.h>
#include "Tx10ubUnassociatedControl.h"
#include "DropPorterSendSelection.h"
#include "Tx10ubHost.h"
#include "Tx10ubProbeDiagnostics.h"

#include <cerrno>
#include <atomic>
#include <cstring>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <system_error>
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
#include <netioapi.h>
#include <future>
#include <algorithm>
#include <bit>
#include <functional>
#include <string>
#include <string_view>
#include "../src/awdl_discovery_state.h"
#include "Tx10ubUsbDiscovery.h"
#include "Tx10ubScanIdle.h"
#include "Tx10ubBleAdvertisement.h"
#include "Tx10ubTls.h"
#include "Tx10ubAirDropHttp.h"
#include "Tx10ubAirDropTransfer.h"
#include "Tx10ubComputerName.h"
#include "Tx10ubSendStatus.h"
#include "Tx10ubTargetSelection.h"
#include "Tx10ubNameLookup.h"
#include "Tx10ubReceiveMdns.h"
#include "Tx10ubReceiveWorker.h"
#include "DropPorterHelperFiles.h"
#include "Tx10ubReceiveWorkerProtocol.h"
#include "Tx10ubUserFileAccess.h"
#include "../driver/tx10ub-probe/tx10ub_action_core.h"
#include "Tx10ubDirectIhv.h"
#endif

#include "..\driver\tx10ub-probe\tx10ub_ioctl.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "wlanapi.lib")
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
#endif

namespace {
wchar_t kGuidText[39]{};
ULONGLONG kExpectedLuid = 0;
}

namespace tx10ub::probe {

// Without a GUID, diagnostic modes use the TX10UB; transfer sessions name their adapter.
std::optional<tx10ub::host::Adapter> SelectProbeAdapter(const GUID* expected = nullptr) {
    try {
        auto adapter = expected ? tx10ub::host::DiscoverAdapterByGuid(*expected)
                                : tx10ub::host::DiscoverAdapter();
        if (StringFromGUID2(adapter.guid, kGuidText, static_cast<int>(std::size(kGuidText))) != 39)
            return std::nullopt;
        kExpectedLuid = adapter.luid.Value;
        return adapter;
    } catch (const std::exception& error) {
        std::cerr << "target_adapter_unavailable=" << error.what() << '\n';
        return std::nullopt;
    }
}

void PrintHex(const wchar_t* name, ULONG value) {
    std::wcout << name << L"=0x" << std::hex << std::setw(8) << std::setfill(L'0')
               << value << std::dec << std::setfill(L' ') << L'\n';
}

void PrintBytes(const UCHAR* bytes, size_t count) {
    for (size_t i = 0; i < count; ++i)
        std::wcout << std::hex << std::setw(2) << std::setfill(L'0')
                   << static_cast<unsigned>(bytes[i]);
    std::wcout << std::dec << std::setfill(L' ');
}

ConnectionSnapshot ReadConnection(const wchar_t* phase) {
    ConnectionSnapshot snapshot;
    GUID guid{};
    HANDLE client = nullptr;
    DWORD version = 0;
    if (FAILED(CLSIDFromString(kGuidText, &guid))) return snapshot;
    DWORD error = WlanOpenHandle(2, nullptr, &version, &client);
    if (error != ERROR_SUCCESS) {
        std::wcout << phase << L"_wlan_error=" << error << L'\n';
        return snapshot;
    }
    PVOID data = nullptr;
    DWORD size = 0;
    error = WlanQueryInterface(client, &guid, wlan_intf_opcode_current_connection,
                               nullptr, &size, &data, nullptr);
    std::wcout << phase << L"_connection_error=" << error << L'\n';
    if (error == ERROR_SUCCESS && data != nullptr && size >= sizeof(WLAN_CONNECTION_ATTRIBUTES)) {
        const auto* connection = static_cast<const WLAN_CONNECTION_ATTRIBUTES*>(data);
        snapshot.connected = connection->isState == wlan_interface_state_connected;
        std::memcpy(snapshot.bssid, connection->wlanAssociationAttributes.dot11Bssid, 6);
        if (wcscmp(phase, L"sta") == 0) {
            const auto& association = connection->wlanAssociationAttributes;
            std::wcout << L"sta_phy_type=" << static_cast<ULONG>(association.dot11PhyType) << L'\n'
                       << L"sta_tx_rate_kbps=" << association.ulTxRate << L'\n'
                       << L"sta_rx_rate_kbps=" << association.ulRxRate << L'\n';
        }
    }
    if (data != nullptr) WlanFreeMemory(data);
    data = nullptr;
    size = 0;
    error = WlanQueryInterface(client, &guid, wlan_intf_opcode_channel_number,
                               nullptr, &size, &data, nullptr);
    std::wcout << phase << L"_channel_error=" << error << L'\n';
    if (error == ERROR_SUCCESS && data != nullptr && size >= sizeof(ULONG))
        std::memcpy(&snapshot.channel, data, sizeof(snapshot.channel));
    if (data != nullptr) WlanFreeMemory(data);
    WlanCloseHandle(client, nullptr);
    std::wcout << phase << L"_connected=" << snapshot.connected << L'\n'
               << phase << L"_sta_channel=" << snapshot.channel << L'\n'
               << phase << L"_bssid_hex=";
    PrintBytes(snapshot.bssid, sizeof(snapshot.bssid));
    std::wcout << L'\n';
    return snapshot;
}

bool ResolveTarget(NET_LUID& luid, NET_IFINDEX& index) {
    GUID guid{};
    if (FAILED(CLSIDFromString(kGuidText, &guid))) return false;
    if (ConvertInterfaceGuidToLuid(&guid, &luid) != NO_ERROR) return false;
    if (ConvertInterfaceLuidToIndex(&luid, &index) != NO_ERROR) return false;
    return luid.Value == kExpectedLuid && index != 0;
}

void WINAPI OnScanNotification(PWLAN_NOTIFICATION_DATA notification, PVOID callbackContext) {
    auto* context = static_cast<ScanNotificationContext*>(callbackContext);
    if (notification->NotificationSource != WLAN_NOTIFICATION_SOURCE_ACM ||
        !IsEqualGUID(notification->InterfaceGuid, context->targetGuid)) return;
    if (notification->NotificationCode == wlan_notification_acm_scan_complete)
        InterlockedExchange(&context->outcome, 1);
    else if (notification->NotificationCode == wlan_notification_acm_scan_fail)
        InterlockedExchange(&context->outcome, 2);
    else return;
    SetEvent(context->event);
}

bool ParsePortId(const wchar_t* text, USHORT& portId) {
    if (text == nullptr || *text == L'\0' || *text == L'-') return false;
    wchar_t* end = nullptr;
    errno = 0;
    unsigned long value = wcstoul(text, &end, 0);
    if (errno != 0 || *end != L'\0' || value >= 0xFFFFul) return false;
    portId = static_cast<USHORT>(value);
    return true;
}

bool ParseUnsigned(const wchar_t* value, ULONG& result) {
    if (value == nullptr || *value == L'\0' || *value == L'-') return false;
    wchar_t* end = nullptr;
    errno = 0;
    const unsigned long parsed = wcstoul(value, &end, 0);
    if (errno != 0 || *end != L'\0') return false;
    result = static_cast<ULONG>(parsed);
    return true;
}

static int HexDigit(wchar_t value) {
    if (value >= L'0' && value <= L'9') return value - L'0';
    if (value >= L'a' && value <= L'f') return value - L'a' + 10;
    if (value >= L'A' && value <= L'F') return value - L'A' + 10;
    return -1;
}

bool ParseHex(const wchar_t* value, UCHAR* output, size_t capacity, size_t& count) {
    count = 0;
    if (value == nullptr) return false;
    const size_t length = wcslen(value);
    if (length == 0 || (length & 1) != 0 || length / 2 > capacity) return false;
    for (size_t i = 0; i < length; i += 2) {
        const int hi = HexDigit(value[i]);
        const int lo = HexDigit(value[i + 1]);
        if (hi < 0 || lo < 0) return false;
        output[count++] = static_cast<UCHAR>((hi << 4) | lo);
    }
    return true;
}

static const wchar_t* ActionClassificationName(ULONG classification) {
    switch (classification) {
    case AWDLWIN_ACTION_CLASS_NOT_ISSUED: return L"NOT_ISSUED";
    case AWDLWIN_ACTION_CLASS_OID_PENDING: return L"OID_PENDING";
    case AWDLWIN_ACTION_CLASS_TASK_STARTED: return L"TASK_STARTED_LEGACY";
    case AWDLWIN_ACTION_CLASS_TASK_COMPLETED: return L"TASK_COMPLETED_LEGACY";
    case AWDLWIN_ACTION_CLASS_FAILED_BEFORE_START: return L"FAILED_BEFORE_START";
    case AWDLWIN_ACTION_CLASS_UNVERIFIED: return L"UNVERIFIED";
    case AWDLWIN_ACTION_CLASS_STOP: return L"STOP";
    case AWDLWIN_ACTION_CLASS_REQUEST_ACCEPTED: return L"REQUEST_ACCEPTED";
    case AWDLWIN_ACTION_CLASS_ABORT_REJECTED: return L"ABORT_REJECTED";
    case AWDLWIN_ACTION_CLASS_ABORT_PENDING: return L"ABORT_PENDING";
    default: return L"UNKNOWN";
    }
}

int ActionExitCode(BOOL ioctlSuccess, DWORD bytesReturned,
                   const AWDLWIN_ACTION_RESULT_V1& result) {
    if (!ioctlSuccess) return 5;
    if (bytesReturned != sizeof(result) || result.Size != sizeof(result) ||
        result.Version != AWDLWIN_ACTION_VERSION) return 6;
    if (result.Classification == AWDLWIN_ACTION_CLASS_STOP)
        return result.StopReason == AWDLWIN_ACTION_STOP_M3_STUCK ? 10 : 9;
    if (result.Classification == AWDLWIN_ACTION_CLASS_FAILED_BEFORE_START ||
        result.Classification == AWDLWIN_ACTION_CLASS_ABORT_REJECTED) return 8;
    if (result.Classification == AWDLWIN_ACTION_CLASS_REQUEST_ACCEPTED) {
        if (!result.OidIssued || !result.M3Seen || result.FinalNdisStatus != 0 ||
            result.WdiHeaderStatus != 0 || result.StopReason != AWDLWIN_ACTION_STOP_NONE ||
            (result.AbortIssued && (!result.AbortCompleted || result.AbortNdisStatus != 0)))
            return 6;
        return 0;
    }
    // Legacy results and pending requests cannot establish the new boundary.
    return 7;
}

void PrintActionResult(const AWDLWIN_ACTION_RESULT_V1& result) {
    std::wcout << L"action_result_version=" << result.Version << L'\n'
               << L"classification=" << result.Classification << L'\n'
               << L"classification_name=" << ActionClassificationName(result.Classification) << L'\n'
               << L"runtime_boundary=oid_completion\n"
               << L"oid_issued=" << result.OidIssued << L'\n'
               << L"target_luid=" << result.TargetNetLuidValue << L'\n'
               << L"port_id=" << result.PortId << L'\n'
               << L"transaction_id=" << result.TransactionId << L'\n'
               << L"abort_transaction_id=" << result.AbortTransactionId << L'\n'
               << L"task_state=" << result.TaskState << L'\n'
               << L"m3_seen=" << result.M3Seen << L'\n'
               << L"m4_seen=" << result.M4Seen << L'\n'
               << L"abort_issued=" << result.AbortIssued << L'\n'
               << L"abort_completed=" << result.AbortCompleted << L'\n'
               << L"wrong_m4_count=" << result.WrongM4Count << L'\n'
               << L"duplicate_m4_count=" << result.DuplicateM4Count << L'\n'
               << L"stop_reason=" << result.StopReason << L'\n'
               << L"last_m4_rejection_reason=" << result.LastM4RejectionReason << L'\n';
    PrintHex(L"submit_ndis_status", result.SubmitNdisStatus);
    PrintHex(L"final_ndis_status", result.FinalNdisStatus);
    PrintHex(L"wdi_header_status", result.WdiHeaderStatus);
    PrintHex(L"m4_header_status", result.M4HeaderStatus);
    PrintHex(L"abort_ndis_status", result.AbortNdisStatus);
}

int ReadActionEvents(ULONGLONG afterSequence, ULONGLONG* newest, bool printRecords) {
    HANDLE device = CreateFileW(kDevice, GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                OPEN_EXISTING, 0, nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        std::wcerr << L"action_event_open_error=" << GetLastError() << L'\n';
        return 4;
    }
    auto log = std::make_unique<AWDLWIN_ACTION_FRAME_STATUS_LOG_V2>();
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(device, IOCTL_AWDLWIN_GET_ACTION_FRAME_STATUS_LOG,
                                    nullptr, 0, log.get(), sizeof(*log), &returned, nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(device);
    if (!ok) {
        std::wcerr << L"action_event_ioctl_error=" << error << L'\n';
        return 5;
    }
    if (returned != sizeof(*log) || log->Size != sizeof(*log) ||
        log->Version != AWDLWIN_ACTION_FRAME_STATUS_LOG_VERSION ||
        log->Count > _countof(log->Records)) return 6;
    ULONGLONG previous = 0;
    for (ULONG i = 0; i < log->Count; ++i) {
        const auto& record = log->Records[i];
        if (record.CopiedLength > sizeof(record.Prefix) ||
            record.CopiedLength > record.OriginalLength || record.Sequence <= previous)
            return 6;
        previous = record.Sequence;
    }
    if (newest != nullptr) *newest = previous;
    std::wcout << L"action_event_snapshot_count=" << log->Count << L'\n'
               << L"action_event_newest_sequence=" << previous << L'\n';
    if (!printRecords) return 0;
    if (afterSequence != 0 && log->Count != 0 &&
        log->Records[0].Sequence > afterSequence + 1)
        std::wcout << L"action_event_history_overwritten=1\n";
    for (ULONG i = 0; i < log->Count; ++i) {
        const auto& record = log->Records[i];
        if (record.Sequence <= afterSequence) continue;
        std::wcout << L"action_event sequence=" << record.Sequence
                   << L" monotonic_100ns=" << record.InterruptTime100ns
                   << L" status_code=0x" << std::hex << record.StatusCode << std::dec
                   << L" target_luid=" << record.TargetNetLuidValue
                   << L" target_if_index=" << record.TargetIfIndex
                   << L" filter_luid=" << record.FilterNetLuidValue
                   << L" filter_if_index=" << record.FilterIfIndex
                   << L" ndis_port_number=" << record.PortNumber
                   << L" original_length=" << record.OriginalLength
                   << L" copied_length=" << record.CopiedLength;
        if (record.CopiedLength >= AWDLWIN_TX_WDI_HEADER_SIZE) {
            USHORT port = 0;
            ULONG status = 0, transaction = 0;
            std::memcpy(&port, record.Prefix, sizeof(port));
            std::memcpy(&status, record.Prefix + 4, sizeof(status));
            std::memcpy(&transaction, record.Prefix + 8, sizeof(transaction));
            std::wcout << L" wdi_port_id=" << port << L" wdi_transaction_id=" << transaction
                       << L" wdi_status=0x" << std::hex << status << std::dec;
        }
        std::wcout << L" prefix_hex=";
        PrintBytes(record.Prefix, record.CopiedLength);
        std::wcout << L'\n';
    }
    std::wcout << L"event_visibility=lwf_delivered_only\n";
    return 0;
}

// One open WLAN handle per run: this is polled after every send, unlike the
// ReadConnection snapshots.
bool StaStillAssociated(HANDLE client, const GUID& guid, const UCHAR (&bssid)[6]) {
    PVOID data = nullptr;
    DWORD size = 0;
    const DWORD error = WlanQueryInterface(client, &guid, wlan_intf_opcode_current_connection,
                                           nullptr, &size, &data, nullptr);
    bool associated = false;
    if (error == ERROR_SUCCESS && data != nullptr && size >= sizeof(WLAN_CONNECTION_ATTRIBUTES)) {
        const auto* connection = static_cast<const WLAN_CONNECTION_ATTRIBUTES*>(data);
        associated = connection->isState == wlan_interface_state_connected &&
            std::memcmp(connection->wlanAssociationAttributes.dot11Bssid, bssid, 6) == 0;
    }
    if (data != nullptr) WlanFreeMemory(data);
    if (!associated) std::wcout << L"sta_check_error=" << error << L'\n';
    return associated;
}

#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
bool StaUsesChannel(HANDLE wlan,const GUID& guid,ULONG expected) {
    PVOID data=nullptr;
    DWORD size=0;
    const auto error=WlanQueryInterface(wlan,&guid,wlan_intf_opcode_channel_number,
        nullptr,&size,&data,nullptr);
    ULONG channel=0;
    if(error==ERROR_SUCCESS&&data&&size>=sizeof(channel))std::memcpy(&channel,data,sizeof(channel));
    if(data)WlanFreeMemory(data);
    return channel==expected;
}
#endif

}

using namespace tx10ub::probe;
namespace events = tx10ub::probe_events;

namespace {

const wchar_t* RepeatStopReason(int code, DWORD ioctlError) {
    switch (code) {
    case 10: return L"m3_stuck";
    case 8: return L"m3_failed";
    case 9: return L"driver_stop";
    case 5: return ioctlError == ERROR_BUSY ? L"driver_busy" : L"ioctl_failed";
    default: return L"unexpected_result";
    }
}

// M3 timeout is sticky in the driver. A later query only shows whether the OID
// eventually completed, which decides if `sc stop` can still drain it.
void PrintLateM3(HANDLE device, const AWDLWIN_ACTION_REQUEST_V1& action, ULONG transactionId) {
    Sleep(5000);
    AWDLWIN_ACTION_CONTROL_V1 control{};
    control.Size = sizeof(control);
    control.Version = AWDLWIN_ACTION_VERSION;
    control.TargetIfIndex = action.TargetIfIndex;
    control.TargetNetLuidValue = action.TargetNetLuidValue;
    control.TransactionId = transactionId;
    control.PortId = action.PortId;
    AWDLWIN_ACTION_RESULT_V1 late{};
    DWORD bytesReturned = 0;
    if (DeviceIoControl(device, IOCTL_AWDLWIN_GET_ACTION_RESULT, &control, sizeof(control),
                        &late, sizeof(late), &bytesReturned, nullptr) &&
        bytesReturned == sizeof(late))
        std::wcout << L"m3_seen_after_5s=" << late.M3Seen << L'\n';
    else
        std::wcout << L"m3_seen_after_5s=UNVERIFIED\n";
}

#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
class DirectIhvSession final {
public:
    explicit DirectIhvSession(const tx10ub::host::Adapter& adapter) : direct_(adapter) {}

    tx10ub::direct_ihv::OperationResult SendAction(
        const AWDLWIN_AF_PARAMETERS& parameters, UnassociatedControl* control,
        std::span<const UCHAR> serviceBody) {
        return Invoke(control, true, [&](auto& direct) { return direct.SendAction(parameters, serviceBody); });
    }

    tx10ub::direct_ihv::OperationResult SendData(
        std::span<const UCHAR, 6> source, std::span<const UCHAR> frame,
        UnassociatedControl* control,
        tx10ub::direct_ihv::DataRate rate=tx10ub::direct_ihv::DataRate::Mbps12) {
        // The owner loop checks the lease before granting the send window.
        // Do not call UnassociatedControl::healthy() from this worker thread.
        return Invoke(control, false, [&](auto& direct) { return direct.SendData(source, frame, rate); });
    }

    tx10ub::direct_ihv::OperationResult SetWps(
        std::span<const UCHAR> ie, UnassociatedControl* control) {
        return Invoke(control, true, [&](auto& direct) { return direct.SetWps(ie); });
    }

    tx10ub::direct_ihv::OperationResult ClearWps(UnassociatedControl* control) {
        return Invoke(control, false, [](auto& direct) { return direct.ClearWps(); });
    }

    tx10ub::direct_ihv::OperationResult DisableEncryption(UnassociatedControl* control) {
        return Invoke(control, true, [](auto& direct) { return direct.DisableEncryption(); });
    }
    tx10ub::direct_ihv::OperationResult EncryptionStatus(UnassociatedControl* control) {
        return Invoke(control, true, [](auto& direct) { return direct.QueryEncryptionStatus(); });
    }

    DWORD Close() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_) return closeStatus_;
        closeStatus_ = direct_.Close();
        closed_ = true;
        return closeStatus_;
    }

    bool drained() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return closed_ && closeStatus_ == ERROR_SUCCESS && !quarantined_;
    }

private:
    template<class Call>
    tx10ub::direct_ihv::OperationResult Invoke(
        UnassociatedControl* control, bool checkControlHealth, Call&& call) {
        tx10ub::direct_ihv::OperationResult result{};
        if (!control || (checkControlHealth && !control->healthy())) {
            result.win32Status = ERROR_OPERATION_ABORTED;
            return result;
        }
        UnassociatedControl::Send sending(control);
        std::lock_guard<std::mutex> lock(mutex_);
        // A lost/cancelled retune acknowledgement does not prove that the
        // controller's lower request has settled. This also gates WPS cleanup,
        // which normally remains allowed after an ordinary operator stop.
        if(control->radio_handoff_uncertain())quarantined_=true;
        if (closed_ || quarantined_) {
            result.win32Status = ERROR_TIMEOUT;
            result.transportQuarantined = quarantined_;
            sending.settled = !quarantined_;
            return result;
        }
        result = call(direct_);
        quarantined_ = result.transportQuarantined;
        // WlanIhvControl is synchronous. An ordinary returned error is settled;
        // only the DirectIhv uncertain-transport classification blocks restart.
        sending.settled = !result.transportQuarantined;
        return result;
    }

    tx10ub::direct_ihv::DirectIhv direct_;
    mutable std::mutex mutex_;
    bool closed_{};
    DWORD closeStatus_{ERROR_SUCCESS};
    bool quarantined_{};
};

std::atomic<DirectIhvSession*> gDirectIhvSession{};
std::atomic<std::uint32_t> gDirectTransactionId{1};

std::uint32_t NextDirectTransactionId() noexcept {
    auto value = gDirectTransactionId.fetch_add(1, std::memory_order_relaxed);
    if (value == 0) value = gDirectTransactionId.fetch_add(1, std::memory_order_relaxed);
    return value;
}

class DirectServiceHandle final {
public:
    explicit DirectServiceHandle(SC_HANDLE value=nullptr) noexcept : value_(value) {}
    ~DirectServiceHandle() { if(value_) CloseServiceHandle(value_); }
    DirectServiceHandle(const DirectServiceHandle&)=delete;
    DirectServiceHandle& operator=(const DirectServiceHandle&)=delete;
    SC_HANDLE get() const noexcept { return value_; }
private:
    SC_HANDLE value_{};
};

tx10ub::host::Adapter VerifyDirectIhvEnvironment(NET_LUID expectedLuid,NET_IFINDEX expectedIndex,
                                                 bool fileSend, bool ndiscapFileReceive) {
    DirectServiceHandle manager(OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT));
    if(!manager.get())throw std::system_error(GetLastError(),std::system_category(),"auxiliary_manager_open_failed");
    DirectServiceHandle auxiliary(OpenServiceW(manager.get(),L"AWDLWinTx10ubProbe",SERVICE_QUERY_STATUS));
    if(!auxiliary.get()) {
        if(GetLastError()!=ERROR_SERVICE_DOES_NOT_EXIST)
            throw std::system_error(GetLastError(),std::system_category(),"auxiliary_status_open_failed");
    } else {
        SERVICE_STATUS_PROCESS status{};DWORD returned{};
        if(!QueryServiceStatusEx(auxiliary.get(),SC_STATUS_PROCESS_INFO,
            reinterpret_cast<BYTE*>(&status),sizeof(status),&returned))
            throw std::system_error(GetLastError(),std::system_category(),"auxiliary_state_query_failed");
        if(returned!=sizeof(status)||status.dwCurrentState!=SERVICE_STOPPED)
            throw std::runtime_error("auxiliary_must_be_stopped_for_direct_control");
    }

    GUID expectedGuid{};
    if(FAILED(CLSIDFromString(kGuidText,&expectedGuid)))
        throw std::runtime_error("direct_target_identity_mismatch");
    const auto adapter=tx10ub::host::DiscoverAdapterByGuid(expectedGuid);
    if (!fileSend && !ndiscapFileReceive && tx10ub::host::ProfileOf(adapter).diagnosticImage != adapter.driverImage)
        throw std::runtime_error("unsupported_driver_image");
    if(adapter.luid.Value!=expectedLuid.Value||adapter.index!=expectedIndex)
        throw std::runtime_error("direct_target_identity_mismatch");
    return adapter;
}

bool DirectAccepted(const tx10ub::direct_ihv::OperationResult& result) noexcept {
    return result.win32Status == ERROR_SUCCESS &&
        result.responseValidation == tx10ub::direct_ihv::ResponseValidation::Valid &&
        result.acceptance == tx10ub::direct_ihv::RequestAcceptance::Accepted;
}

void CopyDirectResult(const tx10ub::direct_ihv::OperationResult& source,
                      AWDLWIN_RAW_ACTION_RESULT_V1& target,
                      std::uint32_t transactionId = 0) noexcept {
    const bool accepted = DirectAccepted(source);
    target.Size = sizeof(target);
    target.Version = AWDLWIN_RAW_ACTION_VERSION;
    target.TransactionId = transactionId;
    target.OidIssued = source.callIssued ? 1u : 0u;
    target.CompletionObserved = 1;
    target.OperationStatus = source.win32Status != ERROR_SUCCESS
        ? source.win32Status : (accepted ? ERROR_SUCCESS : ERROR_INVALID_DATA);
    target.ResponseValidated = accepted ? 1u : 0u;
    target.VendorRequestAccepted = accepted ? 1u : 0u;
}

struct RawActionCall {
    AWDLWIN_RAW_ACTION_RESULT_V1 result{};
    DWORD bytesReturned=0;
    DWORD error=ERROR_SUCCESS;
    ULONG attempts=0;
    bool ioctlOk=false;
    bool stationValid=true;
};

RawActionCall IssueRawAction(HANDLE device,HANDLE wlan,const GUID& guid,
    const UCHAR (&bssid)[6],ULONG channel,AWDLWIN_RAW_ACTION_REQUEST_V1& request,
    bool retryPreIssueBusy=true,bool verifyStation=true,UnassociatedControl* control=nullptr,
    DirectIhvSession* direct=nullptr, const tx10ub::airdrop::ReceiveMdns* receiveService=nullptr) {
    constexpr ULONG busyWaitMs=200;
    constexpr ULONG preIssueBusyRetryLimit=3;
    constexpr ULONG statusDeviceBusy=0x80000011u;
    RawActionCall call{};
    for(;;) {
        if(verifyStation&&(!StaStillAssociated(wlan,guid,bssid)||!StaUsesChannel(wlan,guid,channel))) {
            call.error=ERROR_INVALID_STATE;
            call.stationValid=false;
            break;
        }
        call.result={};
        call.bytesReturned=0;
        ++call.attempts;
        if(control&&!control->healthy()){call.error=ERROR_OPERATION_ABORTED;break;}
        if(direct) {
            AWDLWIN_AF_PARAMETERS parameters{};
            parameters.PortId = 0;
            parameters.TransactionId = NextDirectTransactionId();
            parameters.ChannelNumber = channel;
            parameters.BandId = channel <= 14 ? 1u : 2u;
            std::fill_n(parameters.Peer, 6, static_cast<UCHAR>(0xff));
            parameters.SendTimeoutMs = 1000;
            parameters.BodyLength = static_cast<USHORT>(request.BodyLength);
            std::copy_n(request.Body, request.BodyLength, parameters.Body);
            const auto serviceBody = receiveService
                ? receiveService->service_action(std::span(request.Body,request.BodyLength))
                : awdlwin::wire::Bytes{};
            const auto operation = direct->SendAction(parameters, control, serviceBody);
            call.error = operation.win32Status;
            call.ioctlOk = true; // The direct call returned synchronously.
            call.bytesReturned = sizeof(call.result);
            CopyDirectResult(operation, call.result, parameters.TransactionId);
            break;
        }
        UnassociatedControl::Send sending(control);
        call.ioctlOk=DeviceIoControl(device,IOCTL_AWDLWIN_EXPERIMENT_RAW_ACTION_FRAME,
            &request,sizeof(request),
            &call.result,sizeof(call.result),&call.bytesReturned,nullptr);
        call.error=call.ioctlOk?ERROR_SUCCESS:GetLastError();
        sending.settled=call.ioctlOk&&call.bytesReturned==sizeof(call.result)&&
            call.result.Size==sizeof(call.result)&&call.result.Version==AWDLWIN_RAW_ACTION_VERSION&&
            (!call.result.OidIssued||(call.result.FinalNdisStatus!=ERROR_IO_PENDING&&
             call.result.FinalNdisStatus!=0x103u&&call.result.OperationStatus!=0xc00000b5u));
        if(!call.ioctlOk||call.bytesReturned!=sizeof(call.result)||
           call.result.Size!=sizeof(call.result)||call.result.Version!=AWDLWIN_RAW_ACTION_VERSION)break;
        if(call.result.OidIssued==0&&call.result.OperationStatus==statusDeviceBusy&&
           (call.result.AdmissionBusyReason==AWDLWIN_RAW_ACTION_BUSY_SELF_OID||
            call.result.AdmissionBusyReason==AWDLWIN_RAW_ACTION_BUSY_DATA_QUERY)&&
           retryPreIssueBusy&&call.attempts<=preIssueBusyRetryLimit) {
            std::wcout<<L"raw_action_admission_busy_reason="<<call.result.AdmissionBusyReason
                <<L" retry="<<call.attempts<<L"\n";
            Sleep(busyWaitMs);
            continue;
        }
        break;
    }
    return call;
}

int RawActionExitCode(const RawActionCall& call) {
    if(!call.ioctlOk||call.bytesReturned!=sizeof(call.result)||
       call.result.Size!=sizeof(call.result)||call.result.Version!=AWDLWIN_RAW_ACTION_VERSION)return 5;
    if(call.result.OperationStatus==0x80000011u&&call.result.OidIssued==0)return 8;
    if(call.result.OperationStatus!=0||!call.result.VendorRequestAccepted||
       !call.result.ResponseValidated)return 9;
    return 0;
}

class VendorWpsTrial {
    HANDLE device_=INVALID_HANDLE_VALUE;
    AWDLWIN_VENDOR_WPS_REQUEST_V1 request_{};
    UnassociatedControl* control_=nullptr;
    DirectIhvSession* direct_=nullptr;
    bool attempted_=false,settled_=true,closed_=true,closeAttempted_=false;
    bool issue(bool enabled) {
        request_.Enabled=enabled?1u:0u;
        if(direct_) {
            const auto operation=direct_->SetWps(
                std::span<const UCHAR>(request_.Ie,request_.IeLength),control_);
            settled_=!operation.transportQuarantined;
            const bool accepted=DirectAccepted(operation);
            std::wcout<<L"vendor_wps_enabled_request="<<enabled
                <<L" direct_call_issued="<<operation.callIssued
                <<L" win32_status="<<operation.win32Status
                <<L" response_validated="<<accepted<<L'\n';
            return accepted;
        }
        UnassociatedControl::Send sending(control_);
        AWDLWIN_RAW_ACTION_RESULT_V1 result{};DWORD bytes=0;
        const auto ok=DeviceIoControl(device_,IOCTL_AWDLWIN_EXPERIMENT_VENDOR_WPS,
            &request_,sizeof(request_),&result,sizeof(result),&bytes,nullptr);
        settled_=ok&&bytes==sizeof(result)&&result.Size==sizeof(result)&&
            result.Version==AWDLWIN_RAW_ACTION_VERSION&&
            (!result.OidIssued||(result.FinalNdisStatus!=0x103u&&
              result.FinalNdisStatus!=ERROR_IO_PENDING&&result.OperationStatus!=0xc00000b5u));
        sending.settled=settled_;
        std::wcout<<L"vendor_wps_enabled_request="<<enabled<<L" ioctl_error="<<(ok?0:GetLastError())
            <<L" oid_issued="<<result.OidIssued<<L" accepted="<<result.VendorRequestAccepted
            <<L" response_validated="<<result.ResponseValidated<<L" transaction="<<result.TransactionId<<L'\n';
        PrintHex(L"vendor_wps_operation_status",result.OperationStatus);
        PrintHex(L"vendor_wps_ndis_status",result.FinalNdisStatus);
        PrintHex(L"vendor_wps_wdi_status",result.WdiHeaderStatus);
        return settled_&&result.OperationStatus==0&&result.VendorRequestAccepted&&result.ResponseValidated;
    }
    bool clear() {
        if(direct_) {
            const auto operation=direct_->ClearWps(control_);
            settled_=!operation.transportQuarantined;
            const bool acceptedEffectUnverified=operation.wpsClearStatus==
                tx10ub::direct_ihv::WpsClearStatus::AcceptedEffectUnverified;
            const bool knownInvalidLength=operation.wpsClearStatus==
                tx10ub::direct_ihv::WpsClearStatus::KnownInvalidLengthC0010014;
            const wchar_t* outcome=acceptedEffectUnverified?L"accepted_effect_unverified":
                knownInvalidLength?L"known_invalid_length_reset_required":
                settled_?L"settled_clear_error_reset_required":L"transport_uncertain";
            std::wcout<<L"vendor_wps_clear_requested=1 direct_call_issued="<<operation.callIssued
                <<L" win32_status="<<operation.win32Status
                <<L" outcome="<<outcome<<L" settled="<<settled_
                <<L" ie_clear_readback=UNVERIFIED\n";
            return acceptedEffectUnverified;
        }
        AWDLWIN_VENDOR_WPS_CLEAR_REQUEST_V1 request{};
        request.Size=sizeof(request);request.Version=AWDLWIN_VENDOR_WPS_CLEAR_VERSION;
        request.ConfirmMagic=AWDLWIN_VENDOR_WPS_CLEAR_CONFIRM_MAGIC;
        request.TargetIfIndex=request_.TargetIfIndex;
        request.TargetNetLuidValue=request_.TargetNetLuidValue;
        AWDLWIN_VENDOR_WPS_CLEAR_RESULT_V1 result{};DWORD bytes=0;
        UnassociatedControl::Send sending(control_);
        const auto ok=DeviceIoControl(device_,IOCTL_AWDLWIN_EXPERIMENT_VENDOR_WPS_CLEAR,
            &request,sizeof(request),&result,sizeof(result),&bytes,nullptr);
        const auto error=ok?ERROR_SUCCESS:GetLastError();
        const bool valid=ok&&bytes==sizeof(result)&&result.Raw.Size==sizeof(result.Raw)&&
            result.Raw.Version==AWDLWIN_RAW_ACTION_VERSION;
        settled_=valid&&(!result.Raw.OidIssued||
            (result.Raw.FinalNdisStatus!=0x103u&&result.Raw.FinalNdisStatus!=ERROR_IO_PENDING&&
             result.Raw.OperationStatus!=0xc00000b5u));
        sending.settled=settled_;
        const bool expectedStatus=
            (result.Raw.FinalNdisStatus==0xc0010014u&&
             (result.Raw.WdiHeaderStatus==0||result.Raw.WdiHeaderStatus==0xc0010014u))||
            (result.Raw.FinalNdisStatus==0&&result.Raw.WdiHeaderStatus==0xc0010014u);
        const bool normalCompletion=result.KnownError==0&&result.Raw.OperationStatus==0&&
            result.Raw.FinalNdisStatus==0&&result.Raw.WdiHeaderStatus==0&&
            result.Raw.VendorRequestAccepted==1&&result.Raw.ResponseValidated==1;
        const bool clearCompletion=normalCompletion||(result.KnownError==1&&expectedStatus);
        const bool verified=valid&&settled_&&result.ClearRequested==1&&result.Raw.OidIssued==1&&
            result.Raw.TransactionId!=0&&clearCompletion&&result.ObservationValid==1&&
            result.Cleared==1&&result.Enabled==0&&result.RelatedFlag==0&&result.IeLength==0&&
            result.IeBytesZero==1&&result.ObservationStatus==0;
        std::wcout<<L"vendor_wps_clear_requested="<<(valid?result.ClearRequested:0)
            <<L" ioctl_error="<<error<<L" oid_issued="<<result.Raw.OidIssued
            <<L" transaction="<<result.Raw.TransactionId
            <<L" known_error="<<(valid?result.KnownError:0)
            <<L" settled="<<settled_
            <<L" observation_valid="<<(valid?result.ObservationValid:0)
            <<L" ie_clear_verified="<<verified<<L'\n';
        PrintHex(L"vendor_wps_clear_operation_status",result.Raw.OperationStatus);
        PrintHex(L"vendor_wps_clear_ndis_status",result.Raw.FinalNdisStatus);
        PrintHex(L"vendor_wps_clear_wdi_status",result.Raw.WdiHeaderStatus);
        PrintHex(L"vendor_wps_clear_observation_status",result.ObservationStatus);
        if(valid&&result.ObservationValid==1)
            std::wcout<<L"vendor_wps_clear_enabled="<<result.Enabled<<L" ie_length="<<result.IeLength
                <<L" ie_bytes_zero="<<result.IeBytesZero<<L" related_flag="<<result.RelatedFlag<<L'\n';
        return verified;
    }
public:
    ~VendorWpsTrial(){close();}
    bool drained() const noexcept { return direct_ ? (!attempted_||settled_) : closed_; }
    bool clear_existing(NET_LUID luid,NET_IFINDEX index) {
        if(device_!=INVALID_HANDLE_VALUE)return false;
        request_.TargetIfIndex=index;request_.TargetNetLuidValue=luid.Value;
        device_=CreateFileW(kDevice,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,
            nullptr,OPEN_EXISTING,0,nullptr);
        if(device_==INVALID_HANDLE_VALUE)return false;
        closed_=clear();
        CloseHandle(device_);device_=INVALID_HANDLE_VALUE;
        return closed_;
    }
    bool enable(NET_LUID luid,NET_IFINDEX index,const UCHAR (&self)[6],UnassociatedControl* control,
                DirectIhvSession* direct=nullptr) {
        if(!control||!control->healthy())return false;
        control_=control;direct_=direct;
        request_.Size=sizeof(request_);request_.Version=AWDLWIN_VENDOR_WPS_VERSION;
        request_.ConfirmMagic=AWDLWIN_VENDOR_WPS_CONFIRM_MAGIC;
        request_.TargetIfIndex=index;request_.TargetNetLuidValue=luid.Value;
        // Comparison IE: WPS version, request type, UUID-E, config methods.
        const UCHAR ie[40]={0,0x50,0xf2,4,0x10,0x4a,0,1,0x10,0x10,0x3a,0,1,1,
            0x10,0x47,0,16,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10,8,0,2,0,0x84};
        request_.IeLength=sizeof(ie);std::copy_n(ie,sizeof(ie),request_.Ie);
        std::copy_n(self,6,request_.Ie+28);
        attempted_=true;closed_=false;
        if(direct_)return issue(true);
        device_=CreateFileW(kDevice,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,
            nullptr,OPEN_EXISTING,0,nullptr);
        if(device_==INVALID_HANDLE_VALUE)return false;
        return issue(true);
    }
    bool close() {
        if(direct_&&attempted_&&device_==INVALID_HANDLE_VALUE) {
            if(closeAttempted_)return closed_;
            closeAttempted_=true;
            closed_=!attempted_||(settled_&&clear());
            std::wcout<<L"vendor_wps_cleanup_result="
                <<(closed_?L"accepted_effect_unverified":settled_?L"settled_error_reset_required":L"transport_uncertain")
                <<L" network_function_restart_required=1\n";
            return closed_;
        }
        if(device_!=INVALID_HANDLE_VALUE) {
            closed_=!attempted_||(settled_&&clear());
            CloseHandle(device_);device_=INVALID_HANDLE_VALUE;
            std::wcout<<L"vendor_wps_disabled="<<closed_
                <<L" previous_ie_restored=0 previous_ie_restore_unverified=1\n";
        }
        return closed_;
    }
};

bool IssueEncryptionDisabled(NET_LUID luid,NET_IFINDEX index,UnassociatedControl* control,
                             DirectIhvSession* direct=nullptr) {
    if(!control||!control->healthy())return false;
    if(direct) {
        const auto operation=direct->DisableEncryption(control);
        const bool accepted=DirectAccepted(operation);
        std::wcout<<L"vendor_encryption_disabled_request=1 direct_call_issued="<<operation.callIssued
            <<L" win32_status="<<operation.win32Status
            <<L" response_validated="<<accepted<<L'\n';
        if(!accepted)return false;
        const auto current=direct->EncryptionStatus(control);
        const bool disabled=DirectAccepted(current)&&current.value&&*current.value==1u;
        std::wcout<<L"vendor_encryption_readback_status="<<current.win32Status
            <<L" value="<<(current.value?std::to_wstring(*current.value):L"unavailable")
            <<L" disabled="<<disabled<<L'\n';
        return disabled;
    }
    HANDLE device=CreateFileW(kDevice,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,
        nullptr,OPEN_EXISTING,0,nullptr);
    if(device==INVALID_HANDLE_VALUE)return false;
    AWDLWIN_ENCRYPTION_DISABLED_REQUEST_V1 request{};
    request.Size=sizeof(request);request.Version=AWDLWIN_ENCRYPTION_DISABLED_VERSION;
    request.ConfirmMagic=AWDLWIN_ENCRYPTION_DISABLED_CONFIRM_MAGIC;
    request.TargetIfIndex=index;request.TargetNetLuidValue=luid.Value;
    UnassociatedControl::Send sending(control);
    AWDLWIN_RAW_ACTION_RESULT_V1 result{};DWORD bytes=0;
    const auto ok=DeviceIoControl(device,IOCTL_AWDLWIN_EXPERIMENT_ENCRYPTION_DISABLED,
        &request,sizeof(request),&result,sizeof(result),&bytes,nullptr);
    const auto error=ok?ERROR_SUCCESS:GetLastError();CloseHandle(device);
    sending.settled=ok&&bytes==sizeof(result)&&result.Size==sizeof(result)&&
        result.Version==AWDLWIN_RAW_ACTION_VERSION&&
        (!result.OidIssued||(result.FinalNdisStatus!=0x103u&&
          result.FinalNdisStatus!=ERROR_IO_PENDING&&result.OperationStatus!=0xc00000b5u));
    std::wcout<<L"vendor_encryption_disabled_request=1 ioctl_error="<<error
        <<L" oid_issued="<<result.OidIssued<<L" accepted="<<result.VendorRequestAccepted
        <<L" response_validated="<<result.ResponseValidated<<L" transaction="<<result.TransactionId<<L'\n';
    PrintHex(L"vendor_encryption_operation_status",result.OperationStatus);
    PrintHex(L"vendor_encryption_ndis_status",result.FinalNdisStatus);
    PrintHex(L"vendor_encryption_wdi_status",result.WdiHeaderStatus);
    return sending.settled&&result.OperationStatus==0&&result.VendorRequestAccepted&&result.ResponseValidated;
}

int RunPocRawAwdlAction(int argc,wchar_t** argv) {
    constexpr ULONG busyWaitMs=200;
    constexpr ULONG preIssueBusyRetryLimit=3;
    if(argc!=4) {
        std::wcerr<<L"usage: Tx10ubProbe.exe poc-awdl-raw-action <current-sta-channel> <awdl-body-hex>\n";
        return 2;
    }
    ULONG channel=0;
    UCHAR body[AWDLWIN_ACTION_BODY_CAPACITY]{};
    size_t bodyLength=0;
    if(!ParseUnsigned(argv[2],channel)||channel==0||channel>233||
       !ParseHex(argv[3],body,sizeof(body),bodyLength)||
       bodyLength<AWDLWIN_AF_RAW_BODY_MIN_LENGTH)return 2;
    const UCHAR awdlBodyPrefix[5]={0x7f,0x00,0x17,0xf2,0x08};
    if(std::memcmp(body,awdlBodyPrefix,sizeof(awdlBodyPrefix))!=0||body[5]!=0x10u||
       (body[6]!=0u&&body[6]!=3u))return 2;

    const auto before=ReadConnection(L"raw_before");
    if(!before.connected) {
        std::wcerr<<L"raw_action_requires_connected_current_channel; no OID issued\n";
        return 11;
    }
    if(before.channel!=channel) {
        std::wcerr<<L"raw_action_channel_mismatch; no OID issued\n";
        return 12;
    }
    NET_LUID luid{};
    NET_IFINDEX index=0;
    if(!ResolveTarget(luid,index)) {
        std::wcerr<<L"target_identity_mismatch; no OID issued\n";
        return 3;
    }
    MIB_IF_ROW2 current{};
    current.InterfaceLuid=luid;
    if(GetIfEntry2(&current)!=NO_ERROR||current.InterfaceIndex!=index||
       current.PhysicalAddressLength!=6||(current.PhysicalAddress[0]&1)!=0)return 3;
    AWDLWIN_AF_PARAMETERS parameters{};
    const UCHAR broadcast[6]={0xff,0xff,0xff,0xff,0xff,0xff};
    std::copy_n(broadcast,6,parameters.Peer);
    parameters.PostAckDwellMs=0;
    parameters.BodyLength=static_cast<USHORT>(bodyLength);
    std::copy_n(body,bodyLength,parameters.Body);
    UCHAR preview[AWDLWIN_AF_RAW_BODY_OFFSET+AWDLWIN_AF_MAX_BODY]{};
    size_t previewLength=0;
    if(!AwdlWinAfSerializeRawFrame(&parameters,current.PhysicalAddress,
            preview,sizeof(preview),&previewLength))return 2;

    GUID guid{};
    HANDLE wlan=nullptr;
    DWORD wlanVersion=0;
    if(FAILED(CLSIDFromString(kGuidText,&guid))||
       WlanOpenHandle(2,nullptr,&wlanVersion,&wlan)!=ERROR_SUCCESS)return 4;
    HANDLE device=CreateFileW(kDevice,GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,0,nullptr);
    if(device==INVALID_HANDLE_VALUE) {
        std::wcerr<<L"device_open_error="<<GetLastError()<<L'\n';
        WlanCloseHandle(wlan,nullptr);
        return 4;
    }

    AWDLWIN_RAW_ACTION_REQUEST_V1 request{};
    request.Size=sizeof(request);
    request.Version=AWDLWIN_RAW_ACTION_VERSION;
    request.ConfirmMagic=AWDLWIN_RAW_ACTION_CONFIRM_MAGIC;
    request.TargetIfIndex=index;
    request.TargetNetLuidValue=luid.Value;
    request.ExpectedChannel=channel;
    request.BodyLength=static_cast<ULONG>(bodyLength);
    std::copy_n(body,bodyLength,request.Body);

    std::wcout<<L"raw_action_oid=0x"<<std::hex<<AWDLWIN_AF_RAW_INNER_OID<<std::dec
        <<L"\nraw_action_port_id=0\n"
        L"raw_action_delivery=ihv_method\nrate_500kbps_units=12\n"
        L"destination_mac=ffffffffffff\naddress3_awdl=002500ff9473\n"
        L"post_ack_dwell_ms=0\nchannel_switch_requested=0\n"
        L"expected_sta_channel="<<channel<<L"\nsource_mac=";
    PrintBytes(current.PhysicalAddress,6);
    std::wcout<<L"\npre_issue_busy_wait_ms="<<busyWaitMs
        <<L" pre_issue_busy_retry_limit="<<preIssueBusyRetryLimit<<L'\n';

    const auto call=IssueRawAction(device,wlan,guid,before.bssid,channel,request);
    const auto& result=call.result;
    CloseHandle(device);
    WlanCloseHandle(wlan,nullptr);
    std::wcout<<L"raw_action_attempts="<<call.attempts
        <<L"\nioctl_success="<<(call.ioctlOk?1:0)
        <<L"\nioctl_error="<<call.error
        <<L"\nbytes_returned="<<call.bytesReturned<<L'\n';
    if(call.bytesReturned==sizeof(result)&&result.Size==sizeof(result)) {
        std::wcout<<L"oid_issued="<<result.OidIssued
            <<L"\ncompletion_observed="<<result.CompletionObserved
            <<L"\nvendor_request_accepted="<<result.VendorRequestAccepted
            <<L"\nresponse_validated="<<result.ResponseValidated
            <<L"\nadmission_busy_reason="<<result.AdmissionBusyReason
            <<L"\noperation_status=0x"<<std::hex<<result.OperationStatus
            <<L"\nsubmit_ndis_status=0x"<<result.SubmitNdisStatus
            <<L"\nfinal_ndis_status=0x"<<result.FinalNdisStatus
            <<L"\nwdi_header_status=0x"<<result.WdiHeaderStatus<<std::dec
            <<L"\ntransaction_id="<<result.TransactionId
            <<L"\ninput_length="<<result.InputLength
            <<L"\nbytes_written="<<result.BytesWritten
            <<L"\nbytes_read="<<result.BytesRead
            <<L"\nbytes_needed="<<result.BytesNeeded<<L'\n';
    }
    const auto after=ReadConnection(L"raw_after");
    const bool same=after.connected&&after.channel==before.channel&&
        std::memcmp(after.bssid,before.bssid,sizeof(before.bssid))==0;
    std::wcout<<L"same_association_at_snapshots="<<same
        <<L"\ncontinuous_wifi_traffic=UNVERIFIED\non_air=UNVERIFIED\n"
        L"raw_action_rf_completion=UNVERIFIED\n";
    if(!same)return after.connected&&after.channel!=before.channel?12:11;
    return RawActionExitCode(call);
}

struct NativeRxObserver {
    HANDLE device = INVALID_HANDLE_VALUE;
    NET_LUID luid{};
    NET_IFINDEX index = 0;
    ULONGLONG cursor = 0;
    ULONGLONG statusCursor = 0;
    ULONG channel = 0;
    bool failed = false;
    HANDLE wlan = nullptr;
    GUID guid{};
    UCHAR bssid[6]{};
};

bool ControlNativeRx(NativeRxObserver& observer, ULONG operation) {
    AWDLWIN_NATIVE_RX_CONTROL_REQUEST_V1 input{};
    input.Size = sizeof(input);
    input.Version = AWDLWIN_NATIVE_RX_VERSION;
    input.Operation = operation;
    input.TargetIfIndex = observer.index;
    input.TargetNetLuidValue = observer.luid.Value;
    if (operation != AWDLWIN_NATIVE_RX_OPERATION_STATUS)
        input.ConfirmMagic = AWDLWIN_NATIVE_RX_CONFIRM_MAGIC;
    AWDLWIN_NATIVE_RX_CONTROL_RESULT_V1 output{};
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(observer.device, IOCTL_AWDLWIN_NATIVE_RX_CONTROL,
        &input, sizeof(input), &output, sizeof(output), &returned, nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    std::wcout << L"native_control_operation=" << operation
               << L"\nnative_control_ioctl_error=" << error << L'\n';
    if (returned != sizeof(output) || output.Size != sizeof(output) ||
        output.Version != AWDLWIN_NATIVE_RX_VERSION || output.Operation != operation ||
        output.TargetIfIndex != observer.index || output.TargetNetLuidValue != observer.luid.Value) {
        std::wcerr << L"native_control_result_invalid\n";
        return false;
    }
    std::wcout << L"native_filter_enabled=" << output.Enabled
               << L"\nnative_original_host_filter_known=" << output.OriginalHostFilterKnown
               << L"\nnative_filter_state=" << output.FilterState
               << L"\nnative_filter_generation=" << output.FilterGeneration
               << L"\nnative_pending_host_filter_sets=" << output.PendingHostFilterSets << L'\n';
    PrintHex(L"native_original_host_filter", output.OriginalHostFilter);
    PrintHex(L"native_effective_filter", output.EffectiveFilter);
    PrintHex(L"native_restore_mask", output.RestoreMask);
    PrintHex(L"native_last_ndis_status", output.LastNdisStatus);
    PrintHex(L"native_restore_status", output.RestoreStatus);
    if (!ok) return false;
    if (operation == AWDLWIN_NATIVE_RX_OPERATION_OBSERVE)
        return output.Enabled && output.FilterState == AWDLWIN_NATIVE_RX_FILTER_STATE_DISABLED;
    if (operation == AWDLWIN_NATIVE_RX_OPERATION_ENABLE)
        return output.Enabled && output.FilterState == AWDLWIN_NATIVE_RX_FILTER_STATE_ENABLED &&
            output.OriginalHostFilterKnown && output.LastNdisStatus == 0 &&
            (output.EffectiveFilter & 0x40000u) != 0;
    if (operation == AWDLWIN_NATIVE_RX_OPERATION_DISABLE)
        return !output.Enabled && output.FilterState == AWDLWIN_NATIVE_RX_FILTER_STATE_DISABLED &&
            output.RestoreStatus == 0 && output.PendingHostFilterSets == 0;
    return true;
}

bool ReadNativeRx(NativeRxObserver& observer, bool printCounters = false, bool printFrames = true) {
    if (observer.wlan != nullptr && (!StaStillAssociated(observer.wlan, observer.guid, observer.bssid) ||
        !StaUsesChannel(observer.wlan, observer.guid, observer.channel))) {
        std::wcerr << L"native_sta_association_changed\n";
        observer.failed = true;
        return false;
    }
    AWDLWIN_NATIVE_RX_SNAPSHOT_REQUEST_V1 input{};
    input.Size = sizeof(input);
    input.Version = AWDLWIN_NATIVE_RX_SNAPSHOT_VERSION;
    input.TargetIfIndex = observer.index;
    input.TargetNetLuidValue = observer.luid.Value;
    auto snapshot = std::make_unique<AWDLWIN_NATIVE_RX_SNAPSHOT_V2>();
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(observer.device, IOCTL_AWDLWIN_GET_NATIVE_RX_SNAPSHOT,
        &input, sizeof(input), snapshot.get(), sizeof(*snapshot), &returned, nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok || returned != sizeof(*snapshot) || snapshot->Size != sizeof(*snapshot) ||
        snapshot->Version != AWDLWIN_NATIVE_RX_SNAPSHOT_VERSION ||
        snapshot->Origin != AWDLWIN_NATIVE_RX_ORIGIN_NATIVE80211_MPDU ||
        snapshot->TargetNetLuidValue != observer.luid.Value || snapshot->TargetIfIndex != observer.index ||
        snapshot->Count > AWDLWIN_NATIVE_RX_RECORD_CAPACITY ||
        snapshot->PortCount > AWDLWIN_NATIVE_RX_PORT_CAPACITY ||
        snapshot->StatusCount > AWDLWIN_NATIVE_RX_STATUS_CAPACITY) {
        std::wcerr << L"native_snapshot_failed error=" << error << L'\n';
        observer.failed = true;
        return false;
    }
    ULONGLONG previous = 0;
    for (ULONG i = 0; i < snapshot->Count; ++i) {
        const auto& record = snapshot->Records[i];
        if (record.Sequence <= previous ||
            record.Origin != AWDLWIN_NATIVE_RX_ORIGIN_NATIVE80211_MPDU ||
            record.TargetNetLuidValue != observer.luid.Value || record.TargetIfIndex != observer.index ||
            record.FilterIfIndex != snapshot->FilterIfIndex ||
            record.CopiedLength > sizeof(record.RawBytes) || record.CopiedLength > record.OriginalLength ||
            record.FcsPresence > AWDLWIN_NATIVE_RX_FCS_PRESENT) {
            observer.failed = true;
            return false;
        }
        previous = record.Sequence;
        if (!printFrames) continue;
        if (record.Sequence <= observer.cursor) continue;
        if (record.Sequence != observer.cursor + 1) {
            std::wcerr << L"native_rx_history_gap after=" << observer.cursor
                       << L" next=" << record.Sequence << L'\n';
            observer.failed = true;
            return false;
        }
        observer.cursor = record.Sequence;
        std::wcout << L"native_frame sequence=" << record.Sequence
                   << L" monotonic_100ns=" << record.InterruptTime100ns
                   << L" source=native80211_nbl port=" << record.PortNumber
                   << L" original_length=" << record.OriginalLength
                   << L" copied_length=" << record.CopiedLength
                   << L" receive_flags=" << record.ReceiveFlags
                   << L" nbl_flags=" << record.NblFlags
                   << L" flags=" << record.Flags
                   << L" metadata_flags=" << record.Dot11MetadataFlags
                   << L" dot11_receive_flags=" << record.Dot11ReceiveFlags
                   << L" frequency_mhz=" << record.Dot11ChCenterFrequencyMHz
                   << L" fcs_presence=" << record.FcsPresence << L" frame_hex=";
        PrintBytes(record.RawBytes, record.CopiedLength);
        std::wcout << L'\n';
        // Decode only an explicitly known FCS boundary, never guess it from bytes.
        if (record.CopiedLength == record.OriginalLength &&
            record.FcsPresence != AWDLWIN_NATIVE_RX_FCS_UNKNOWN) {
            const auto parsed = awdlwin::wire::parse_action_mpdu(
                {record.RawBytes, record.CopiedLength}, record.FcsPresence == AWDLWIN_NATIVE_RX_FCS_PRESENT);
            if (parsed) {
                const auto body = awdlwin::wire::serialize_action_body(parsed.value().body);
                if (body) {
                    std::wcout << L"native_decoded sequence=" << record.Sequence
                               << L" subtype=" << static_cast<unsigned>(parsed.value().body.header.subtype)
                               << L" body_bytes=" << body.value().size() << L'\n';
                }
            }
        }
    }
    if (printFrames && previous < observer.cursor) {
        std::wcerr << L"native_rx_history_reset\n";
        observer.failed = true;
        return false;
    }
    if (!printFrames) observer.cursor = previous;
    ULONGLONG statusPrevious = 0;
    for (ULONG i = 0; i < snapshot->StatusCount; ++i) {
        const auto& record = snapshot->StatusRecords[i];
        if (record.Sequence <= statusPrevious || record.Sequence > snapshot->StatusSequence ||
            record.CopiedLength > sizeof(record.Payload) || record.CopiedLength > record.OriginalLength ||
            (record.StatusCode != AWDLWIN_NATIVE_RX_STATUS_MEDIA_SPECIFIC && record.CopiedLength != 0)) {
            observer.failed = true; return false;
        }
        statusPrevious = record.Sequence;
        if (!printFrames || record.Sequence <= observer.statusCursor) continue;
        if (record.Sequence != observer.statusCursor + 1) {
            std::wcerr << L"native_status_history_gap after=" << observer.statusCursor
                       << L" next=" << record.Sequence << L'\n';
            observer.failed = true; return false;
        }
        observer.statusCursor = record.Sequence;
        std::wcout << L"native_status sequence=" << record.Sequence
                   << L" monotonic_100ns=" << record.InterruptTime100ns
                   << L" source=ndis_status ndis_port_number=" << record.PortNumber
                   << L" status_code=" << record.StatusCode
                   << L" original_length=" << record.OriginalLength
                   << L" copied_length=" << record.CopiedLength << L" flags=" << record.Flags
                   << L" status_buffer_hex=";
        PrintBytes(record.Payload, record.CopiedLength); std::wcout << L'\n';
    }
    if ((printFrames && statusPrevious < observer.statusCursor) ||
        statusPrevious != snapshot->StatusSequence) {
        std::wcerr << L"native_status_history_reset_or_overwrite\n";
        observer.failed = true; return false;
    }
    if (!printFrames) observer.statusCursor = statusPrevious;
    if (printCounters) {
        for (ULONG i = 0; i < snapshot->PortCount; ++i) {
            const auto& port = snapshot->Ports[i];
            std::wcout << L"native_port ndis_port_number=" << port.PortNumber
                       << L" callbacks=" << port.CallbackCount << L" nbls=" << port.NetBufferListCount
                       << L" net_buffers=" << port.NetBufferCount << L" captured_mpdus=" << port.CapturedMpduCount << L'\n';
        }
        std::wcout << L"native_untracked_port_callbacks=" << snapshot->UntrackedPortCallbacks
                   << L"\nnative_status_overwrites=" << snapshot->StatusOverwriteCount << L'\n';
        std::wcout << L"native_callbacks=" << snapshot->CallbackCount
                   << L"\nnative_net_buffer_lists=" << snapshot->NetBufferListCount
                   << L"\nnative_net_buffers=" << snapshot->NetBufferCount
                   << L"\nnative_management_actions=" << snapshot->ManagementActionCount
                   << L"\nnative_awdl_candidates=" << snapshot->AwdlCandidateCount
                   << L"\nnative_copy_failures=" << snapshot->CopyFailureCount
                   << L"\nnative_oversize=" << snapshot->OversizeCount
                   << L"\nnative_invalid_metadata=" << snapshot->InvalidMetadataCount
                   << L"\nnative_loopback=" << snapshot->LoopbackCount
                   << L"\nnative_local_source=" << snapshot->LocalSourceCount
                   << L"\nnative_last_sequence=" << observer.cursor << L'\n';
    }
    return true;
}

class NativeRxLease {
public:
    NativeRxLease(NET_LUID luid, NET_IFINDEX index) {
        observer_.luid = luid;
        observer_.index = index;
    }
    NativeRxLease(const NativeRxLease&) = delete;
    NativeRxLease& operator=(const NativeRxLease&) = delete;
    ~NativeRxLease() { close(); }
    bool enable(bool passive = false) {
        const auto before = ReadConnection(L"native_before");
        DWORD version = 0;
        if (!before.connected || FAILED(CLSIDFromString(kGuidText, &observer_.guid)) ||
            WlanOpenHandle(2, nullptr, &version, &observer_.wlan) != ERROR_SUCCESS) return false;
        std::memcpy(observer_.bssid, before.bssid, sizeof(observer_.bssid));
        observer_.channel = before.channel;
        observer_.device = CreateFileW(kDevice, GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (observer_.device == INVALID_HANDLE_VALUE) {
            std::wcerr << L"native_device_open_error=" << GetLastError() << L'\n';
            return false;
        }
        armed_ = ControlNativeRx(observer_, passive
            ? AWDLWIN_NATIVE_RX_OPERATION_OBSERVE : AWDLWIN_NATIVE_RX_OPERATION_ENABLE);
        return armed_ && StaStillAssociated(observer_.wlan, observer_.guid, observer_.bssid);
    }
    bool close() {
        if (observer_.device != INVALID_HANDLE_VALUE) {
            if (armed_) restored_ = ControlNativeRx(observer_, AWDLWIN_NATIVE_RX_OPERATION_DISABLE);
            armed_ = false;
            CloseHandle(observer_.device);
            observer_.device = INVALID_HANDLE_VALUE;
        }
        if (observer_.wlan != nullptr) {
            WlanCloseHandle(observer_.wlan, nullptr);
            observer_.wlan = nullptr;
        }
        return restored_;
    }
    NativeRxObserver& observer() { return observer_; }
private:
    NativeRxObserver observer_{};
    bool armed_ = false;
    bool restored_ = true;
};

class RxCamLease {
    NET_LUID luid_{};
    NET_IFINDEX index_{};
    HANDLE device_=INVALID_HANDLE_VALUE;
    HANDLE wlan_=nullptr;
    GUID guid_{};
    UCHAR bssid_[6]{};
    ULONG channel_=0;
    ULONGLONG checked_=0;
    bool active_=false, restored_=true;
    bool control(ULONG operation) {
        AWDLWIN_RX_CAM_CONTROL_REQUEST request{};
        request.Size=sizeof(request);request.Version=AWDLWIN_RX_CAM_VERSION;
        request.Operation=operation;request.TargetIfIndex=index_;
        request.TargetNetLuidValue=luid_.Value;
        AWDLWIN_RX_CAM_CONTROL_RESULT result{};
        DWORD bytes=0;
        const BOOL ok=DeviceIoControl(device_,IOCTL_AWDLWIN_RX_CAM_CONTROL,
            &request,sizeof(request),&result,sizeof(result),&bytes,nullptr);
        if(!ok||bytes!=sizeof(result)||result.OperationStatus!=0) {
            if(bytes==sizeof(result)) {
                PrintHex(L"cam_operation_status",result.OperationStatus);
                PrintHex(L"cam_failure_stage",result.FailureStage);
                PrintHex(L"cam_failure_class",result.FailureClassification);
                PrintHex(L"cam_failure_ndis",result.FailureNdisStatus);
                PrintHex(L"cam_failure_wdi",result.FailureWdiStatus);
                PrintHex(L"cam_failure_value",result.FailureValue);
            }
            std::wcerr<<L"cam_control_error="<<(ok?ERROR_INVALID_DATA:GetLastError())
                <<L" operation="<<operation<<L'\n';return false;
        }
        if(operation!=AWDLWIN_RX_CAM_REFRESH) {
            PrintHex(L"cam_baseline",result.Baseline);
            PrintHex(L"cam_current",result.Current);
            PrintHex(L"cam_restored",result.Restored);
            PrintHex(L"cam_restore_status",result.RestoreStatus);
            std::wcout<<L"cam_active="<<result.Active<<L"\ncam_samples="<<result.Samples
                <<L"\ncam_reapplied="<<result.Reapplied<<L'\n';
        }
        return operation==AWDLWIN_RX_CAM_DISABLE
            ? !result.Active&&result.RestoreStatus==ERROR_SUCCESS
            : result.Active!=0;
    }
public:
    RxCamLease(NET_LUID luid,NET_IFINDEX index):luid_(luid),index_(index){}
    RxCamLease(const RxCamLease&)=delete;
    RxCamLease& operator=(const RxCamLease&)=delete;
    ~RxCamLease(){close();}
    bool enable() {
        const auto before=ReadConnection(L"cam_sta");
        DWORD version=0;
        if(!before.connected||FAILED(CLSIDFromString(kGuidText,&guid_))||
            WlanOpenHandle(2,nullptr,&version,&wlan_)!=ERROR_SUCCESS)return false;
        std::memcpy(bssid_,before.bssid,sizeof(bssid_));channel_=before.channel;
        device_=CreateFileW(kDevice,GENERIC_READ|GENERIC_WRITE,
            FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,0,nullptr);
        if(device_==INVALID_HANDLE_VALUE)return false;
        // Even a failed enable may have submitted a write: always close/restore.
        active_=true;
        return control(AWDLWIN_RX_CAM_ENABLE);
    }
    bool refresh() {
        if(!active_)return false;
        const auto now=GetTickCount64();
        if(now-checked_<200)return true;
        checked_=now;
        if(!StaStillAssociated(wlan_,guid_,bssid_)||!StaUsesChannel(wlan_,guid_,channel_)) {
            std::wcerr<<L"cam_sta_changed=1\n";return false;
        }
        return control(AWDLWIN_RX_CAM_REFRESH);
    }
    bool close() {
        if(device_!=INVALID_HANDLE_VALUE) {
            if(active_)restored_=control(AWDLWIN_RX_CAM_DISABLE);
            active_=false;
            CloseHandle(device_);device_=INVALID_HANDLE_VALUE;
        }
        if(wlan_!=nullptr){WlanCloseHandle(wlan_,nullptr);wlan_=nullptr;}
        return restored_;
    }
};

struct ExperimentalDiscovery {
    awdlwin::discovery::TransmitState state;
    awdlwin::wire::ActionSubtype subtype;
    bool bothSubtypes = false;
    bool allowOffChannel = false;
    const std::atomic_bool* coexistenceAssociationChanged = nullptr;
    std::function<bool()> scanIdleForSubmit;
    bool respondToLiveAction = false;
    bool predictSync = false;
    bool specificAction = false;
    bool trackUsbActions = false;
    bool verboseLog = true;
    bool receiving = false;
    bool interactiveSendBrowse = false;
    bool transferPeerSelected = false;
    UnassociatedControl* unassociated = nullptr;
    DirectIhvSession* directIhv = nullptr;
    NativeRxObserver* nativeObserver = nullptr; // Non-owning; caller holds the control handle.
    tx10ub::usb::DiscoveryReceiver* usbObserver = nullptr; // Same-thread owner in RunPocDiscovery.
};

awdlwin::wire::ActionSubtype DiscoverySubtypeForAccepted(
    const ExperimentalDiscovery& discovery, ULONG accepted) {
    if (!discovery.bothSubtypes) return discovery.subtype;
    // Advance only after acceptance. Busy retries regenerate the same subtype
    // from current receive state instead of starving one advertisement type.
    return accepted % 2 == 0 ? awdlwin::wire::ActionSubtype::psf
                             : awdlwin::wire::ActionSubtype::mif;
}

// A locally initialized self-master experiment, not an elected/synchronized
// Apple peer. The existing OWL builder remains the sole wire serializer.
ExperimentalDiscovery MakeExperimentalDiscovery(const UCHAR (&self)[6], ULONG channel,
    awdlwin::wire::ActionSubtype subtype, awdlwin::discovery::MonotonicTime started) {
    ExperimentalDiscovery result{};
    auto& s = result.state;
    std::copy_n(self, 6, s.self_address.begin());
    s.name = "AWDLWin";
    s.version = 0x34; // Pinned OWL state.c version; not the captured Apple's a0.
    s.device_class = 1; // Explicit experimental desktop profile, not hardware detection.
    s.psf_interval_tu = 110;
    s.sync = {started, 0, 16, 4};
    // Declared local experiment attributes; no captured remote election reuse.
    s.election = {s.self_address, s.self_address, 0, 80, 80, 0, 0};
    s.current_channel = {static_cast<std::uint8_t>(channel),
        static_cast<std::uint8_t>(channel == 6 ? 0x51 : 0x80)};
    s.master_channel = s.current_channel;
    s.channel_sequence.fill(s.current_channel);
    result.subtype = subtype;
    return result;
}

using ActiveMdnsRunner = std::function<int(HANDLE, const std::function<int()>&,ULONG&,tx10ub::airdrop::ReceiveMdns*)>;
int RunActiveMdns(NET_LUID luid, NET_IFINDEX index, const UCHAR (&self)[6],
                  HANDLE device, tx10ub::usb::DiscoveryReceiver& receiver,
                  const std::function<int()>& maintainAction,ULONG pairedRfLeadUs,
                  bool requireDataCompletionConfirmation,ULONG channel,UnassociatedControl* control,bool rawVendorData=false,
                  USHORT* nextDataSequence=nullptr,bool directAirDrop=false,USHORT initialSequence=0);

void PrintDiscoveryBody(const AWDLWIN_ACTION_REQUEST_V1& action,
    awdlwin::discovery::MonotonicTime generatedAt) {
    std::wcout << L"discovery_generated_us=" << generatedAt.time_since_epoch().count()
               << L"\ndiscovery_generated_subtype=" << static_cast<unsigned>(action.Body[6])
               << L"\ndiscovery_body_bytes=" << action.BodyLength << L"\ndiscovery_body_hex=";
    PrintBytes(action.Body, action.BodyLength);
    std::wcout << L'\n';
}

bool GenerateDiscoveryBody(const ExperimentalDiscovery& discovery,
    AWDLWIN_ACTION_REQUEST_V1& action, bool print, ULONG accepted = 0,
    awdlwin::discovery::MonotonicTime* generatedAt = nullptr,
    std::optional<awdlwin::discovery::MonotonicTime>* predictedUsbAt = nullptr,
    std::optional<awdlwin::discovery::MonotonicTime> generationTime = std::nullopt,
    bool waitForSync=true,bool* deferred=nullptr) {
    if(deferred)*deferred=false;
    auto now = generationTime.value_or(awdlwin::discovery::monotonic_now());
    const auto subtype = DiscoverySubtypeForAccepted(discovery, accepted);
    awdlwin::wire::Bytes body;
    if(discovery.usbObserver) {
        if(!discovery.usbObserver->generate(subtype,now,body,discovery.predictSync,predictedUsbAt,
                waitForSync,deferred))return false;
    } else {
        auto generated=awdlwin::discovery::generate_owl_discovery(discovery.state,subtype,now);
        if(!generated)return false;
        body=std::move(generated.value());
    }
    if(body.size()>sizeof(action.Body))return false;
    action.BodyLength = static_cast<USHORT>(body.size());
    std::memcpy(action.Body, body.data(), body.size());
    if (generatedAt) *generatedAt = now;
    if (print) PrintDiscoveryBody(action, now);
    return true;
}

bool IsActionResourceRejection(const AWDLWIN_ACTION_RESULT_V1& result) {
    return result.Size == sizeof(result) && result.Version == AWDLWIN_ACTION_VERSION &&
        result.Classification == AWDLWIN_ACTION_CLASS_FAILED_BEFORE_START &&
        result.M3Seen && !result.M4Seen && !result.AbortIssued && !result.AbortCompleted &&
        result.StopReason == AWDLWIN_ACTION_STOP_NONE && result.FinalNdisStatus == 0 &&
        result.WdiHeaderStatus == 0xc000009au;
}
#endif

// Repeat-send experiment (driver built with EnableRepeatExperiment=true).
// Sends <count> Actions in one process. The next send starts only after the
// IOCTL returned M3 success, and the driver admits it on the same condition.
// M4 is not awaited. Stops at the first failure or station association change.
int RunPocRepeat(int argc, wchar_t** argv
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
    , const ExperimentalDiscovery* discovery = nullptr,
    const ActiveMdnsRunner* activeMdnsRunner = nullptr
#endif
) {
    if (argc < 8 || argc > 11) {
        std::wcerr << L"usage: Tx10ubProbe.exe poc-repeat <port-id> <channel> <band-id> "
                      L"<peer-mac-hex> <count> <interval-ms> [send-timeout-ms=1000] "
                      L"[dwell-ms=100] [body-hex]\n";
        return 2;
    }
    USHORT portId = 0;
    ULONG channel = 0, band = 0, count = 0, intervalMs = 0, timeoutMs = 1000, dwellMs = 100;
    AWDLWIN_ACTION_REQUEST_V1 action{};
    size_t peerCount = 0, bodyCount = 0;
    const wchar_t* bodyHex = argc >= 11 ? argv[10] : L"040aa76c0200000600000102000101";
    if (!ParsePortId(argv[2], portId) || !ParseUnsigned(argv[3], channel) ||
        !ParseUnsigned(argv[4], band) ||
        !ParseHex(argv[5], action.Peer, sizeof(action.Peer), peerCount) || peerCount != 6 ||
#ifndef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
        (action.Peer[0] & 1) != 0 || // Ordinary builds refuse group addresses.
#endif
        !ParseUnsigned(argv[6], count) || !ParseUnsigned(argv[7], intervalMs) ||
        (argc >= 9 && !ParseUnsigned(argv[8], timeoutMs)) ||
        (argc >= 10 && !ParseUnsigned(argv[9], dwellMs)) ||
        !ParseHex(bodyHex, action.Body, sizeof(action.Body), bodyCount) || bodyCount < 2 ||
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
        (action.Body[0] != 0x04 && action.Body[0] != 0x7f) ||
#else
        action.Body[0] != 0x04 ||
#endif
        channel == 0 || count == 0 || count > 4000 ||
        intervalMs > 60000 || timeoutMs == 0 || timeoutMs > 1000 || dwellMs > 100) return 2;
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
    const UCHAR broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const UCHAR zero[6]{};
    const bool broadcastTarget = std::memcmp(action.Peer, broadcast, 6) == 0;
    if (std::memcmp(action.Peer, zero, 6) == 0 ||
        ((action.Peer[0] & 1) != 0 && !broadcastTarget) || channel > 233 ||
        band != (channel <= 14 ? 1u : 2u)) return 2;
#endif
    NET_LUID luid{};
    NET_IFINDEX index = 0;
    if (!ResolveTarget(luid, index)) {
        std::wcerr << L"target_identity_mismatch; no OID issued\n";
        return 3;
    }
    bool unassociatedMode=false;
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
    unassociatedMode=discovery&&discovery->unassociated;
#endif
    bool directIhvMode=false;
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
    directIhvMode=discovery&&discovery->directIhv;
    if(directIhvMode&&!discovery->specificAction)return 2;
#endif
    const auto before = ReadConnection(L"before");
    if (!before.connected && !unassociatedMode) {
        std::wcerr << L"poc_requires_connected_target; no OID issued\n";
        return 11;
    }
    // Raw-body experiments stay on-channel. Current-state Discovery may opt
    // into an explicit off-channel request; association must still be maintained.
    if (
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
        (!unassociatedMode && (!discovery || !discovery->allowOffChannel) && before.channel != channel) ||
        (!broadcastTarget && std::memcmp(before.bssid, action.Peer, 6) != 0)) {
#else
        before.channel != channel ||
        std::memcmp(before.bssid, action.Peer, 6) != 0) {
#endif
        std::wcout << L"repeat_stop_reason=sta_target_mismatch\n";
        return 12;
    }
    ULONGLONG eventSequence = 0;
    if (!directIhvMode&&ReadActionEvents(0, &eventSequence, false) != 0) return 4;
    GUID guid{};
    HANDLE wlan = nullptr;
    DWORD wlanVersion = 0;
    if (FAILED(CLSIDFromString(kGuidText, &guid)) ||
        WlanOpenHandle(2, nullptr, &wlanVersion, &wlan) != ERROR_SUCCESS) {
        std::wcerr << L"wlan_open_failed; no OID issued\n";
        return 4;
    }
    const auto stationAssociated=[&] {
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
        if(unassociatedMode)return discovery->unassociated->healthy();
#endif
        return StaStillAssociated(wlan,guid,before.bssid);
    };
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
    const auto stationOnChannel=[&] {
        if(unassociatedMode)return discovery->unassociated->healthy();
        return StaUsesChannel(wlan,guid,channel);
    };
#endif
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
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
    if(discovery&&discovery->respondToLiveAction)
        action.ExperimentMagic=AWDLWIN_ACTION_RESPONSE_EXPERIMENT_MAGIC;
#endif
    HANDLE device = INVALID_HANDLE_VALUE;
    if(!directIhvMode) {
        device = CreateFileW(kDevice, GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             OPEN_EXISTING, 0, nullptr);
        if (device == INVALID_HANDLE_VALUE) {
            std::wcerr << L"device_open_error=" << GetLastError() << L'\n';
            WlanCloseHandle(wlan, nullptr);
            return 4;
        }
    }
    LARGE_INTEGER frequency{}, start{};
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    std::wcout << L"repeat_count=" << count << L"\nrepeat_interval_ms=" << intervalMs
               << L"\nsend_timeout_ms=" << timeoutMs << L"\npost_ack_dwell_ms=" << dwellMs
               << L"\nrequested_channel=" << channel << L"\nbody_hex=";
    PrintBytes(action.Body, action.BodyLength);
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
    if(discovery&&discovery->specificAction) {
        if(directIhvMode)
            std::wcout<<L"\nrow=index,t_ms,direct_call_issued,vendor_request_accepted,response_validated,"
                L"win32_status,call_error,duration_us,exit\n"<<std::flush;
        else
            std::wcout<<L"\nrow=index,t_ms,oid_issued,vendor_request_accepted,response_validated,"
                L"operation_status,submit_ndis_status,final_ndis_status,wdi_header_status,"
                L"admission_busy_reason,bytes_written,bytes_read,bytes_needed,ioctl_error,ioctl_us,exit\n"<<std::flush;
    }
    else
#endif
        std::wcout << L"\nrow=index,t_ms,transaction_id,classification,m3_seen,m4_seen,"
                      L"final_ndis,wdi_status,ioctl_error,ioctl_us,exit\n" << std::flush;
    ULONG accepted = 0;
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
    constexpr ULONG resourceWaitMs = 200;
    const ULONG resourceRejectionLimit = discovery && discovery->coexistenceAssociationChanged ? 0 : 32;
    constexpr ULONG peerWindowWaitMs = 2000;
    constexpr ULONG peerWindowMissLimit = 4;
    ULONG resourceRejections = 0;
    ULONG consecutiveResourceRejections = 0;
    ULONG consecutivePeerWindowMisses = 0;
    ULONG psfAccepted = 0, mifAccepted = 0;
    const bool ndiscapRx = discovery && discovery->usbObserver && discovery->usbObserver->uses_ndiscap();
    const bool continuousReceiver = discovery && discovery->usbObserver;
    std::wcout << L"resource_wait_ms=" << resourceWaitMs
               << L"\nresource_rejection_limit=" << resourceRejectionLimit
               << L"\npeer_window_wait_ms=" << peerWindowWaitMs
               << L"\npeer_window_miss_limit=" << peerWindowMissLimit << L'\n';
    if(continuousReceiver)std::wcout<<L"resource_limit_scope=consecutive_refusals\n";
    // NdisCap receive handles discovery and Action advertisements in the same
    // owner loop, so the startup burst cannot delay installing the responder.
    const bool receiveHandlesStartup = ndiscapRx && activeMdnsRunner && discovery->receiving;
    std::optional<tx10ub::airdrop::ReceiveMdns> receiveService;
    if (discovery && discovery->receiving) receiveService.emplace(discovery->state.self_address);
    auto* actionService = receiveHandlesStartup && directIhvMode ? &*receiveService : nullptr;
#endif
    double minUs = 1e18, maxUs = 0, sumUs = 0;
    int exitCode = 0;
    const wchar_t* stopReason = L"none";
    ULONG measuredAccepted = 0;
    ULONG attemptIndex = 0;
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
    ULONG browseAccepted = 0;
    bool alignedMifAccepted=false;
    bool rawPendingAction=false,rawPendingActionIsMif=false,rawMifUsbOutObserved=false;
    enum class AttemptResult { accepted, resource_busy, deferred, peer_window_miss, failed };
    ULONGLONG lastAcceptedAt = GetTickCount64();
    const auto attemptAction = [&](ULONG sequenceAccepted,bool waitForWindow=true) -> AttemptResult {
        AWDLWIN_ACTION_RESULT_V1 result{};
        DWORD bytesReturned = 0;
        LARGE_INTEGER t0{}, t1{};
        awdlwin::discovery::MonotonicTime generatedAt{};
        awdlwin::discovery::MonotonicTime responseObservation{};
        std::optional<awdlwin::discovery::MonotonicTime> predictedUsbAt;
        bool generationDeferred=false;
        if (discovery) {
            const bool specificAction=discovery->specificAction;
            if(discovery->usbObserver&&!discovery->usbObserver->poll()) {
                stopReason=ndiscapRx?L"ndiscap_receive_failed":L"usb_receive_failed";exitCode=4;return AttemptResult::failed;
            }
            if (discovery->nativeObserver && !ReadNativeRx(*discovery->nativeObserver)) {
                stopReason = L"native_capture_failed";
                exitCode = 4;
                return AttemptResult::failed;
            }
            if (!specificAction&&!stationAssociated()) {
                stopReason = L"sta_association_changed";
                exitCode = 11;
                return AttemptResult::failed;
            }
            if (!specificAction&&!discovery->allowOffChannel && !stationOnChannel()) {
                stopReason = L"sta_target_mismatch";
                exitCode = 12;
                return AttemptResult::failed;
            }
            if(!specificAction) {
                MIB_IF_ROW2 current{};
                current.InterfaceLuid = luid;
                if (GetIfEntry2(&current) != NO_ERROR || current.PhysicalAddressLength != 6 ||
                    std::memcmp(current.PhysicalAddress, discovery->state.self_address.data(), 6) != 0) {
                    stopReason = L"source_identity_changed";
                    exitCode = 3;
                    return AttemptResult::failed;
                }
            }
            // WLAN queries above can take several AWs. Drain newly arrived
            // Sync first, then serialize immediately before submission. No
            // WLAN query or body logging may age this timestamped body.
            if(discovery->usbObserver&&!discovery->usbObserver->poll()) {
                stopReason=ndiscapRx?L"ndiscap_receive_failed":L"usb_receive_failed";exitCode=4;return AttemptResult::failed;
            }
        }
        awdlwin::discovery::MonotonicTime submittedAt{};
        bool peerWindowAligned=false, peerWindowBootstrap=false;
        if(discovery) {
            if(discovery->specificAction) {
                if(!discovery->usbObserver) {
                    stopReason=L"specific_action_requires_receive";exitCode=2;
                    return AttemptResult::failed;
                }
                if(rawPendingAction) {
                    const auto ready=ndiscapRx?std::optional<bool>{true}:waitForWindow?
                        std::optional<bool>{discovery->usbObserver->await_action_out_fence()}:
                        discovery->usbObserver->action_out_ready();
                    if(!ready || (waitForWindow&&!*ready)) {
                        stopReason=L"action_out_unconfirmed";exitCode=4;
                        return AttemptResult::failed;
                    }
                    if(!*ready)return AttemptResult::deferred;
                    if(rawPendingActionIsMif&&!ndiscapRx)rawMifUsbOutObserved=true;
                    rawPendingAction=false;
                }
                ULONGLONG peerWindowDeadline=0;
                enum class PeerWindowCheck { matched, retry, deferred, expired, failed };
                const auto checkPeerActionWindow=[&](awdlwin::discovery::MonotonicTime expectedOut) {
                    if(discovery->usbObserver->peer_action_channel_window(expectedOut,channel))
                        return PeerWindowCheck::matched;
                    if(!waitForWindow)return PeerWindowCheck::deferred;
                    if(peerWindowDeadline==0)peerWindowDeadline=GetTickCount64()+peerWindowWaitMs;
                    if(GetTickCount64()>=peerWindowDeadline) {
                        std::wcout<<L"action_peer_window_wait_expired=1\n";
                        return PeerWindowCheck::expired;
                    }
                    if(!discovery->usbObserver->wait(1)) {
                        stopReason=ndiscapRx?L"ndiscap_receive_failed":L"usb_receive_failed";exitCode=4;
                        return PeerWindowCheck::failed;
                    }
                    return PeerWindowCheck::retry;
                };
                for(;;) {
                    peerWindowAligned=false;
                    peerWindowBootstrap=false;
                    if(!stationAssociated()) {
                        stopReason=L"sta_association_changed";exitCode=11;
                        return AttemptResult::failed;
                    }
                    if(!stationOnChannel()) {
                        stopReason=L"sta_target_mismatch";exitCode=12;
                        return AttemptResult::failed;
                    }
                    MIB_IF_ROW2 current{};
                    current.InterfaceLuid=luid;
                    if(GetIfEntry2(&current)!=NO_ERROR||current.PhysicalAddressLength!=6||
                       std::memcmp(current.PhysicalAddress,discovery->state.self_address.data(),6)!=0) {
                        stopReason=L"source_identity_changed";exitCode=3;
                        return AttemptResult::failed;
                    }
                    if(!discovery->usbObserver->poll()) {
                        stopReason=ndiscapRx?L"ndiscap_receive_failed":L"usb_receive_failed";exitCode=4;
                        return AttemptResult::failed;
                    }
                    const auto generationCandidate=awdlwin::discovery::monotonic_now();
                    const auto projected=discovery->predictSync?
                        discovery->usbObserver->predicted_action_out(generationCandidate):std::nullopt;
                    const auto candidateWindow=checkPeerActionWindow(
                        projected.value_or(generationCandidate));
                    if(candidateWindow!=PeerWindowCheck::matched) {
                        if(candidateWindow==PeerWindowCheck::deferred)return AttemptResult::deferred;
                        if(candidateWindow==PeerWindowCheck::expired)
                            return AttemptResult::peer_window_miss;
                        if(candidateWindow==PeerWindowCheck::failed)
                            return AttemptResult::failed;
                        continue;
                    }
                    peerWindowAligned=projected.has_value();
                    peerWindowBootstrap=!projected.has_value();
                    if(!GenerateDiscoveryBody(*discovery,action,false,sequenceAccepted,
                            &generatedAt,&predictedUsbAt,generationCandidate,waitForWindow,&generationDeferred)) {
                        if(generationDeferred)return AttemptResult::deferred;
                        stopReason=L"discovery_generation_failed";exitCode=2;
                        return AttemptResult::failed;
                    }
                    if(generatedAt!=generationCandidate) {
                        if(!waitForWindow)return AttemptResult::deferred;
                        if(peerWindowDeadline==0)peerWindowDeadline=GetTickCount64()+peerWindowWaitMs;
                        if(GetTickCount64()>=peerWindowDeadline) {
                            std::wcout<<L"action_peer_window_wait_expired=1\n";
                            return AttemptResult::peer_window_miss;
                        }
                        continue;
                    }
                    const auto generatedWindow=checkPeerActionWindow(
                        predictedUsbAt.value_or(generatedAt));
                    if(generatedWindow!=PeerWindowCheck::matched) {
                        if(generatedWindow==PeerWindowCheck::deferred)return AttemptResult::deferred;
                        peerWindowAligned=false;
                        peerWindowBootstrap=false;
                        if(generatedWindow==PeerWindowCheck::expired)
                            return AttemptResult::peer_window_miss;
                        if(generatedWindow==PeerWindowCheck::failed)
                            return AttemptResult::failed;
                        continue;
                    }
                    peerWindowAligned=predictedUsbAt.has_value();
                    peerWindowBootstrap=!predictedUsbAt.has_value();
                    if(discovery->trackUsbActions&&
                       !discovery->usbObserver->track_action(discovery->state.self_address,
                           std::span<const std::uint8_t>(action.Body,action.BodyLength),generatedAt,predictedUsbAt)) {
                        stopReason=L"usb_tx_tracking_unavailable";exitCode=4;
                        return AttemptResult::failed;
                    }
                    submittedAt=awdlwin::discovery::monotonic_now();
                    AWDLWIN_RAW_ACTION_REQUEST_V1 request{};
                    request.Size=sizeof(request);
                    request.Version=AWDLWIN_RAW_ACTION_VERSION;
                    request.ConfirmMagic=AWDLWIN_RAW_ACTION_CONFIRM_MAGIC;
                    request.TargetIfIndex=index;
                    request.TargetNetLuidValue=luid.Value;
                    request.ExpectedChannel=channel;
                    request.BodyLength=action.BodyLength;
                    std::copy_n(action.Body,action.BodyLength,request.Body);
                    QueryPerformanceCounter(&t0);
                    // A busy pre-issue refusal returns to the caller. It then
                    // waits and regenerates Sync from a fresh timestamp.
                    const auto call=IssueRawAction(device,wlan,guid,before.bssid,channel,request,false,false,
                        discovery->unassociated,discovery->directIhv,actionService);
                    QueryPerformanceCounter(&t1);
                    const double us=(t1.QuadPart-t0.QuadPart)*1e6/frequency.QuadPart;
                    const double tMs=(t0.QuadPart-start.QuadPart)*1e3/frequency.QuadPart;
                    const int code=RawActionExitCode(call);
                    const ULONG thisAttempt=attemptIndex++;
                    if(discovery->verboseLog||code!=0) {
                    PrintDiscoveryBody(action,generatedAt);
                    std::wcout<<L"discovery_generation_to_submit_us="<<(submittedAt-generatedAt).count()<<L'\n';
                    std::wcout<<L"sync_projection_active="<<predictedUsbAt.has_value();
                    if(predictedUsbAt)std::wcout<<L" predicted_usb_tx_us="<<predictedUsbAt->time_since_epoch().count()
                        <<L" projected_delay_us="<<(*predictedUsbAt-generatedAt).count();
                    std::wcout<<L'\n';
                    if(peerWindowAligned)std::wcout<<L"action_peer_window=matched\n";
                    else if(peerWindowBootstrap)std::wcout<<L"action_peer_window=bootstrap_current_channel_no_tx_estimate\n";
                    std::wcout<<L"row="<<thisAttempt<<L','<<std::fixed<<std::setprecision(1)<<tMs
                        <<L','<<call.result.OidIssued<<L','<<call.result.VendorRequestAccepted
                        <<L','<<call.result.ResponseValidated;
                    if(directIhvMode) {
                        std::wcout<<L",0x"<<std::hex<<call.result.OperationStatus<<std::dec
                            <<L','<<call.error<<L','<<std::setprecision(0)<<us<<L','<<code<<L'\n'<<std::flush;
                    } else {
                        std::wcout<<L",0x"<<std::hex<<call.result.OperationStatus<<L",0x"<<call.result.SubmitNdisStatus
                            <<L",0x"<<call.result.FinalNdisStatus<<L",0x"<<call.result.WdiHeaderStatus
                            <<std::dec<<L','<<call.result.AdmissionBusyReason<<L','<<call.result.BytesWritten
                            <<L','<<call.result.BytesRead<<L','<<call.result.BytesNeeded<<L','<<call.error
                            <<L','<<std::setprecision(0)<<us<<L','<<code<<L'\n'<<std::flush;
                    }
                    }
                    if(code!=0) {
                        if(discovery->trackUsbActions)discovery->usbObserver->cancel_action(
                            discovery->state.self_address,
                            std::span<const std::uint8_t>(action.Body,action.BodyLength));
                        if(!call.stationValid) {
                            if(!stationAssociated()) {
                                stopReason=L"sta_association_changed";exitCode=11;
                            } else {stopReason=L"sta_target_mismatch";exitCode=12;}
                            return AttemptResult::failed;
                        }
                        const bool retryableBusy=code==8&&call.result.OidIssued==0&&
                            (call.result.AdmissionBusyReason==AWDLWIN_RAW_ACTION_BUSY_SELF_OID||
                             call.result.AdmissionBusyReason==AWDLWIN_RAW_ACTION_BUSY_DATA_QUERY);
                        if(retryableBusy&&consecutiveResourceRejections<resourceRejectionLimit) {
                            ++resourceRejections;++consecutiveResourceRejections;
                            if(!stationAssociated()) {
                                stopReason=L"sta_association_changed";exitCode=11;
                                return AttemptResult::failed;
                            }
                            return AttemptResult::resource_busy;
                        }
                        stopReason=code==8?L"raw_action_preissue_busy":L"raw_action_rejected";
                        std::wcout<<L"repeat_stop_index="<<thisAttempt<<L'\n';
                        exitCode=code;
                        return AttemptResult::failed;
                    }
                    if(peerWindowAligned&&
                       DiscoverySubtypeForAccepted(*discovery,sequenceAccepted)==awdlwin::wire::ActionSubtype::mif)
                        alignedMifAccepted=true;
                    const auto acceptedSubtype=DiscoverySubtypeForAccepted(*discovery,sequenceAccepted);
                    if(actionService)actionService->action_submitted();
                    rawPendingAction=!ndiscapRx;
                    rawPendingActionIsMif=!ndiscapRx&&acceptedSubtype==awdlwin::wire::ActionSubtype::mif;
                    if(acceptedSubtype==awdlwin::wire::ActionSubtype::psf)++psfAccepted;else ++mifAccepted;
                    consecutiveResourceRejections=0;
                    ++measuredAccepted;sumUs+=us;
                    if(us<minUs)minUs=us;
                    if(us>maxUs)maxUs=us;
                    lastAcceptedAt=GetTickCount64();
                    if(!stationAssociated()) {
                        stopReason=L"sta_association_changed";exitCode=11;
                    }
                    return AttemptResult::accepted;
                }
            }
            constexpr ULONG responseContextAttemptLimit=32;
            ULONG responseContextRefreshes=0;
            ULONGLONG peerWindowDeadline=0;
            for(;;) {
                peerWindowAligned=false;
                peerWindowBootstrap=false;
                if(discovery->respondToLiveAction) {
                    if(!waitForWindow&&!discovery->usbObserver->try_response_observation(responseObservation))
                        return AttemptResult::deferred;
                    const auto tickNow=GetTickCount64();
                    const auto remaining=peerWindowDeadline==0?DWORD{2000}:
                        static_cast<DWORD>(peerWindowDeadline>tickNow?peerWindowDeadline-tickNow:0);
                    if(waitForWindow&&!discovery->usbObserver->await_response_observation(responseObservation,remaining)) {
                        if(peerWindowDeadline!=0) {
                            std::wcout<<L"action_peer_window_wait_expired=1\n";
                            return AttemptResult::peer_window_miss;
                        }
                        stopReason=L"live_response_context_unavailable";exitCode=4;return AttemptResult::failed;
                    }
                    if(peerWindowDeadline!=0&&GetTickCount64()>=peerWindowDeadline) {
                        std::wcout<<L"action_peer_window_wait_expired=1\n";
                        return AttemptResult::peer_window_miss;
                    }
                }
                const auto generationCandidate=awdlwin::discovery::monotonic_now();
                if(discovery->predictSync) {
                    const auto projected=discovery->usbObserver->predicted_action_out(generationCandidate);
                    if(projected) {
                        const auto decision=discovery->usbObserver->peer_action_channel_window(
                            responseObservation,*projected,channel);
                        if(!decision) {
                            if(!waitForWindow)return AttemptResult::deferred;
                            if(peerWindowDeadline==0)peerWindowDeadline=GetTickCount64()+peerWindowWaitMs;
                            if(GetTickCount64()>=peerWindowDeadline) {
                                std::wcout<<L"action_peer_window_wait_expired=1\n";
                                return AttemptResult::peer_window_miss;
                            }
                            if(!discovery->usbObserver->wait(1)) {
                                stopReason=ndiscapRx?L"ndiscap_receive_failed":L"usb_receive_failed";exitCode=4;return AttemptResult::failed;
                            }
                            continue;
                        }
                        peerWindowAligned=true;
                    } else {
                        // No same-session TX estimate yet: submit unaligned to
                        // seed the estimator without inventing a lead time.
                        peerWindowBootstrap=true;
                    }
                }
                if(!GenerateDiscoveryBody(*discovery,action,false,sequenceAccepted,
                        &generatedAt,&predictedUsbAt,generationCandidate,waitForWindow,&generationDeferred)) {
                    if(generationDeferred)return AttemptResult::deferred;
                    stopReason=L"discovery_generation_failed";
                    exitCode=2;
                    return AttemptResult::failed;
                }
                if(discovery->trackUsbActions&&
                   !discovery->usbObserver->track_action(discovery->state.self_address,
                       std::span<const std::uint8_t>(action.Body,action.BodyLength),generatedAt,predictedUsbAt)) {
                    stopReason=L"usb_tx_tracking_unavailable";exitCode=4;return AttemptResult::failed;
                }
                submittedAt=awdlwin::discovery::monotonic_now();
                if(discovery->predictSync) {
                    if(predictedUsbAt) {
                        const auto actualWindow=discovery->usbObserver->peer_action_channel_window(
                            responseObservation,*predictedUsbAt,channel);
                        if(actualWindow) {
                            peerWindowAligned=true;
                            peerWindowBootstrap=false;
                        } else {
                            peerWindowAligned=false;
                            peerWindowBootstrap=false;
                            if(discovery->trackUsbActions)discovery->usbObserver->cancel_action(
                                discovery->state.self_address,
                                std::span<const std::uint8_t>(action.Body,action.BodyLength));
                            if(!waitForWindow)return AttemptResult::deferred;
                            if(peerWindowDeadline==0)peerWindowDeadline=GetTickCount64()+peerWindowWaitMs;
                            if(GetTickCount64()>=peerWindowDeadline) {
                                std::wcout<<L"action_peer_window_wait_expired=1\n";
                                return AttemptResult::peer_window_miss;
                            }
                    if(!discovery->usbObserver->wait(1)) {
                        stopReason=ndiscapRx?L"ndiscap_receive_failed":L"usb_receive_failed";exitCode=4;return AttemptResult::failed;
                            }
                            continue;
                        }
                    } else {
                        peerWindowAligned=false;
                        peerWindowBootstrap=true;
                    }
                }
                if(!discovery->respondToLiveAction||
                   discovery->usbObserver->response_observation_current(responseObservation,submittedAt))break;

                if(discovery->trackUsbActions)discovery->usbObserver->cancel_action(
                    discovery->state.self_address,
                    std::span<const std::uint8_t>(action.Body,action.BodyLength));
                if(!waitForWindow)return AttemptResult::deferred;
                std::wcout<<L"live_response_context_refresh="<<(responseContextRefreshes+1)<<L'\n';
                if(responseContextRefreshes+1==responseContextAttemptLimit) {
                    stopReason=L"live_response_context_expired";exitCode=4;return AttemptResult::failed;
                }
                ++responseContextRefreshes;
                if(!discovery->usbObserver->wait(1)) {
                    stopReason=L"usb_receive_failed";exitCode=4;return AttemptResult::failed;
                }
            }
        }
        std::uint64_t requestUtcUs = 0;
        if (discovery && discovery->coexistenceAssociationChanged) {
            if (discovery->coexistenceAssociationChanged->load()) {
                stopReason = L"sta_association_changed"; exitCode = 11; return AttemptResult::failed;
            }
            if (discovery->scanIdleForSubmit && !discovery->scanIdleForSubmit()) {
                stopReason = L"scan_or_peer_changed"; exitCode = 11; return AttemptResult::failed;
            }
            requestUtcUs = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        }
        QueryPerformanceCounter(&t0);
        const BOOL ok = DeviceIoControl(device, IOCTL_AWDLWIN_EXPERIMENT_ACTION_FRAME,
                                        &action, sizeof(action), &result, sizeof(result),
                                        &bytesReturned, nullptr);
        const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        QueryPerformanceCounter(&t1);
        if (requestUtcUs) std::wcout << L"coexistence_request_utc_us=" << requestUtcUs << L'\n';
        if(discovery&&discovery->verboseLog) {
            PrintDiscoveryBody(action, generatedAt);
            std::wcout<<L"discovery_generation_to_submit_us="<<(submittedAt-generatedAt).count()<<L'\n';
            if(discovery->predictSync) {
                std::wcout<<L"sync_projection_active="<<predictedUsbAt.has_value();
                if(predictedUsbAt)std::wcout<<L" predicted_usb_tx_us="<<predictedUsbAt->time_since_epoch().count()
                    <<L" projected_delay_us="<<(*predictedUsbAt-generatedAt).count();
                std::wcout<<L'\n';
                if(peerWindowAligned)std::wcout<<L"action_peer_window=matched\n";
                else if(peerWindowBootstrap)std::wcout<<L"action_peer_window=bootstrap_unaligned_no_tx_estimate\n";
            }
            if(discovery->respondToLiveAction)
                std::wcout<<L"action_response_observation_us="<<responseObservation.time_since_epoch().count()
                    <<L" action_response_event_age_us="<<(submittedAt-responseObservation).count()<<L'\n';
        }
        const double us = (t1.QuadPart - t0.QuadPart) * 1e6 / frequency.QuadPart;
        const double tMs = (t0.QuadPart - start.QuadPart) * 1e3 / frequency.QuadPart;
        const int code = ActionExitCode(ok, bytesReturned, result);
        const ULONG thisAttempt = attemptIndex++;
        if(!discovery||discovery->verboseLog||code!=0)std::wcout << L"row=" << thisAttempt << L',' << std::fixed << std::setprecision(1) << tMs
                   << L',' << result.TransactionId << L',' << result.Classification
                   << L',' << result.M3Seen << L',' << result.M4Seen
                   << L",0x" << std::hex << result.FinalNdisStatus << L",0x"
                   << result.WdiHeaderStatus << std::dec << L',' << error << L','
                   << std::setprecision(0) << us << L',' << code << L'\n' << std::flush;
        if (code != 0) {
            if(discovery&&discovery->trackUsbActions)discovery->usbObserver->cancel_action(discovery->state.self_address,
                std::span<const std::uint8_t>(action.Body,action.BodyLength));
            if (code == 8 && IsActionResourceRejection(result) &&
                (continuousReceiver?consecutiveResourceRejections:resourceRejections) < resourceRejectionLimit) {
                ++resourceRejections;
                ++consecutiveResourceRejections;
                if (!stationAssociated()) {
                    stopReason = L"sta_association_changed";
                    exitCode = 11;
                    return AttemptResult::failed;
                }
                return AttemptResult::resource_busy;
            }
            stopReason = RepeatStopReason(code, error);
            std::wcout << L"repeat_stop_index=" << thisAttempt << L'\n';
            if (bytesReturned == sizeof(result)) PrintActionResult(result);
            if (code == 10) PrintLateM3(device, action, result.TransactionId);
            exitCode = code;
            return AttemptResult::failed;
        }
        if (discovery && discovery->verboseLog && discovery->predictSync && peerWindowAligned)
            std::wcout<<L"action_peer_window_outcome=accepted\n";
        if (discovery) {
            if(discovery->respondToLiveAction)
                discovery->usbObserver->mark_response_accepted(responseObservation);
            const auto acceptedSubtype=DiscoverySubtypeForAccepted(*discovery, sequenceAccepted);
            if(discovery->predictSync&&peerWindowAligned&&
               acceptedSubtype==awdlwin::wire::ActionSubtype::mif)alignedMifAccepted=true;
            if (acceptedSubtype == awdlwin::wire::ActionSubtype::psf)
                ++psfAccepted;
            else ++mifAccepted;
        }
        if(continuousReceiver)consecutiveResourceRejections=0;
        ++measuredAccepted;
        sumUs += us;
        if (us < minUs) minUs = us;
        if (us > maxUs) maxUs = us;
        lastAcceptedAt=GetTickCount64();
        if (!stationAssociated()) {
            stopReason = L"sta_association_changed";
            std::wcout << L"repeat_stop_index=" << thisAttempt << L'\n';
            exitCode = 11;
        }
        return AttemptResult::accepted;
    };
#endif

    while (accepted < count && exitCode == 0) {
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
        if (receiveHandlesStartup) break;
        const auto sent = attemptAction(accepted);
        if (sent == AttemptResult::resource_busy) {
            consecutivePeerWindowMisses=0;
            if(continuousReceiver) {
                if(!discovery->usbObserver->wait(resourceWaitMs)) {
                    stopReason=ndiscapRx?L"ndiscap_receive_failed":L"usb_receive_failed";exitCode=4;break;
                }
            } else Sleep(resourceWaitMs);
            continue;
        }
        if(sent==AttemptResult::peer_window_miss) {
            if(++consecutivePeerWindowMisses>=peerWindowMissLimit&&!(discovery&&discovery->receiving)) {
                if(ndiscapRx&&activeMdnsRunner&&discovery&&discovery->interactiveSendBrowse) {
                    // Keep polling for a peer within the mDNS browse budget.
                    // The maintenance loop still requires a valid Action window.
                    std::wcout<<L"airdrop_discovery_startup_window_deferred=1\n"<<std::flush;
                    break;
                }
                stopReason=L"peer_channel_window_unavailable";exitCode=17;break;
            }
            if(!discovery->usbObserver->wait(resourceWaitMs)) {
                stopReason=ndiscapRx?L"ndiscap_receive_failed":L"usb_receive_failed";exitCode=4;break;
            }
            continue;
        }
        if (sent == AttemptResult::failed) break;
        consecutivePeerWindowMisses=0;
#else
        AWDLWIN_ACTION_RESULT_V1 result{};
        DWORD bytesReturned = 0;
        LARGE_INTEGER t0{}, t1{};
        QueryPerformanceCounter(&t0);
        const BOOL ok = DeviceIoControl(device, IOCTL_AWDLWIN_EXPERIMENT_ACTION_FRAME,
                                        &action, sizeof(action), &result, sizeof(result),
                                        &bytesReturned, nullptr);
        const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        QueryPerformanceCounter(&t1);
        const double us = (t1.QuadPart - t0.QuadPart) * 1e6 / frequency.QuadPart;
        const double tMs = (t0.QuadPart - start.QuadPart) * 1e3 / frequency.QuadPart;
        const int code = ActionExitCode(ok, bytesReturned, result);
        std::wcout << L"row=" << attemptIndex++ << L',' << std::fixed << std::setprecision(1) << tMs
                   << L',' << result.TransactionId << L',' << result.Classification
                   << L',' << result.M3Seen << L',' << result.M4Seen
                   << L",0x" << std::hex << result.FinalNdisStatus << L",0x"
                   << result.WdiHeaderStatus << std::dec << L',' << error << L','
                   << std::setprecision(0) << us << L',' << code << L'\n' << std::flush;
        if(code!=0) {
            stopReason=RepeatStopReason(code,error);
            std::wcout<<L"repeat_stop_index="<<(attemptIndex-1)<<L'\n';
            if(bytesReturned==sizeof(result))PrintActionResult(result);
            if(code==10)PrintLateM3(device,action,result.TransactionId);
            exitCode=code;break;
        }
        ++measuredAccepted;sumUs+=us;if(us<minUs)minUs=us;if(us>maxUs)maxUs=us;
#endif
        ++accepted;
#ifndef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
        if(!stationAssociated()) {
            stopReason=L"sta_association_changed";
            std::wcout<<L"repeat_stop_index="<<(attemptIndex-1)<<L'\n';
            exitCode=11;break;
        }
#endif
        if(exitCode!=0)break;
        if (intervalMs != 0 && accepted < count) {
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
            if(continuousReceiver) {
                if(!discovery->usbObserver->wait(intervalMs)) {
                    stopReason=ndiscapRx?L"ndiscap_receive_failed":L"usb_receive_failed";exitCode=4;break;
                }
            } else
#endif
            Sleep(intervalMs);
        }
    }
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
    if(exitCode==0&&activeMdnsRunner&&discovery&&discovery->specificAction&&!ndiscapRx) {
        if(rawPendingAction) {
            if(!discovery->usbObserver->await_action_out_fence()) {
                stopReason=L"usb_action_out_unconfirmed";exitCode=4;
            } else {
                if(rawPendingActionIsMif)rawMifUsbOutObserved=true;
                rawPendingAction=false;
            }
        }
        if(exitCode==0&&!rawMifUsbOutObserved) {
            stopReason=L"mdns_requires_usb_mif_out";exitCode=17;
            std::wcerr<<L"mdns_requires_usb_mif_out=1\n";
        }
    }
    if(exitCode==0&&activeMdnsRunner&&discovery&&discovery->predictSync&&!alignedMifAccepted) {
        stopReason=L"mdns_requires_aligned_mif";exitCode=17;
        std::wcerr<<L"mdns_requires_aligned_mif=1\n";
    }
    if(exitCode==0&&activeMdnsRunner) {
        constexpr ULONG browseAdvertisementLimit=256;
        constexpr ULONGLONG minimumAdvertisementIntervalMs=113;
        const ULONGLONG advertisementIntervalMs=(std::max)(ULONGLONG{intervalMs},minimumAdvertisementIntervalMs);
        ULONGLONG nextBrowseAttemptAt=receiveHandlesStartup ? GetTickCount64() : lastAcceptedAt+advertisementIntervalMs;
        ULONGLONG busyRetryAt=0;
        ULONG consecutiveBrowsePeerWindowMisses=0;
        std::wcout<<L"browse_advertisement_limit="<<browseAdvertisementLimit
            <<L" browse_advertisement_interval_ms="<<advertisementIntervalMs<<L'\n';
        const std::function<int()> maintainAction=[&]() -> int {
            if(exitCode!=0)return exitCode;
            if(browseAccepted>=browseAdvertisementLimit&&
               !(discovery&&(discovery->receiving||discovery->transferPeerSelected))) {
                std::wcerr<<L"browse_advertisement_limit_reached=1\n";
                exitCode=16;stopReason=L"browse_advertisement_limit";return exitCode;
            }
            const auto now=GetTickCount64();
            const auto due=(std::max)(nextBrowseAttemptAt,busyRetryAt);
            if(now<due)return 0;
            const auto sent=attemptAction(accepted+browseAccepted,false);
            if(sent==AttemptResult::failed)return exitCode?exitCode:4;
            // Keep this subtype due. A later owner-loop iteration retries it;
            // window deferral is neither an admission failure nor an accepted TX.
            if(sent==AttemptResult::deferred)return 0;
            if(sent==AttemptResult::peer_window_miss) {
                if(++consecutiveBrowsePeerWindowMisses>=peerWindowMissLimit) {
                    stopReason=L"peer_channel_window_unavailable";exitCode=17;return exitCode;
                }
                nextBrowseAttemptAt=GetTickCount64()+resourceWaitMs;
                return 0;
            }
            if(sent==AttemptResult::resource_busy) {
                consecutiveBrowsePeerWindowMisses=0;
                busyRetryAt=GetTickCount64()+resourceWaitMs;
                nextBrowseAttemptAt=busyRetryAt;
                return 0;
            }
            consecutiveBrowsePeerWindowMisses=0;
            ++browseAccepted;
            busyRetryAt=0;
            nextBrowseAttemptAt=lastAcceptedAt+advertisementIntervalMs;
            return exitCode;
        };
        exitCode=(*activeMdnsRunner)(device,maintainAction,channel,receiveService ? &*receiveService : nullptr);
        if(discovery&&discovery->specificAction&&rawPendingAction&&!ndiscapRx) {
            if(!discovery->usbObserver->await_action_out_fence()) {
                stopReason=L"usb_action_out_unconfirmed";exitCode=4;
            } else {
                if(rawPendingActionIsMif)rawMifUsbOutObserved=true;
                rawPendingAction=false;
            }
        }
        std::wcout<<L"browse_advertisements_accepted="<<browseAccepted
            <<L"/"<<browseAdvertisementLimit<<L'\n';
    }
#endif
    if(device!=INVALID_HANDLE_VALUE)CloseHandle(device);
    WlanCloseHandle(wlan, nullptr);
    const auto after = ReadConnection(L"after");
        const bool sameAssociation = unassociatedMode ? !after.connected : after.connected &&
        std::memcmp(after.bssid, before.bssid, sizeof(before.bssid)) == 0;
    if (exitCode == 0 && !sameAssociation) stopReason = L"sta_association_changed";
    std::wcout << std::fixed << std::setprecision(0)
               << L"repeat_accepted=" << accepted << L'/' << count << L'\n'
               << L"ioctl_us_min=" << (measuredAccepted ? minUs : 0) << L'\n'
               << L"ioctl_us_avg=" << (measuredAccepted ? sumUs / measuredAccepted : 0) << L'\n'
               << L"ioctl_us_max=" << maxUs << L'\n'
               << L"same_association_after=" << sameAssociation << L'\n'
               << L"repeat_stop_reason=" << stopReason << L'\n';
    if(!directIhvMode)ReadActionEvents(eventSequence, nullptr, false);
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
    std::wcout << L"resource_rejections_waited=" << resourceRejections << L'\n';
    if (discovery) std::wcout << L"discovery_psf_accepted=" << psfAccepted
                             << L"\ndiscovery_mif_accepted=" << mifAccepted << L'\n';
#endif
    if (exitCode != 0) return exitCode;
    return sameAssociation ? 0 : 11;
}

#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
int ReadDataQueryState(bool requireReady=false) {
    NET_LUID luid{}; NET_IFINDEX index=0;
    if(!ResolveTarget(luid,index))return 3;
    const auto device=CreateFileW(kDevice,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,
        nullptr,OPEN_EXISTING,0,nullptr);
    if(device==INVALID_HANDLE_VALUE)return 4;
    AWDLWIN_DATA_QUERY_STATE_REQUEST_V1 input{};
    input.Size=sizeof(input);input.Version=1;input.TargetIfIndex=index;input.TargetNetLuidValue=luid.Value;
    AWDLWIN_DATA_QUERY_STATE_V1 state{};DWORD bytes=0;
    const auto ok=DeviceIoControl(device,IOCTL_AWDLWIN_GET_DATA_QUERY_STATE,&input,sizeof(input),
        &state,sizeof(state),&bytes,nullptr);
    const auto error=ok?ERROR_SUCCESS:GetLastError();CloseHandle(device);
    if(!ok||bytes!=sizeof(state)||state.Size!=sizeof(state)||state.Version!=1) {
        std::wcerr<<L"data_query_state_error="<<error<<L'\n';return 4;
    }
    std::wcout<<L"data_query_running="<<state.Running<<L" restart_ready="<<state.RestartReady
        <<L" pool_ready="<<state.PoolReady<<L" backfill_known="<<state.BackFillKnown
        <<L" data_backfill="<<state.DataBackFillSize<<L" context_backfill="<<state.ContextBackFillSize
        <<L" restarts="<<state.RestartCount<<L" preparation_reason="<<state.PreparationReason
        <<L" attribute_length="<<state.AttributeLength<<L" attribute_type="<<state.AttributeType
        <<L" attribute_revision="<<state.AttributeRevision<<L" attribute_size="<<state.AttributeSize
        <<L" advertised_data_backfill="<<state.AdvertisedDataBackFillSize
        <<L" advertised_context_backfill="<<state.AdvertisedContextBackFillSize<<L'\n';
    return requireReady&&(!state.Running||!state.RestartReady||!state.PoolReady||!state.BackFillKnown)?4:0;
}

int RunActiveMdns(NET_LUID luid,NET_IFINDEX index,const UCHAR (&self)[6],
                  HANDLE device,tx10ub::usb::DiscoveryReceiver& receiver,
                  const std::function<int()>& maintainAction,ULONG pairedRfLeadUs=0,
                  bool requireDataCompletionConfirmation=false,ULONG channel=44,UnassociatedControl* control=nullptr,bool rawVendorData,
                  USHORT* nextDataSequence,bool directAirDrop,USHORT initialSequence) {
    awdlwin::wire::MacAddress source{};std::copy_n(self,6,source.begin());
    std::wcout<<L"mdns_browse_kind=multicast_qm\nmdns_paired_rf_lead_us="<<pairedRfLeadUs<<L'\n';
    constexpr std::array<awdlwin::mdns::BrowseService,3> services{
        awdlwin::mdns::BrowseService::app_svc_pre_pair,
        awdlwin::mdns::BrowseService::application_service_pairing,
        awdlwin::mdns::BrowseService::airdrop};
    // Query cadence does not delimit reception or discard accumulated records.
    // One bounded browse spans pairing, BLE wake-up and AirDrop publication.
    constexpr auto queryInterval=std::chrono::seconds(3);
    const auto browseDeadline=awdlwin::discovery::monotonic_now()+std::chrono::seconds(30);
    struct QueryCleanup {
        tx10ub::usb::DiscoveryReceiver& receiver;
        ~QueryCleanup(){receiver.clear_browse_query();}
    } cleanup{receiver};
    bool browseRegistered=false;
    const bool ndisSendBrowse=directAirDrop&&receiver.uses_ndiscap();
    // File sending browses AirDrop directly, as OpenDrop does. The pairing
    // services belong to the diagnostic browse and are not send prerequisites.
    unsigned number=directAirDrop?2:0,airdropRound=0;
    USHORT sequence=initialSequence;
    while(number<services.size()&&awdlwin::discovery::monotonic_now()<browseDeadline) {
        constexpr USHORT port=5353,id=0;
        auto made=awdlwin::mdns::build_browse_query(source,port,id,sequence++,0,services[number]);
        if(!made||made.value().mpdu.empty()||made.value().mpdu.size()>AWDLWIN_DATA_QUERY_FRAME_CAPACITY)return 4;
        const auto& query=made.value();
        if(!browseRegistered) {
            if(!receiver.register_browse_query(query,browseDeadline))return 4;
            browseRegistered=true;
        }
        std::wcout<<L"mdns_query_service=";
        for(const auto ch:awdlwin::mdns::service_label(query.service))std::wcout<<static_cast<wchar_t>(ch);
        std::wcout<<L"._tcp.local\nmdns_query_round="<<(number==services.size()-1?airdropRound+1:1)<<L'\n';
        AWDLWIN_DATA_QUERY_REQUEST_V1 input{};
        input.Size=sizeof(input);input.Version=AWDLWIN_DATA_QUERY_VERSION;
        input.TargetIfIndex=index;input.TargetNetLuidValue=luid.Value;input.ConfirmMagic=AWDLWIN_DATA_QUERY_CONFIRM_MAGIC;
        input.FrameLength=static_cast<ULONG>(query.mpdu.size());std::copy(query.mpdu.begin(),query.mpdu.end(),input.Frame);
        AWDLWIN_RAW_DATA_REQUEST_V1 rawInput{};
        if(rawVendorData) {
            if(query.mpdu.size()>sizeof(rawInput.Frame))return 4;
            rawInput.Size=sizeof(rawInput);rawInput.Version=AWDLWIN_RAW_DATA_VERSION;
            rawInput.ConfirmMagic=AWDLWIN_RAW_DATA_CONFIRM_MAGIC;
            rawInput.TargetIfIndex=index;rawInput.TargetNetLuidValue=luid.Value;
            rawInput.ExpectedChannel=channel;rawInput.FrameLength=static_cast<ULONG>(query.mpdu.size());
            std::copy(query.mpdu.begin(),query.mpdu.end(),rawInput.Frame);
        }
        bool accepted=false,missedWindow=false;
        auto nextQueryAt=browseDeadline;
        for(unsigned attempt=0;attempt<3;++attempt) {
            using Time=awdlwin::discovery::MonotonicTime;
            using Bounds=std::optional<std::pair<Time,Time>>;
            struct Result {BOOL ok;DWORD error,bytes;AWDLWIN_DATA_QUERY_RESULT_V1 output;AWDLWIN_RAW_ACTION_RESULT_V1 vendor;};
            std::promise<Bounds> permit;
            auto permission=permit.get_future();
            std::promise<std::optional<Time>> started;
            auto submission=started.get_future();
            // Create the worker before selecting the window. It may submit
            // only within the selected center interval; reader/decoder events
            // remain owned by this thread and are not consumed before the
            // exact MPDU identity is registered below.
            auto pending=std::async(std::launch::async,[&] {
                Result r{};
                const auto bounds=permission.get();
                const auto now=awdlwin::discovery::monotonic_now();
                if(!bounds||now<bounds->first||now>bounds->second) {
                    started.set_value(std::nullopt);return r;
                }
                started.set_value(now);
                if(rawVendorData) {
                    if(auto* direct=gDirectIhvSession.load(std::memory_order_acquire)) {
                        const auto operation=direct->SendData(std::span<const UCHAR,6>(self),query.mpdu,control);
                        r.ok=operation.win32Status==ERROR_SUCCESS;
                        r.error=operation.win32Status;
                        r.bytes=sizeof(r.vendor);
                        CopyDirectResult(operation,r.vendor);
                        // These fields are consumed only by the shared query scheduler.
                        r.output.Size=sizeof(r.output);r.output.Version=AWDLWIN_DATA_QUERY_VERSION;
                        r.output.Submitted=operation.callIssued?1u:0u;
                        r.output.Completed=operation.transportQuarantined?0u:1u;
                        r.output.NdisStatus=DirectAccepted(operation)?0u:ERROR_GEN_FAILURE;
                        r.bytes=sizeof(r.output);
                    } else {
                        UnassociatedControl::Send sending(control);
                        r.ok=DeviceIoControl(device,IOCTL_AWDLWIN_EXPERIMENT_RAW_DATA,
                            &rawInput,sizeof(rawInput),&r.vendor,sizeof(r.vendor),&r.bytes,nullptr);
                        r.error=r.ok?ERROR_SUCCESS:GetLastError();
                        sending.settled=r.ok&&r.bytes==sizeof(r.vendor)&&r.vendor.Size==sizeof(r.vendor)&&
                            r.vendor.Version==AWDLWIN_RAW_ACTION_VERSION&&(!r.vendor.OidIssued||
                            (r.vendor.FinalNdisStatus!=0x103u&&r.vendor.FinalNdisStatus!=ERROR_IO_PENDING&&
                             r.vendor.OperationStatus!=0xc00000b5u));
                        // Common scheduling code consumes admission only; transport confirmation follows completion.
                        r.output.Size=sizeof(r.output);r.output.Version=AWDLWIN_DATA_QUERY_VERSION;
                        r.output.Submitted=r.vendor.OidIssued;
                        r.output.Completed=sending.settled;
                        r.output.NdisStatus=r.vendor.OperationStatus==0&&r.vendor.ResponseValidated&&
                            r.vendor.VendorRequestAccepted?0u:ERROR_GEN_FAILURE;
                        r.bytes=sizeof(r.output);
                    }
                } else {
                    UnassociatedControl::Send sending(control);
                    r.ok=DeviceIoControl(device,IOCTL_AWDLWIN_DATA_BROWSE_QUERY,
                        &input,sizeof(input),&r.output,sizeof(r.output),&r.bytes,nullptr);
                    r.error=r.ok?ERROR_SUCCESS:GetLastError();
                    sending.settled=r.ok&&r.bytes==sizeof(r.output)&&r.output.Size==sizeof(r.output)&&
                        r.output.Version==AWDLWIN_DATA_QUERY_VERSION&&(!r.output.Submitted||r.output.Completed);
                }
                return r;
            });
            struct PermitCleanup {
                std::promise<Bounds>& permit;
                bool released=false;
                void release(Bounds bounds) {permit.set_value(std::move(bounds));released=true;}
                ~PermitCleanup(){if(!released)try{permit.set_value(std::nullopt);}catch(...) {}}
            } permitCleanup{permit};
            const auto windowResult=receiver.await_multicast_window(channel,2000,maintainAction,
                std::chrono::microseconds{pairedRfLeadUs},false,ndisSendBrowse?std::optional{browseDeadline}:std::nullopt);
            if(ndisSendBrowse&&windowResult==WAIT_TIMEOUT) {
                permitCleanup.release(std::nullopt);pending.get();missedWindow=true;break;
            }
            if(windowResult!=0) {permitCleanup.release(std::nullopt);pending.get();return windowResult;}
            auto bounds=receiver.data_submit_bounds();
            if(awdlwin::discovery::monotonic_now()>=browseDeadline) {
                permitCleanup.release(std::nullopt);pending.get();return 15;
            }
            if(bounds)bounds->second=(std::min)(bounds->second,browseDeadline);
            permitCleanup.release(bounds);
            const auto submittedAt=submission.get();
            if(!submittedAt) {
                pending.get();
                missedWindow=true;
                std::wcout<<L"mdns_center_submission_missed=1\n";
                continue;
            }
            const bool tracked=receiver.track_data_query(query.mpdu,*submittedAt);
            if(!tracked) {
                pending.get();receiver.cancel_data_query();return 4;
            }
            // Receive ownership stays on this thread. Only the bounded send
            // runs on a worker, so queued receive events do not age past250ms.
            bool receiveOk=true;
            while(pending.wait_for(std::chrono::milliseconds(0))!=std::future_status::ready) {
                if(receiveOk)receiveOk=receiver.wait(10);else Sleep(10);
            }
            const auto r=pending.get();
            nextQueryAt=(std::min)(*submittedAt+queryInterval,browseDeadline);
            if(rawVendorData) {
                std::wcout<<L"mdns_raw_vendor=1 accepted="<<r.vendor.VendorRequestAccepted
                    <<L" response_validated="<<r.vendor.ResponseValidated<<L" transaction="<<r.vendor.TransactionId<<L'\n';
                PrintHex(L"mdns_raw_vendor_status",r.vendor.OperationStatus);
            }
            std::wcout<<L"mdns_data_query="<<number<<L" attempt="<<attempt<<L" ioctl_error="<<r.error
                <<L" submitted="<<r.output.Submitted<<(rawVendorData?L" vendor_request_finished=":L" completed=")<<r.output.Completed
                <<L" timed_out="<<r.output.TimedOut<<L" local_port="<<port<<L" dns_id="<<id
                <<L" frame_length="<<query.mpdu.size()
                <<L" submitted_steady_us="<<submittedAt->time_since_epoch().count()
                <<L" data_backfill="<<r.output.DataBackFillSize<<L" context_backfill="<<r.output.ContextBackFillSize<<L'\n';
            PrintHex(L"mdns_data_ndis_status",r.output.NdisStatus);
            if(!tracked||!receiveOk||!r.ok||r.bytes!=sizeof(r.output)||r.output.Size!=sizeof(r.output)||
               r.output.Version!=AWDLWIN_DATA_QUERY_VERSION||!r.output.Submitted||!r.output.Completed||r.output.TimedOut) {
                receiver.cancel_data_query();return 4;
            }
            if(r.output.NdisStatus==ERROR_SUCCESS){
                if(receiver.uses_ndiscap()) {
                    if(!receiver.confirm_driver_submission())return 4;
                    if(!receiver.poll())return 4;
                } else if(requireDataCompletionConfirmation) {
                    if(!receiver.await_data_query_out_fence())return 4;
                } else if(!receiver.poll())return 4;
                accepted=true;break;
            }
            receiver.cancel_data_query();
            if(r.output.NdisStatus!=0xc000009au||attempt==2)return 4;
            std::wcout<<L"mdns_resource_wait_ms=200\n";
            if(!receiver.wait(200))return 4;
        }
        if(!accepted) {
            if(!ndisSendBrowse||!missedWindow)return 4;
            // A local scheduling miss must not discard an announcement received
            // while waiting or terminate the user's first browse.
            nextQueryAt=awdlwin::discovery::monotonic_now();
            if(maintainAction)if(const auto error=maintainAction())return error;
        } else {
            std::wcout<<L"mdns_query_frame_hex=";PrintBytes(query.mpdu.data(),query.mpdu.size());std::wcout<<L'\n';
        }
        for(;;) {
            // The send picker and the browse must agree about live services.
            // An unsolicited announcement can arrive during radio preparation.
            const auto found=directAirDrop?receiver.airdrop_services():receiver.browse_services();
            const auto matchingEndpoints=std::count_if(found.endpoints.begin(),found.endpoints.end(),
                [&](const auto& endpoint){return endpoint.service==query.service;});
            if(matchingEndpoints!=0&&!found.truncated) {
                std::wcout<<events::DiscoveredEndpoints<<matchingEndpoints<<L'\n';
                for(const auto& endpoint:found.endpoints) {
                    if(endpoint.service!=query.service)continue;
                    std::wcout<<L"mdns_endpoint_service=";
                    for(const auto ch:awdlwin::mdns::service_label(endpoint.service))
                        std::wcout<<static_cast<wchar_t>(ch);
                    std::wcout<<L"._tcp.local\nmdns_endpoint_host=";
                    for(std::size_t i=0;i<endpoint.host.size();++i) {
                        if(i)std::wcout<<L'.';
                        for(const auto ch:endpoint.host[i])std::wcout<<static_cast<wchar_t>(static_cast<unsigned char>(ch));
                    }
                    std::wcout<<L"\nmdns_endpoint_port="<<endpoint.port<<L"\nmdns_endpoint_address_hex=";
                    PrintBytes(reinterpret_cast<const UCHAR*>(endpoint.address.data()),endpoint.address.size());
                    std::wcout<<L'\n';
                }
                // Pairing services are intermediate probes. Discovery succeeds
                // only after sending the AirDrop query and resolving its reply.
                if(query.service==awdlwin::mdns::BrowseService::airdrop) {
                    if(nextDataSequence)*nextDataSequence=sequence;
                    return 0;
                }
                break;
            }
            if(!receiver.browse_window_open()||awdlwin::discovery::monotonic_now()>=nextQueryAt)break;
            const auto maintenanceError=maintainAction?maintainAction():0;
            if(maintenanceError!=0)return maintenanceError;
            if(!receiver.wait(10))return 4;
        }
        if(query.service!=awdlwin::mdns::BrowseService::airdrop) {
            ++number;
        } else {
            ++airdropRound;
            if(awdlwin::discovery::monotonic_now()<browseDeadline)
                std::wcout<<L"mdns_airdrop_unresolved_retry="<<airdropRound<<L'\n';
        }
    }
    std::wcout<<events::DiscoveredEndpoints<<0<<L'\n';return 15;
}

int SendRawDataFrame(NET_LUID luid,NET_IFINDEX index,HANDLE device,
                     tx10ub::usb::DiscoveryReceiver& receiver,const std::function<int()>& maintainAction,
                     ULONG channel,UnassociatedControl* control,std::span<const UCHAR> mpdu,unsigned kind,
                     const std::function<bool()>& peerCurrent,
                     const std::function<void(awdlwin::discovery::MonotonicTime)>& submitted={},bool verboseLog=true,
                     bool guardedMulticastReply=false,
                     tx10ub::direct_ihv::DataRate rate=tx10ub::direct_ihv::DataRate::Mbps12,
                     bool fixedUpload=false,tx10ub::airdrop::UploadTiming* timing=nullptr,
                     std::optional<awdlwin::discovery::MonotonicTime> multicastDeadline=std::nullopt) {
    using Time=awdlwin::discovery::MonotonicTime;
    using Bounds=std::optional<std::pair<Time,Time>>;
    const auto windowDeadline=multicastDeadline.value_or(awdlwin::discovery::monotonic_now()+std::chrono::milliseconds{3000});
    for(;;) {
    AWDLWIN_RAW_DATA_REQUEST_V1 input{};
    input.Size=sizeof(input);input.Version=AWDLWIN_RAW_DATA_VERSION;
    input.ConfirmMagic=AWDLWIN_RAW_DATA_CONFIRM_MAGIC;input.TargetIfIndex=index;
    input.TargetNetLuidValue=luid.Value;input.ExpectedChannel=channel;
    if(mpdu.size()>sizeof(input.Frame)) {
        std::wcerr<<L"tcp_send_failed stage=frame_size exit=4 frame_bytes="<<mpdu.size()<<L" ioctl_called=0\n";
        return 4;
    }
    input.FrameLength=static_cast<ULONG>(mpdu.size());
    std::copy(mpdu.begin(),mpdu.end(),input.Frame);
    // TCP unicast uses the guarded peer channel window and the single receive owner.
    // Create the worker before granting the narrow submission interval.
    struct Result {
        BOOL ok{};bool ioctlCalled=false;DWORD error{},bytes{},completionError{};AWDLWIN_RAW_ACTION_RESULT_V1 output{};
        std::chrono::microseconds macRead{},ihvCall{};
    };
    struct Submission {std::optional<Time> at;Time checked;Bounds bounds;const wchar_t* rejection;};
    // Declared before the future: every worker joins before its event closes,
    // including exceptions and all rejected-permit/receive-failure exits.
    struct CompletionEvent {
        HANDLE handle=CreateEventW(nullptr,TRUE,FALSE,nullptr);
        ~CompletionEvent(){if(handle)CloseHandle(handle);}
    } completion;
    if(!completion.handle) {
        std::wcerr<<L"tcp_send_failed stage=completion_event_create exit=4 ioctl_called=0 event_error="
            <<GetLastError()<<L'\n';return 4;
    }
    std::promise<Bounds> permit;auto permission=permit.get_future();
    std::promise<Submission> started;auto submission=started.get_future();
    const auto launchStart=timing?awdlwin::discovery::monotonic_now():Time{};
    auto pending=std::async(std::launch::async,[&] {
        const auto issue=[&] {
        Result r;const auto bounds=permission.get();const auto now=awdlwin::discovery::monotonic_now();
        const auto rejection=!bounds?L"permit_missing":now<bounds->first?L"permit_early":
            now>bounds->second?L"permit_late":nullptr;
        if(rejection){started.set_value({std::nullopt,now,bounds,rejection});return r;}
        started.set_value({now,now,bounds,nullptr});
        if(auto* direct=gDirectIhvSession.load(std::memory_order_acquire)) {
            std::array<UCHAR,6> source{};
            if(mpdu.size()<16) {
                r.error=ERROR_INVALID_DATA;
                return r;
            }
            std::copy_n(mpdu.begin()+10,source.size(),source.begin());
            const auto operation=direct->SendData(std::span<const UCHAR,6>(source),mpdu,control,rate);
            r.macRead=operation.macReadTime;
            r.ihvCall=operation.ihvCallTime;
            r.ioctlCalled=operation.callIssued;
            r.ok=operation.win32Status==ERROR_SUCCESS;
            r.error=operation.win32Status;
            r.bytes=sizeof(r.output);
            CopyDirectResult(operation,r.output);
        } else {
            UnassociatedControl::Send sending(control);
            r.ioctlCalled=true;
            r.ok=DeviceIoControl(device,IOCTL_AWDLWIN_EXPERIMENT_RAW_DATA,&input,sizeof(input),
                &r.output,sizeof(r.output),&r.bytes,nullptr);r.error=r.ok?0:GetLastError();
            sending.settled=r.ok&&r.bytes==sizeof(r.output)&&r.output.Size==sizeof(r.output)&&
                r.output.Version==AWDLWIN_RAW_ACTION_VERSION&&(!r.output.OidIssued||
                (r.output.FinalNdisStatus!=0x103u&&r.output.FinalNdisStatus!=ERROR_IO_PENDING&&
                 r.output.OperationStatus!=0xc00000b5u));
        }
        return r;
        };
        Result r{};
        try { r=issue(); } catch(...) {
            r.error=ERROR_GEN_FAILURE;
            r.completionError=ERROR_GEN_FAILURE;
        }
        // The direct call/IOCTL has returned or been latched as uncertain.
        if(!SetEvent(completion.handle))r.completionError=GetLastError();
        return r;
    });
    if(timing) {
        ++timing->permitAttempts;
        timing->workerLaunch+=awdlwin::discovery::monotonic_now()-launchStart;
    }
    const auto joinWorker=[&] {
        auto r=pending.get();
        if(timing){timing->macRead+=r.macRead;timing->ihvCall+=r.ihvCall;}
        return r;
    };
    struct PermitCleanup {
        std::promise<Bounds>& p;bool released=false;
        ~PermitCleanup(){if(!released)try{p.set_value(std::nullopt);}catch(...) {}}
        void release(Bounds b){p.set_value(std::move(b));released=true;}
    } release{permit};
    // Report only after the worker has settled; console IO must not consume
    // the narrow permit before DeviceIoControl, or race the worker's result.
    const auto failed=[&](const wchar_t* stage,int code,const Result& r,const Submission& attempt) {
        std::wcerr<<L"tcp_send_failed stage="<<stage<<L" exit="<<code<<L" kind="<<kind
            <<L" frame_bytes="<<mpdu.size()<<L" awdl_sequence="
            <<(mpdu.size()>=36?int(mpdu[34]|(unsigned(mpdu[35])<<8)):-1)
            <<L" ioctl_called="<<r.ioctlCalled<<L" worker_steady_us="<<attempt.checked.time_since_epoch().count()
            <<L" permit_start_us="<<(attempt.bounds?attempt.bounds->first.time_since_epoch().count():-1)
            <<L" permit_end_us="<<(attempt.bounds?attempt.bounds->second.time_since_epoch().count():-1)
            <<L" worker_minus_end_us="<<(attempt.bounds?(attempt.checked-attempt.bounds->second).count():0)
            <<L" transaction="<<r.output.TransactionId<<L" ioctl_error="<<r.error
            <<L" event_error="<<r.completionError
            <<L" returned_bytes="<<r.bytes<<L" result_size="<<r.output.Size
            <<L" result_version="<<r.output.Version<<L" oid_issued="<<r.output.OidIssued
            <<L" operation_status="<<r.output.OperationStatus<<L" ndis_status="<<r.output.FinalNdisStatus
            <<L" response_validated="<<r.output.ResponseValidated
            <<L" vendor_accepted="<<r.output.VendorRequestAccepted<<L'\n';
        return code;
    };
    awdlwin::wire::MacAddress destination{};
    if(mpdu.size()>=10)std::copy_n(mpdu.begin()+4,6,destination.begin());
    const auto remaining=std::chrono::ceil<std::chrono::milliseconds>(
        windowDeadline-awdlwin::discovery::monotonic_now()).count();
    if(remaining<=0) {
        release.release(std::nullopt);const auto r=joinWorker();const auto attempt=submission.get();
        return failed(L"window_deadline",4,r,attempt);
    }
    const auto windowTimeout=static_cast<DWORD>((std::min)(std::int64_t{3000},remaining));
    const auto windowStart=timing?awdlwin::discovery::monotonic_now():Time{};
    const auto window=(mpdu.size()>=10&&(mpdu[4]&1)==0)?
        receiver.await_unicast_window(channel,windowTimeout,maintainAction,destination,fixedUpload):
        receiver.await_multicast_window(channel,windowTimeout,maintainAction,{},guardedMulticastReply,multicastDeadline);
    if(timing)timing->windowWait+=awdlwin::discovery::monotonic_now()-windowStart;
    if(window) {
        release.release(std::nullopt);const auto r=joinWorker();const auto attempt=submission.get();
        return failed(L"window_wait",window,r,attempt);
    }
    if(!peerCurrent()) {
        release.release(std::nullopt);const auto r=joinWorker();const auto attempt=submission.get();
        return failed(L"peer_current",4,r,attempt);
    }
    const auto permitAt=timing?awdlwin::discovery::monotonic_now():Time{};
    release.release(receiver.data_submit_bounds());
    const auto attempt=submission.get();
    if(timing)timing->permitWake+=attempt.checked-permitAt;
    if(!attempt.at){
        const auto r=joinWorker();
        if(!r.ioctlCalled&&attempt.rejection&&std::wstring_view(attempt.rejection)==L"permit_late"&&
           awdlwin::discovery::monotonic_now()<windowDeadline) {
            // The worker rejected admission before IOCTL/tracking. Keep this
            // exact TCP frame queued and select a fresh permit with the same
            // overall deadline; every worker has joined before the next try.
            if(verboseLog)std::wcout<<L"tcp_send_deferred reason=permit_late ioctl_called=0\n";
            continue;
        }
        return failed(attempt.rejection,4,r,attempt);
    }
    if(submitted)submitted(*attempt.at);
    if(!receiver.track_data_query(mpdu,*attempt.at)) {
        const auto r=joinWorker();receiver.cancel_data_query();return failed(L"track_query",4,r,attempt);
    }
    bool received=true;
    while(pending.wait_for(std::chrono::milliseconds(0))!=std::future_status::ready) {
        // One interruptible read wait, not a fixed-duration receive loop.
        // Keep the bounded timeout for control checks; either event wakes now.
        if(received)received=receiver.poll(10,completion.handle);else Sleep(10);
        if(WaitForSingleObject(completion.handle,0)==WAIT_OBJECT_0)break;
    }
    // The completion signal can precede std::async publishing its result.
    // get() still joins the worker before inspecting its output or restoring.
    const auto r=joinWorker();
    const auto* directSession=gDirectIhvSession.load(std::memory_order_acquire);
    const bool accepted=received&&!r.completionError&&r.ok&&r.bytes==sizeof(r.output)&&r.output.Size==sizeof(r.output)&&
        r.output.Version==AWDLWIN_RAW_ACTION_VERSION&&r.output.OidIssued&&
        r.output.OperationStatus==0&&(directSession||r.output.FinalNdisStatus==0)&&r.output.ResponseValidated&&
        r.output.VendorRequestAccepted;
    if(verboseLog) {
    if(directSession) {
        std::wcout<<L"tcp_raw_packet="<<kind<<L" accepted="<<accepted
            <<L" direct_call_issued="<<r.output.OidIssued<<L" win32_status="<<r.error<<L'\n';
        PrintHex(L"tcp_direct_status",r.output.OperationStatus);
    } else {
        std::wcout<<L"tcp_raw_packet="<<kind<<L" accepted="<<accepted
            <<L" transaction="<<r.output.TransactionId<<L" ioctl_error="<<r.error<<L'\n';
        PrintHex(L"tcp_raw_operation_status",r.output.OperationStatus);
        PrintHex(L"tcp_raw_final_ndis_status",r.output.FinalNdisStatus);
    }
    }
    if(!accepted) {
        const auto stage=!received?L"receive_wait":r.completionError?L"completion_event_signal":!r.ok?L"ioctl_failed":
            r.bytes!=sizeof(r.output)||r.output.Size!=sizeof(r.output)?L"result_size":
            r.output.Version!=AWDLWIN_RAW_ACTION_VERSION?L"result_version":
            !r.output.OidIssued?L"oid_not_issued":r.output.OperationStatus?L"operation_status":
            r.output.FinalNdisStatus?L"ndis_status":!r.output.ResponseValidated?L"response_unvalidated":L"vendor_rejected";
        receiver.cancel_data_query();return failed(stage,4,r,attempt);
    }
    const auto confirmationStart=timing?awdlwin::discovery::monotonic_now():Time{};
    bool submissionConfirmed=false;
    if(receiver.uses_ndiscap()) {
        submissionConfirmed=receiver.confirm_driver_submission();
        if(timing)timing->driverConfirmation+=awdlwin::discovery::monotonic_now()-confirmationStart;
        if(!submissionConfirmed)return failed(L"driver_submission_confirmation",4,r,attempt);
        if(!receiver.poll())return failed(L"ndiscap_receive",4,r,attempt);
        if(verboseLog)std::wcout<<L"tcp_driver_submission_confirmed="<<kind<<L'\n';
    } else {
        submissionConfirmed=receiver.await_data_query_out_fence();
        if(timing)timing->usbFence+=awdlwin::discovery::monotonic_now()-confirmationStart;
        if(!submissionConfirmed)return failed(L"usb_out_fence",4,r,attempt);
        if(verboseLog) {
            std::wcout<<L"tcp_usb_out_packet="<<kind<<L" frame_hex=";
            PrintBytes(mpdu.data(),mpdu.size());std::wcout<<L'\n';
        }
    }
    return 0;
    }
}

int RunTcpConnectCheck(NET_LUID luid,NET_IFINDEX index,const UCHAR (&self)[6],HANDLE device,
                      tx10ub::usb::DiscoveryReceiver& receiver,const std::function<int()>& maintainAction,
                      ULONG channel,UnassociatedControl* control,USHORT awdlSequence) {
    using Check=tx10ub::tcp::ConnectCheck;
    using Time=awdlwin::discovery::MonotonicTime;
    const auto snapshot=receiver.airdrop_services();
    std::vector<awdlwin::mdns::Endpoint> targets;
    for(const auto& e:snapshot.endpoints)if(e.service==awdlwin::mdns::BrowseService::airdrop)targets.push_back(e);
    if(snapshot.truncated||targets.size()!=1){std::wcerr<<L"tcp_target_not_unique=1\n";return 4;}
    awdlwin::wire::MacAddress source{};std::copy_n(self,6,source.begin());
    GUID random{};if(FAILED(CoCreateGuid(&random)))return 4;
    const auto localPort=static_cast<std::uint16_t>(49152u+(random.Data2&0x3fffu));
    if(!receiver.begin_tcp_connect(source,targets.front(),localPort,random.Data1))return 4;
    struct Cleanup {tx10ub::usb::DiscoveryReceiver& r;~Cleanup(){r.clear_tcp_connect();}} cleanup{receiver};
    std::wcout<<L"tcp_connect_check=1 tls_started=0 local_port="<<localPort
        <<L" remote_port="<<targets.front().port<<L'\n';
    const auto send=[&](Check::Packet kind)->int {
        const auto made=receiver.tcp_connect()->frame(kind,awdlSequence++);
        if(!made)return 4;
        return SendRawDataFrame(luid,index,device,receiver,maintainAction,channel,control,made.value(),
            static_cast<unsigned>(kind),[&]{return receiver.tcp_peer_current();},
            [&](Time at){receiver.mark_tcp_submitted(at);});
    };
    for(unsigned attempt=0;attempt<3&&!receiver.tcp_connect()->syn_ack_received();++attempt) {
        const auto sent=send(Check::Packet::syn);if(sent)return sent;
        std::wcout<<L"tcp_syn_attempt="<<attempt<<L'\n';
        const auto deadline=GetTickCount64()+2500;
        do {
            if(!receiver.poll()||!receiver.tcp_peer_current())return 4;
            if(receiver.tcp_connect()->refused()){std::wcout<<L"tcp_connection_refused=1\n";return 16;}
            if(receiver.tcp_connect()->syn_ack_received())break;
            if(maintainAction){const auto e=maintainAction();if(e)return e;}
            if(!receiver.wait(10))return 4;
        }while(GetTickCount64()<deadline);
    }
    if(!receiver.tcp_connect()->syn_ack_received()){std::wcout<<L"tcp_syn_ack_timeout=1\n";return 15;}
    const auto ack=send(Check::Packet::ack);
    if(ack){std::wcout<<L"tcp_close_reset_sent=0\n";return ack;}
    const auto reset=send(Check::Packet::reset);
    std::wcout<<L"tcp_syn_ack_received=1 "
        <<(receiver.uses_ndiscap()?L"tcp_ack_driver_submission_confirmed=1":L"tcp_ack_usb_observed=1")
        <<L" tcp_close_reset_"<<(receiver.uses_ndiscap()?L"driver_submission_confirmed=":L"sent=")
        <<(reset==0)<<L" tcp_stream_created=0 tls_started=0\n";
    return reset;
}

std::optional<awdlwin::mdns::Endpoint> RefreshAirDropTarget(
    const awdlwin::mdns::Endpoint& selected,const awdlwin::mdns::Snapshot& latest) {
    if(latest.truncated)return std::nullopt;
    for(const auto& current:latest.endpoints) {
        if(tx10ub::airdrop::same_target(current,selected))return current;
    }
    return std::nullopt;
}

int SelectAirDropTarget(tx10ub::usb::DiscoveryReceiver& receiver,const std::function<int()>& maintainAction,
                       UnassociatedControl& control,awdlwin::mdns::Endpoint& selected,
                       const std::function<int(tx10ub::airdrop::TargetSelection&,DWORD&)>& updateNames,
                       const std::function<int()>& refreshBrowse=nullptr,
                       const std::function<std::optional<unsigned>(unsigned)>& readCommittedTarget=nullptr,
                       bool* offerClientCertificate=nullptr) {
    tx10ub::airdrop::TargetSelection candidates;
    const auto selectedTarget = [&](unsigned round) {
        return readCommittedTarget ? readCommittedTarget(round) : control.selected_target(round);
    };
    const auto select = [&](unsigned id) {
        const auto current=candidates.select(id);
        if(!current)return false;
        selected=*current;
        if(offerClientCertificate)*offerClientCertificate=candidates.offer_client_certificate(id);
        std::wcout<<events::TargetSelected<<L'\n'<<std::flush;
        return true;
    };
    const auto selectionExpired = [&] {
        std::wcout << events::FailurePrefix.data() << events::Select << events::FailureReason.data()
                   << dropporter::target_files::SelectionExpired << events::FailureHttpStatus.data() << 0 << L'\n' << std::flush;
        return 4;
    };
    auto deadline=GetTickCount64()+60000;
    ULONGLONG nextUpdate=0;
    unsigned round=0,refreshGeneration=0;
    auto lastNameFrame=GetTickCount64();
    std::string previousRows;
    bool force=true;
    std::wcout<<events::TargetWaiting<<L'\n'<<std::flush;
    while(GetTickCount64()<deadline) {
        if(!control.healthy())return control.stopped()?16:4;
        if(!receiver.poll())return 4;
        if(round&&refreshBrowse&&GetTickCount64()>=nextUpdate&&control.refresh_requested(refreshGeneration+1)) {
            std::wcout<<events::StagePrefix.data()<<events::Discovery<<L'\n'<<std::flush;
            if(const auto error=refreshBrowse())return error;
            ++refreshGeneration;
            candidates.restart_lookups();
            deadline=GetTickCount64()+60000;
            force=true;
        }
        candidates.update(receiver.airdrop_services());
        // Product selections carry a session-local endpoint ID that survives name refreshes.
        if(round&&!force)if(const auto id=selectedTarget(round)) {
            if(select(*id))return 0;
            if (readCommittedTarget) return selectionExpired();
            force=true;nextUpdate=0;
        }
        if(GetTickCount64()>=nextUpdate) {
            const auto rows=candidates.rows();
            if(force||rows!=previousRows) {
                const auto header=refreshGeneration?std::string(dropporter::target_files::Refresh) + std::to_string(refreshGeneration)+"\n":std::string{};
                if(round >= dropporter::target_files::MaxRound ||!control.publish_targets(++round,header+rows))return 4;
                previousRows=rows;force=false;
                std::wcout<<events::TargetWaiting<<L'\n'<<std::flush;
            }
            nextUpdate=GetTickCount64()+250;
        }
        if(round)if(const auto id=selectedTarget(round)) {
            if(select(*id))return 0;
            if (readCommittedTarget) return selectionExpired();
            force=true;nextUpdate=0;
        }
        DWORD waitMs=10;
        if(const auto error=updateNames(candidates,waitMs)) {
            std::wcerr<<events::FailurePrefix.data()<<events::Select<<events::FailureReason.data()<<L"target_name_lookup_failed"
                     <<events::FailureHttpStatus.data()<<0<<L'\n'<<std::flush;
            return error;
        }
        if(waitMs==0){lastNameFrame=GetTickCount64();continue;}
        // A flight's immediate replies take precedence over advertisements.
        // Keep advertisements alive when a peer remains silent, including
        // peers whose entire sequence stays on the current channel.
        constexpr ULONGLONG replyQuietMs=100;
        if(GetTickCount64()-lastNameFrame>=replyQuietMs&&maintainAction){
            const auto error=maintainAction();if(error)return error;
        }
        if(!receiver.wait(waitMs))return 4;
    }
    std::wcout<<events::FailurePrefix.data()<<events::Select<<events::FailureReason.data()<<L"timeout"
                     <<events::FailureHttpStatus.data()<<0<<L'\n'<<std::flush;
    return 15;
}

class UploadDataRate {
    static constexpr int retryThreshold=4;
    std::optional<std::uint32_t> sequenceEnd_;
    std::uint16_t recentRetries_=0;
    bool fallbackActive_=false;
public:
    bool fallback_active() const { return fallbackActive_; }
    tx10ub::direct_ihv::DataRate next(std::uint32_t sequence,std::size_t payloadBytes) {
        using Rate=tx10ub::direct_ihv::DataRate;
        if(!payloadBytes)return Rate::Mbps12;
        if(fallbackActive_)return Rate::Mbps12;
        const bool repeated=sequenceEnd_&&static_cast<std::int32_t>(sequence-*sequenceEnd_)<0;
        const auto end=sequence+static_cast<std::uint32_t>(payloadBytes);
        if(!sequenceEnd_||static_cast<std::int32_t>(end-*sequenceEnd_)>0)sequenceEnd_=end;
        // Ignore isolated losses. If at least four of the last sixteen
        // payloads needed retransmission, keep the baseline rate for this upload.
        recentRetries_=static_cast<std::uint16_t>((recentRetries_<<1)|unsigned(repeated));
        fallbackActive_=std::popcount(recentRetries_)>=retryThreshold;
        return repeated?Rate::Mbps12:Rate::Mbps24;
    }
};

int RunAirDropAttempt(NET_LUID luid,NET_IFINDEX index,const UCHAR (&self)[6],HANDLE device,
                      tx10ub::usb::DiscoveryReceiver& receiver,const std::function<int()>& maintainAction,
                      ULONG channel,UnassociatedControl* control,USHORT& awdlSequence,
                      const tx10ub::airdrop::SendBatch* file,std::u16string_view senderName,bool verboseLog,
                      const awdlwin::mdns::Endpoint& selected,std::uint64_t attemptDeadline,
                      tx10ub::airdrop::TransferStatus& status,tx10ub::airdrop::AttemptFailure& failure,
                      bool offerCertificate) try {
    status.stage(events::WideConnect.data());
    const auto freshTarget=RefreshAirDropTarget(selected,receiver.airdrop_services());
    if(!freshTarget)return failure.record(L"peer_expired",4);
    std::vector<awdlwin::mdns::Endpoint> targets{*freshTarget};
    awdlwin::wire::MacAddress source{};std::copy_n(self,6,source.begin());
    // Generate credentials before creating a TCP PCB or sending a SYN.
    tx10ub::tls::Client tls(offerCertificate);
    struct TlsCleanup {
        tx10ub::tls::Client& tls;tx10ub::airdrop::AttemptFailure& failure;
        ~TlsCleanup(){if(!tls.close())failure.retryable=false;}
    } tlsCleanup{tls,failure};
    if(!tls.healthy()){PrintHex(L"tls_init_error",tls.error());return failure.record(L"tls_init",4);}
    GUID random{};if(FAILED(CoCreateGuid(&random)))return 4;
    auto localPort=static_cast<std::uint16_t>(49152u+(random.Data2&0x3fffu));
    std::string transferId;
    if(file) {
        wchar_t text[39]{};if(StringFromGUID2(random,text,39)!=39)return 4;
        for(unsigned i=1;i<37;++i) {
            auto c=static_cast<char>(text[i]);if(c>='a'&&c<='f')c=static_cast<char>(c-'a'+'A');
            transferId+=c;
        }
    }
    struct Cleanup {tx10ub::usb::DiscoveryReceiver& r;~Cleanup(){r.clear_tcp_stream();}} cleanup{receiver};
    if(!receiver.begin_tcp_stream(source,targets.front(),localPort))return 4;
    std::wcout<<L"airdrop_discover_started=1 local_port="<<localPort<<L" remote_port="<<targets.front().port
        <<L" tls_peer_identity_authenticated=0\n"<<std::flush;
    tx10ub::airdrop::Response response;
    std::string senderId;constexpr char digits[]="0123456789abcdef";
    for(auto byte:self){senderId+=digits[byte>>4];senderId+=digits[byte&15];}
    tx10ub::airdrop::Exchange exchange(file?std::span<const tx10ub::airdrop::File>(file->files):
        std::span<const tx10ub::airdrop::File>{},senderId,senderName,transferId);
    const auto fail=[&](const wchar_t* reason,int code,unsigned http=0,bool transient=false) {
        const bool discovery=exchange.stage()==tx10ub::airdrop::Exchange::Stage::discover&&!exchange.done()&&!exchange.needs_connection();
        return failure.record(reason,code,http,transient&&discovery&&(!response.status()||response.status()==200));
    };
    awdlwin::wire::Bytes pendingTls;
    awdlwin::wire::Bytes request;
    std::size_t requestOffset=0;
    std::size_t pendingOffset=0;
    bool announcedTcp=false,announcedTls=false,requested=false,requestLogged=false,closing=false,resetQueued=false;
    std::uint64_t queuedRequestBytes=0;
    const auto idleTimeout=std::chrono::seconds{file?600:90};
    auto lastProgress=awdlwin::discovery::monotonic_now();
    std::optional<awdlwin::discovery::MonotonicTime> uploadStarted;
    tx10ub::airdrop::UploadAckProgress uploadProgress;
    DWORD pollWaitMs=0;
    tx10ub::airdrop::UploadTiming uploadTiming;
    bool polledAfterSend=false;
    uploadTiming.driverSubmission=receiver.uses_ndiscap();
    UploadDataRate uploadRate;
    std::optional<tx10ub::direct_ihv::DataRate> reportedUploadRate;
    bool waitingUpload=false;
    ULONGLONG lastDataFrame=0;
    constexpr ULONGLONG replyQuietMs=100;
    while(true) {
        if(!polledAfterSend&&!receiver.poll(pollWaitMs))return fail(L"receive_failed",4,0,receiver.retryable_tcp_failure());
        polledAfterSend=false;
        pollWaitMs=0;
        const auto now=awdlwin::discovery::monotonic_now();
        const auto nowCount=now.time_since_epoch().count();
        if(exchange.stage()==tx10ub::airdrop::Exchange::Stage::discover&&!exchange.done()&&!exchange.needs_connection()&&
           static_cast<std::uint64_t>(nowCount)>=attemptDeadline)
            return fail(L"timeout",15,0,true);
        if(awdlwin::discovery::monotonic_now()-lastProgress>=idleTimeout) {
            std::wcerr<<L"airdrop_transport_idle_timeout=1\n";return fail(L"timeout",15);
        }
        if(!receiver.tcp_stream_peer_current())return fail(L"peer_expired",4);
        auto& stream=*receiver.tcp_stream();
        if(uploadStarted&&!closing)status.progress(uploadProgress.acknowledged(stream.acknowledged_bytes()),file->size,
            static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now-*uploadStarted).count()));
        if(stream.connected()&&!announcedTcp){
            announcedTcp=true;status.stage(events::WideTls.data());
            lastProgress=awdlwin::discovery::monotonic_now();
            std::wcout<<L"tcp_stream_connected=1\n";
        }
        const auto received=stream.read();
        if(!received.empty())lastProgress=awdlwin::discovery::monotonic_now();
        if(!received.empty()&&!closing&&!tls.closed()&&!tls.feed(received)) {
            PrintHex(L"tls_stream_error",tls.error());
            failure.certificateRejected=offerCertificate&&!requested&&tls.certificate_rejected();
            return fail(L"tls_error",4,0,failure.certificateRejected);
        }
        if(tls.ready()&&!requested) {
            status.stage(exchange.label());
            if(file&&exchange.stage()==tx10ub::airdrop::Exchange::Stage::upload) {
                uploadStarted=now;
                receiver.begin_upload_ack_delivery();
            }
            if(!announcedTls){announcedTls=true;std::wcout<<L"tls_handshake_complete=1 tls_version=1.2\n";}
            request=exchange.request(targets.front().address,targets.front().port);requestOffset=0;
            requested=true;requestLogged=false;queuedRequestBytes=0;lastProgress=awdlwin::discovery::monotonic_now();
        }
        const auto plaintext=tls.read();
        if(!plaintext.empty())lastProgress=awdlwin::discovery::monotonic_now();
        if(!plaintext.empty()&&!response.complete()&&!response.feed(plaintext)) {
            std::wcerr<<L"airdrop_http_response_invalid=1\n";return fail(L"invalid_response",4);
        }
        if((tls.closed()||stream.eof())&&!response.complete()) {
            // A TCP FIN without a TLS close_notify does not authenticate EOF framing.
            if(!tls.closed()||!response.finish()){std::wcerr<<L"airdrop_response_truncated=1\n";return fail(L"connection_ended",4,0,true);}
        }
        if(response.complete()&&!closing) {
            std::wcout<<events::ExchangePrefix<<exchange.label()<<events::ResponseComplete<<response.status()
                <<L" body_bytes="<<response.body().size()<<L'\n'<<std::flush;
            if(response.status()==200&&(requestOffset!=request.size()||
                (exchange.stage()==tx10ub::airdrop::Exchange::Stage::upload&&!exchange.upload_request_queued()))) {
                std::wcerr<<L"airdrop_premature_success_response=1\n";return fail(L"invalid_response",4);
            }
            if(response.status()!=200)fail(L"http_error",17,response.status());
            receiver.allow_discovery_retry(false); // No retry after any complete discovery reply.
            exchange.accept(response.status());
            if(exchange.done()||exchange.needs_connection()) {
                if(file&&exchange.done()&&response.status()==200)std::wcout<<events::UploadSucceeded<<L" file_bytes="<<file->size<<L'\n'<<std::flush;
                closing=true;
                if(!tls.closed()&&!tls.shutdown()){
                    PrintHex(L"tls_shutdown_error",tls.error());
                    if(!exchange.done()||response.status()!=200)return 4;
                }
            } else {
                response=tx10ub::airdrop::Response{};requested=false;request.clear();requestOffset=0;queuedRequestBytes=0;
            }
        }
        // Carry a short ciphertext tail into the next upload record so a TLS
        // boundary does not cost a separate guarded radio submission.
        constexpr std::size_t uploadRecordLimit=16*1024;
        const bool moreUpload=requested&&!closing&&exchange.stage()==tx10ub::airdrop::Exchange::Stage::upload&&
            !exchange.upload_request_queued();
        if(requested&&!closing&&(pendingTls.empty()||
           (moreUpload&&pendingTls.size()-pendingOffset<uploadRecordLimit))) {
            if(requestOffset<request.size()) {
                const auto size=(std::min)(std::size_t{4096},request.size()-requestOffset);
                if(!tls.write(std::span(request).subspan(requestOffset,size)))return fail(L"tls_error",4);
                requestOffset+=size;queuedRequestBytes+=size;lastProgress=awdlwin::discovery::monotonic_now();
            } else if(exchange.stage()==tx10ub::airdrop::Exchange::Stage::upload&&!exchange.upload_request_queued()) {
                const auto chunkLimit=(std::min)(tls.max_message_size(),uploadRecordLimit);
                if(!chunkLimit)return fail(L"tls_error",4);
                const auto chunk=exchange.next_upload_chunk(chunkLimit);
                if(chunk.empty()||!tls.write(chunk))return fail(L"tls_error",4);
                queuedRequestBytes+=chunk.size();lastProgress=awdlwin::discovery::monotonic_now();
            }
            const bool fullRequestQueued=requestOffset==request.size()&&
                (exchange.stage()!=tx10ub::airdrop::Exchange::Stage::upload||exchange.upload_request_queued());
            if(fullRequestQueued&&!requestLogged) {
                requestLogged=true;std::wcout<<events::ExchangePrefix<<exchange.label()
                    <<events::RequestQueued<<L" plaintext_bytes="<<queuedRequestBytes<<L'\n'<<std::flush;
            }
        }
        auto wire=tls.outbound();
        if(!wire.empty()) {
            uploadProgress.produced(wire.size(),exchange.file_bytes_read());
            if(pendingOffset){pendingTls.erase(pendingTls.begin(),pendingTls.begin()+pendingOffset);pendingOffset=0;}
            if(wire.size()>131072-pendingTls.size())return 4;
            pendingTls.insert(pendingTls.end(),wire.begin(),wire.end());
        }
        if(pendingOffset<pendingTls.size()&&stream.connected()) {
            const auto pending=std::span(pendingTls).subspan(pendingOffset);
            pendingOffset+=uploadStarted&&!closing?
                stream.write_upload(pending,!exchange.upload_request_queued()):stream.write(pending);
            if(pendingOffset==pendingTls.size()){pendingTls.clear();pendingOffset=0;}
        }
        if(!stream.healthy())return fail(L"connection_ended",4,0,stream.retryable_error());
        const bool maintainDuringUpload=uploadStarted&&!closing&&channel==44;
        // The DATA window wait defers Action work while the peer shares the
        // channel. Give due advertisements a turn between completed sends.
        if(maintainDuringUpload&&maintainAction) {
            const auto error=maintainAction();if(error)return error;
        }
        if(const auto* ip=stream.outbound()) {
            auto destination=targets.front().peer;
            if(ip->size()<40)return 4;
            if((*ip)[24]==0xff)destination={0x33,0x33,(*ip)[36],(*ip)[37],(*ip)[38],(*ip)[39]};
            const auto frame=awdlwin::wire::build_awdl_data_mpdu({destination,source,awdlSequence++,0x86dd,*ip},0);
            if(!frame)return 4;
            auto rate=tx10ub::direct_ihv::DataRate::Mbps12;
            if(uploadStarted&&!closing&&gDirectIhvSession.load(std::memory_order_acquire)) {
                if(const auto packet=tx10ub::tcp::parse(*ip);packet&&packet->payload_size) {
                    const bool wasFallback=uploadRate.fallback_active();
                    rate=uploadRate.next(packet->sequence,packet->payload_size);
                    if(!wasFallback&&uploadRate.fallback_active())
                        std::wcout<<L"airdrop_upload_rate_fallback_mbps=12 reason=clustered_tcp_retransmissions\n"<<std::flush;
                    if(!reportedUploadRate) {
                        std::wcout<<L"airdrop_upload_requested_rate_mbps="
                            <<(rate==tx10ub::direct_ihv::DataRate::Mbps24?24:12)<<L'\n'<<std::flush;
                        reportedUploadRate=rate;
                    }
                }
            }
            const bool uploading=uploadStarted.has_value()&&!closing;
            const auto sendStart=uploading?awdlwin::discovery::monotonic_now():awdlwin::discovery::MonotonicTime{};
            if(uploading)uploadTiming.begin_frame(sendStart);
            const auto sent=SendRawDataFrame(luid,index,device,receiver,maintainAction,channel,control,
                frame.value(),3,[&]{return receiver.tcp_stream_peer_current();},{},verboseLog,false,rate,
                uploading,uploading?&uploadTiming:nullptr);
            if(uploading)uploadTiming.sendTotal+=awdlwin::discovery::monotonic_now()-sendStart;
            // A failed admission or transport confirmation is never replayed, even during discovery.
            if(sent)return fail(L"send_failed",sent);
            status.sent(frame.value().size(),rate==tx10ub::direct_ihv::DataRate::Mbps24);
            stream.sent();lastDataFrame=GetTickCount64();
            if(uploading)uploadTiming.completed_frame(awdlwin::discovery::monotonic_now(),
                stream.upload_queue_state(pendingTls.size()-pendingOffset,!exchange.upload_request_queued()));
            // NdisCap polls after confirming submission. That poll already
            // delivered ACKs and checked the lease for the next iteration.
            polledAfterSend=uploading&&receiver.uses_ndiscap();
            continue;
        }
        if(uploadStarted&&!closing&&exchange.upload_request_queued()&&pendingTls.empty()&&!stream.write_pending()&&!waitingUpload) {
            waitingUpload=true;
            std::wcout<<events::UploadWaiting<<L'\n'<<std::flush;
        }
        if(closing&&pendingTls.empty()) {
            if(!resetQueued){stream.abort();resetQueued=true;continue;}
            if(exchange.needs_connection()) {
                status.stage(events::WideConnect.data());
                // OpenDrop discovers with one client, then creates another
                // client for Ask -> Upload. Drain/close the old TCP owner first.
                receiver.clear_tcp_stream();
                if(!tls.reset_connection()){PrintHex(L"tls_reconnect_error",tls.error());return fail(L"tls_error",4);}
                const auto refreshed=RefreshAirDropTarget(targets.front(),receiver.airdrop_services());
                if(!refreshed){std::wcerr<<L"airdrop_transfer_target_expired=1\n";return fail(L"peer_expired",4);}
                targets.front()=*refreshed;
                localPort=localPort==65535?std::uint16_t{49152}:static_cast<std::uint16_t>(localPort+1);
                if(!receiver.begin_tcp_stream(source,targets.front(),localPort))return 4;
                exchange.start_next_connection();
                response=tx10ub::airdrop::Response{};request.clear();requestOffset=0;
                queuedRequestBytes=0;
                pendingTls.clear();pendingOffset=0;
                uploadProgress={};
                announcedTcp=announcedTls=requested=requestLogged=closing=resetQueued=false;
                std::wcout<<L"airdrop_discover_connection_closed=1\nairdrop_transfer_connection_started=1 local_port="
                    <<localPort<<L" remote_port="<<targets.front().port<<L" tls_identity_reused=1\n"<<std::flush;
                continue;
            }
            if(!tls.close()){std::wcerr<<L"tls_temporary_user_key_delete_failed=1\n";return 4;}
            std::wcout<<events::TransportClosed<<L" tls_temporary_user_key_deleted=1\n"<<std::flush;
            return exchange.status()==200?0:17;
        }
        if(stream.eof()&&!response.complete())return 4;
        if(!maintainDuringUpload&&maintainAction&&(!lastDataFrame||GetTickCount64()-lastDataFrame>=replyQuietMs)) {
            const auto error=maintainAction();if(error)return error;
        }
        // The next iteration can form a full segment from the next TLS record.
        // Its normal nonblocking poll still services incoming ACKs and timers.
        if(moreUpload&&!exchange.upload_request_queued()&&pendingTls.size()-pendingOffset<uploadRecordLimit)continue;
        pollWaitMs=1; // Resume the send loop directly after the ACK wakes the reader.
    }
} catch(const std::exception& error) {
    // Return through the existing outer stop/restore sequence after local
    // TCP/TLS RAII cleanup, including file-stream read failures.
    std::cerr<<"airdrop_transport_exception="<<error.what()<<'\n';return failure.record(L"interrupted",4);
}

class AirDropNameLookups {
    struct Job {
        unsigned id,attempt;
        std::uint64_t started;
        unsigned openingFramesConfirmed{};
        bool namePublished=false;
        awdlwin::mdns::Endpoint endpoint;
        std::unique_ptr<tx10ub::tcp::Stream> stream;
        std::unique_ptr<tx10ub::airdrop::NameLookup> lookup;
    };
    NET_LUID luid_;NET_IFINDEX index_;HANDLE device_;
    tx10ub::usb::DiscoveryReceiver& receiver_;
    const std::function<int()>& maintain_;
    ULONG channel_;UnassociatedControl* control_;USHORT& sequence_;
    awdlwin::wire::MacAddress self_{};
    tx10ub::tls::Identity identity_;
    std::array<std::unique_ptr<Job>,4> jobs_;
    unsigned nextSend_=0;
    unsigned portOffset_=0;
    bool release(std::unique_ptr<Job>& job) {
        const bool ok=job->lookup->close();
        receiver_.detach_name_stream(*job->stream);job.reset();return ok;
    }
public:
    AirDropNameLookups(NET_LUID luid,NET_IFINDEX index,const UCHAR (&self)[6],HANDLE device,
                      tx10ub::usb::DiscoveryReceiver& receiver,const std::function<int()>& maintain,
                      ULONG channel,UnassociatedControl* control,USHORT& sequence)
        :luid_(luid),index_(index),device_(device),receiver_(receiver),maintain_(maintain),
         channel_(channel),control_(control),sequence_(sequence){
        std::copy_n(self,6,self_.begin());
        GUID random{};
        if(FAILED(CoCreateGuid(&random)))throw std::runtime_error("name_port_seed_failed");
        portOffset_=random.Data2&0x3fff;
    }
    ~AirDropNameLookups(){close();}
    bool close() {
        bool ok=true;for(auto& job:jobs_)if(job&&!release(job))ok=false;
        receiver_.cancel_data_query();return identity_.close()&&ok;
    }
    int pump(tx10ub::airdrop::TargetSelection& candidates,DWORD& waitMs) try {
        waitMs=10;
        using Lookup=tx10ub::airdrop::NameLookup;
        const auto now=static_cast<std::uint64_t>(awdlwin::discovery::monotonic_now().time_since_epoch().count());
        for(auto& job:jobs_)if(job) {
            const auto current=candidates.select(job->id);
            const bool fresh=current&&tx10ub::airdrop::same_target(*current,job->endpoint)&&receiver_.name_peer_current(*current);
            const auto state=fresh?job->lookup->step(now):Lookup::State::peer_failed;
            if(state==Lookup::State::fatal)return 4;
            if(fresh&&!job->namePublished&&!job->lookup->name().empty()) {
                candidates.set_receiver_name(job->id,job->lookup->name());job->namePublished=true;
                std::wcout<<L"airdrop_target_name_ready target="<<job->id
                    <<L" elapsed_ms="<<(now-job->started)/1000<<L'\n'<<std::flush;
            }
            if(state!=Lookup::State::active) {
                const bool certificateRejected=candidates.offer_client_certificate(job->id)&&job->lookup->certificate_rejected();
                const bool retry=fresh&&job->lookup->name().empty()&&(job->lookup->retryable()||certificateRejected)&&
                    candidates.retry_name_lookup(job->id,now,certificateRejected);
                std::wcout<<L"airdrop_target_name_result target="<<job->id<<L" attempt="<<job->attempt
                    <<L" elapsed_ms="<<(now-job->started)/1000
                    <<L" phase="<<job->lookup->phase()<<L" reason="<<(fresh?job->lookup->reason():"peer_expired")
                    <<L" http_status="<<job->lookup->http_status()<<L" tls_error="<<job->lookup->tls_error()
                    <<L" tcp_open_frames_confirmed="<<job->openingFramesConfirmed
                    <<L" retry="<<retry<<L'\n'<<std::flush;
                if(!retry)candidates.set_receiver_name(job->id,fresh?job->lookup->name():std::string{});
                if(!release(job))return 4;
            }
        }
        for(auto& slot:jobs_)if(!slot) {
            const auto pending=candidates.next_name_lookup(now);if(!pending)break;
            const auto attempt=candidates.mark_name_lookup_attempted(pending->first,now);
            if(!receiver_.name_peer_current(pending->second)){candidates.set_receiver_name(pending->first,{});continue;}
            auto job=std::make_unique<Job>();job->id=pending->first;job->attempt=attempt;job->started=now;job->endpoint=pending->second;
            std::wcout<<L"airdrop_target_name_started target="<<job->id<<L" attempt="<<attempt<<L'\n'<<std::flush;
            job->stream=std::make_unique<tx10ub::tcp::Stream>(self_,job->endpoint,
                static_cast<std::uint16_t>(49152+((portOffset_+(job->id-1)*4+attempt-1)&0x3fff)),now);
            job->lookup=std::make_unique<Lookup>(*job->stream,
                candidates.name_lookup_deadline(job->id),identity_,now,candidates.offer_client_certificate(job->id));
            if(!receiver_.attach_name_stream(*job->stream))return 4;
            slot=std::move(job);
        }
        // One frame at a time; an unavailable peer window never blocks the
        // other connections. Existing admission and transport confirmation still run.
        for(unsigned offset=0;offset<jobs_.size();++offset) {
            const auto at=(nextSend_+offset)%jobs_.size();auto& job=jobs_[at];
            if(!job)continue;
            if(receiver_.name_peer_on_channel(job->endpoint,channel_))waitMs=1;
            if(!receiver_.name_send_ready(job->endpoint,channel_))continue;
            const auto* ip=job->stream->outbound();if(!ip)continue;
            if(ip->size()<40)return 4;
            auto destination=job->endpoint.peer;
            if((*ip)[24]==0xff)destination={0x33,0x33,(*ip)[36],(*ip)[37],(*ip)[38],(*ip)[39]};
            const auto frame=awdlwin::wire::build_awdl_data_mpdu({destination,self_,sequence_++,0x86dd,*ip},0);
            if(!frame)return 4;
            const bool opening = !job->stream->connected();
            const auto sent=SendRawDataFrame(luid_,index_,device_,receiver_,maintain_,channel_,control_,
                frame.value(),3,[&]{return receiver_.name_peer_current(job->endpoint);},{},false);
            if(sent)return sent;
            if(opening)++job->openingFramesConfirmed;
            job->stream->sent();nextSend_=static_cast<unsigned>((at+1)%jobs_.size());waitMs=0;break;
        }
        return 0;
    }catch(const std::exception& error) {
        std::cerr<<"airdrop_target_name_lookup_exception="<<error.what()<<'\n';
        return 4; // Return through the normal stop/drain/restore owner.
    }
};

int RunAirDropDiscover(NET_LUID luid,NET_IFINDEX index,const UCHAR (&self)[6],HANDLE device,
                      tx10ub::usb::DiscoveryReceiver& receiver,const std::function<int()>& maintainAction,
                      ULONG channel,UnassociatedControl* control,USHORT awdlSequence,
                      const tx10ub::airdrop::SendBatch* file=nullptr,bool verboseLog=true,
                      const awdlwin::mdns::Endpoint* selected=nullptr,bool offerCertificate=true) {
    using namespace tx10ub::airdrop;
    TransferStatus status(true,receiver.uses_ndiscap());
    const auto snapshot=receiver.airdrop_services();
    std::vector<awdlwin::mdns::Endpoint> targets;
    for(const auto& e:snapshot.endpoints)if(e.service==awdlwin::mdns::BrowseService::airdrop)targets.push_back(e);
    if(selected) {
        const auto current=RefreshAirDropTarget(*selected,snapshot);
        if(!current)return status.fail(L"peer_expired",4);
        targets={*current};
    } else if(snapshot.truncated||targets.size()!=1)return status.fail(L"target_not_unique",4);
    std::u16string senderName;
    if (file) {
        const auto name = tx10ub::ReadLocalComputerName();
        if (name.empty()) return status.fail(L"computer_name_unavailable",4);
        senderName.assign(name.begin(), name.end());
    }
    const auto clock=[] {return static_cast<std::uint64_t>(awdlwin::discovery::monotonic_now().time_since_epoch().count());};
    DiscoveryRetry retry(clock());
    struct RetryCleanup {tx10ub::usb::DiscoveryReceiver& r;~RetryCleanup(){r.allow_discovery_retry(false);}} retryCleanup{receiver};
    for(;;) {
        receiver.allow_discovery_retry(true);
        AttemptFailure failure;
        const auto result=RunAirDropAttempt(luid,index,self,device,receiver,maintainAction,channel,control,
            awdlSequence,file,senderName,verboseLog,targets.front(),retry.begin_attempt(clock()),status,failure,
            offerCertificate);
        if(result==0){status.complete();return 0;}
        if(!retry.allowed(clock(),failure)||!receiver.retry_receive_healthy())
            return status.fail(failure.reason?failure.reason:L"interrupted",result,failure.httpStatus);
        if(failure.certificateRejected)offerCertificate=false;
        std::wcout<<L"airdrop_discovery_retry=1\n"<<std::flush;
        const auto resumeAt=(std::min)(retry.deadline(),clock()+500'000);
        while(clock()<resumeAt) {
            if(maintainAction){const auto error=maintainAction();if(error)return status.fail(L"interrupted",error);}
            if(!receiver.poll()||!receiver.wait(5))return status.fail(L"receive_failed",4);
        }
        if(clock()>=retry.deadline())return status.fail(L"timeout",15);
    }
}

struct RadioHandoffWaiting {
    RadioHandoffWaiting(bool receiving, bool wide) {
        const auto mode = receiving ? (wide ? events::HandoffReceiveWide : events::HandoffReceive) :
            (wide ? events::HandoffSendWide : events::HandoffSend);
        std::wcout << events::RadioHandoff << mode << L'\n' << std::flush;
    }
    ~RadioHandoffWaiting() { std::wcout << events::RadioHandoff << events::HandoffIdle << L'\n' << std::flush; }
};

bool ChangePeerDataChannel(tx10ub::usb::DiscoveryReceiver& receiver, UnassociatedControl& control,
    ULONG& dataChannel, ULONG& actionChannel, unsigned next, bool receiving) {
    if (!receiver.uses_ndiscap() && !receiver.await_action_out_fence()) return false;
    if (!control.request_channel(dataChannel, next, [&] { return receiver.wait(1); }, receiving)) return false;
    if (!receiver.set_fixed_channel(next)) return false;
    dataChannel = actionChannel = next;
    return true;
}

int PreparePeerDataChannel(tx10ub::usb::DiscoveryReceiver& receiver,UnassociatedControl& control,
                          ULONG& dataChannel,ULONG& actionChannel,const awdlwin::wire::MacAddress& peer,
                          const std::function<int()>& maintainAction,bool receiving);

int RunAirDropReceive(NET_LUID luid,NET_IFINDEX index,const UCHAR (&self)[6],HANDLE device,
    tx10ub::usb::DiscoveryReceiver& receiver,const std::function<int()>& maintainAction,
    ULONG& channel,ULONG& actionChannel,UnassociatedControl* control,USHORT& sequence,
    const std::filesystem::path& destination,const std::filesystem::path& applicationControl,DWORD fileOwnerPid,
    unsigned receiveAckRateMbps,tx10ub::airdrop::ReceiveMdns& advertisement,tx10ub::airdrop::ReceiveWorker& worker,
    const std::function<bool()>& startAdvertisement) try {
    awdlwin::wire::MacAddress source{};std::copy_n(self,6,source.begin());
    const auto clock=[](){return static_cast<std::uint64_t>(awdlwin::discovery::monotonic_now().time_since_epoch().count());};
    // Resolve from the actual executable, never from a remote request/CWD.
    wchar_t executable[32768]{};const auto length=GetModuleFileNameW(nullptr,executable,32768);
    if(!length||length>=32768)return 4;
    namespace helpers = dropporter::helper_files;
    const std::filesystem::path probePath(executable);
    auto workerPath = probePath.parent_path() / helpers::Receiver;
    if (_wcsicmp(probePath.filename().c_str(), helpers::DiagnosticProbe) == 0) {
        auto root = probePath.parent_path();
        workerPath = root / helpers::DiagnosticReceiver;
        for (unsigned depth = 0; depth < 8 && !std::filesystem::is_regular_file(workerPath); ++depth) {
            workerPath = root / helpers::DiagnosticReceiverPath;
            const auto parent = root.parent_path();
            if (parent == root) break;
            root = parent;
        }
    }
    if (!std::filesystem::is_regular_file(workerPath) ||
        !worker.start(workerPath, applicationControl, destination, fileOwnerPid)) return 4;
    const auto cancelPath=applicationControl/dropporter::session_markers::CancelFileName;
    tx10ub::tls::Identity identity;
    tx10ub::tcp::Listener listener(source,8771,clock());
    if(!listener.healthy())return 4;
    struct Connection {
        unsigned id=0;
        std::unique_ptr<tx10ub::tcp::Stream> tcp;
        std::unique_ptr<tx10ub::tls::Server> tls;
        awdlwin::wire::Bytes cipher,plain;
        ULONGLONG activity=0,closingAt=0;
        bool closeRequested=false,shutdown=false;
        bool reportedTls=false;
        std::uint64_t receivedPlain=0;
        std::optional<awdlwin::discovery::MonotonicTime> ackQueuedAt;
        std::uint64_t ackCount=0;
        std::chrono::microseconds ackReadyWait{}, ackSendTime{}, longestAck{};
    };
    std::array<Connection,tx10ub::receive_worker_protocol::MaxConnections> connections;
    const auto reportAckTiming=[](const Connection& c) {
        if (!c.ackCount) return;
        std::wcout<<L"airdrop_receive_ack_timing id="<<c.id
                  <<L" plaintext_bytes="<<c.receivedPlain
                  <<L" count="<<c.ackCount
                  <<L" ready_wait_us="<<c.ackReadyWait.count()
                  <<L" send_us="<<c.ackSendTime.count()
                  <<L" max_us="<<c.longestAck.count()<<L'\n';
    };
    const auto connectionFailure=[](const wchar_t* stage,const Connection& c){
        std::wcerr<<L"airdrop_receive_failed stage="<<stage<<L" id="<<c.id
                  <<L" tls_error="<<c.tls->error()<<L" tcp_error="<<c.tcp->error()
                  <<L" plaintext_bytes="<<c.receivedPlain<<L'\n';
        return 4;
    };
    unsigned nextId=1;bool mdnsDue=true;
    bool standbyAnnouncementPending=false;
    tx10ub::airdrop::ReceiveDiscoveryRound discoveryRound;
    bool uploadCommitted=false;
    const auto receivePacket=[&](const auto& peer,auto packet){
        for(auto& c:connections)if(c.tcp&&c.tcp->receive(peer,packet))return;
        if(listener.receive(peer,packet))return;
        const auto parsed=awdlwin::ip::parse_ipv6(packet);
        if(const auto* ip=std::get_if<awdlwin::ip::Packet>(&parsed)){
            const auto dns=awdlwin::ip::parse_mdns(*ip);
            if(const auto* message=std::get_if<awdlwin::ip::Mdns>(&dns)){
                using Query = tx10ub::airdrop::ReceiveMdns::Query;
                const auto query=advertisement.classify_query(*message);
                if(query==Query::local){
                    mdnsDue=true;
                    discoveryRound.observe(peer, GetTickCount64());
                } else if(query==Query::otherInstanceLookup && channel==6 && ip->destination[0]==0xff){
                    standbyAnnouncementPending=true;
                }
            }
        }
    };
    receiver.receive_application(receivePacket);
    struct Detach {
        tx10ub::usb::DiscoveryReceiver& r;
        ~Detach(){r.observe_receive_discovery({});r.receive_application({});}
    };
    // Record startup only. Separate limits keep a burst of lookups from hiding
    // the first SYN, including one admitted while the listener is detached.
    std::array<unsigned,3> discoveryEvents{};
    unsigned startupAnnouncements=0;
    const auto localAddress=tx10ub::tcp::local_address(source);
    Detach detach{receiver};
    receiver.observe_receive_discovery([&](const auto& datagram,bool attached){
        const wchar_t* stage=nullptr;
        unsigned kind=0;
        if(datagram.mdns){
            using Query=tx10ub::airdrop::ReceiveMdns::Query;
            switch(advertisement.classify_query(*datagram.mdns)){
            case Query::local: stage=L"local_query"; break;
            case Query::otherInstanceLookup: stage=L"other_lookup"; kind=1; break;
            default: return;
            }
        } else if(datagram.packet.protocol==IPPROTO_TCP && datagram.packet.destination==localAddress){
            const auto segment=tx10ub::tcp::parse(datagram.ipv6);
            if(!segment || segment->destination_port!=8771 || (segment->flags&0x12)!=0x02)return;
            stage=L"syn";kind=2;
        } else return;
        if(discoveryEvents[kind]>=16)return;
        ++discoveryEvents[kind];
        std::wcout<<L"receive_discovery_stage="<<stage<<L" tick_ms="<<GetTickCount64()
                  <<L" committed_channel="<<channel<<L" listener_attached="<<attached<<L" peer=";
        PrintBytes(datagram.source.data(),datagram.source.size());
        std::wcout<<L'\n'<<std::flush;
    });
    if(!control||!control->healthy()||!startAdvertisement())return 4;
    const auto send=[&](const awdlwin::wire::Bytes& ip,const awdlwin::mdns::Endpoint& endpoint){
        if(ip.size()<40)return 4;
        auto to=endpoint.peer;if(ip[24]==0xff)to={0x33,0x33,ip[36],ip[37],ip[38],ip[39]};
        const auto frame=awdlwin::wire::build_awdl_data_mpdu({to,source,sequence++,0x86dd,ip},0);
        if(!frame)return 4;
        using Rate = tx10ub::direct_ihv::DataRate;
        const auto segment = tx10ub::tcp::parse(ip);
        const auto rate = (to[0] & 1) == 0 && segment && segment->flags == 0x10 && segment->payload_size == 0
            && receiveAckRateMbps == 24 ? Rate::Mbps24 : Rate::Mbps12;
        return SendRawDataFrame(luid,index,device,receiver,maintainAction,channel,control,
            frame.value(),3,[&]{return receiver.name_peer_current(endpoint);},{},false,false,rate,channel==44);
    };
    ULONGLONG lastFrame=0,lastTick=0;
    DWORD receiveWaitMs=0;
    bool announcedConnection=false;
    std::wcout<<L"airdrop_receive_ack_rate_mbps="<<receiveAckRateMbps<<L'\n';
    std::wcout<<L"receive_discovery_stage=ready tick_ms="<<GetTickCount64()<<L'\n';
    std::wcout<<events::ReceiveWaiting<<L'\n';
    std::wcout<<L"airdrop_receive_listening=1\n"<<std::flush;
    for(;;){
        if(!control||!control->healthy())break;
        if(!worker.healthy()){
            std::wcerr<<L"airdrop_receive_worker_unavailable=1\n";return 4;
        }
        if(!receiver.poll(receiveWaitMs))return 4;
        receiveWaitMs=0;
        if(!listener.healthy()){
            std::wcerr<<L"airdrop_receive_listener_unavailable=1\n";return 4;
        }
        listener.tick(clock());
        const bool tcpIdle=!listener.has_pending_connections()&&
            std::none_of(connections.begin(),connections.end(),[](const auto& c){return bool(c.tcp);});
        if(!tcpIdle || channel!=6)standbyAnnouncementPending=false;
        receiver.set_receive_tcp_active(!tcpIdle);
        if(tcpIdle&&announcedConnection){
            std::wcout<<events::ReceiveTcpIdle<<L'\n'<<std::flush;
            announcedConnection=false;
            discoveryRound.tcp_ended(GetTickCount64(), uploadCommitted);
            uploadCommitted = false;
        }
        const auto& widePeer = discoveryRound.wide_peer();
        if (tcpIdle && discoveryRound.should_reopen(GetTickCount64(),
                widePeer && receiver.target_peer_present(*widePeer))) {
            if (channel == 44) {
                receiver.receive_application({});
                RadioHandoffWaiting waiting(true, false);
                if (!ChangePeerDataChannel(receiver, *control, channel, actionChannel, 6, true)) return 4;
                receiver.receive_application(receivePacket);
            }
            discoveryRound.reset();
            mdnsDue = true;
            std::wcout << L"airdrop_receive_discovery_reopened channel=" << channel << L'\n' << std::flush;
        }
        const auto requestingPeer = tcpIdle && channel == 6 ? discoveryRound.single_requester(GetTickCount64()) : std::nullopt;
        if (requestingPeer && receiver.preferred_data_channel(*requestingPeer, true) == 44u) {
            std::wcout<<L"receive_discovery_stage=handoff_begin tick_ms="<<GetTickCount64()<<L'\n'<<std::flush;
            receiver.receive_application({});
            const auto result=PreparePeerDataChannel(receiver,*control,channel,actionChannel,
                *requestingPeer,maintainAction,true);
            if(result)return result;
            receiver.receive_application(receivePacket);
            std::wcout<<L"receive_discovery_stage=handoff_end tick_ms="<<GetTickCount64()
                      <<L" committed_channel="<<channel<<L'\n'<<std::flush;
            mdnsDue=true;
            discoveryRound.channel_attempted(GetTickCount64(), channel == 44 ? requestingPeer : std::nullopt);
        }
        while(worker.can_queue_read(tx10ub::tls::Server::MaxBufferedBytes)){
            auto stream=listener.accept();
            if(!stream)break;
            if(nextId==1){
                receiver.observe_receive_discovery({});
                std::wcout<<L"receive_discovery_stage=tcp_established tick_ms="<<GetTickCount64()
                          <<L" peer=";
                PrintBytes(stream->endpoint().peer.data(),stream->endpoint().peer.size());
                std::wcout<<L'\n'<<std::flush;
            }
            auto slot=std::find_if(connections.begin(),connections.end(),[](const auto& c){return !c.tcp;});
            if(slot==connections.end())return 4;
            slot->id=nextId++;if(!nextId)return 4;
            uploadCommitted = false;
            slot->tcp=std::move(stream);slot->tls=std::make_unique<tx10ub::tls::Server>(identity);slot->activity=GetTickCount64();
            if(!slot->tls->healthy())return connectionFailure(L"tls_init",*slot);
            if(!worker.send(1,slot->id))return 4;
            announcedConnection=true;
            std::wcout<<events::ReceiveConnected<<slot->id<<L'\n'<<std::flush;
        }
        const auto now=GetTickCount64();
        if(now-lastTick>=100 && worker.can_queue_read(tx10ub::tls::Server::MaxBufferedBytes)){
            if(GetFileAttributesW(cancelPath.c_str())!=INVALID_FILE_ATTRIBUTES)return 4;
            if(!worker.send(4,0))return 4;
            lastTick=now;
        }
        for(auto& message:worker.take()){
            // A new connection may already be using the current channel.
            if (message.type == 3 && !message.data.empty() &&
                message.data.front() == tx10ub::receive_worker_protocol::UploadCommitted && message.connection == nextId - 1) {
                uploadCommitted = !tcpIdle;
                if (tcpIdle) discoveryRound.tcp_ended(GetTickCount64(), true);
            }
            const auto c=std::find_if(connections.begin(),connections.end(),[&](const auto& item){return item.tcp&&item.id==message.connection;});
            if(c==connections.end())continue;
            if(message.type==3)c->closeRequested=true;
            else if(message.type==tx10ub::receive_worker_protocol::FinalizingProgress)c->activity=now;
            else {if(c->plain.size()+message.data.size()>131072)return connectionFailure(L"response_buffer",*c);c->plain.insert(c->plain.end(),message.data.begin(),message.data.end());}
        }
        if(const auto* ip=listener.outbound()){
            const auto* endpoint=listener.outbound_endpoint();
            if(!endpoint)return 4;
            // No send is in flight here: SendRawDataFrame always joins/drains
            // before returning to this owner loop.
            if(!receiver.name_peer_current(*endpoint)){listener.discard_outbound();continue;}
            if(receiver.name_send_ready(*endpoint,channel,channel==44)){const auto result=send(*ip,*endpoint);if(result)return result;listener.sent();lastFrame=GetTickCount64();continue;}
        }
        bool sentFrame=false;
        for(auto& c:connections){
            if(!c.tcp)continue;
            c.tcp->tick(clock());
            const bool canRead = worker.can_queue_read(tx10ub::tls::Server::MaxBufferedBytes);
            bool valid=c.tcp->healthy()&&receiver.name_peer_current(c.tcp->endpoint());
            if(valid && !c.shutdown && canRead){
                auto received=c.tcp->read();
                if(!received.empty()){c.activity=now;valid=c.tls->feed(received);}
            }
            if(valid && !c.shutdown && canRead){
                auto plain=c.tls->read();c.receivedPlain+=plain.size();
                constexpr auto frameBytes=tx10ub::receive_worker_protocol::MaxFrameBytes;
                for(std::size_t offset=0;offset<plain.size();offset+=frameBytes)
                    if(!worker.send(2,c.id,std::span(plain).subspan(offset,(std::min)(frameBytes,plain.size()-offset))))return 4;
            }
            if(c.tls->ready()&&!c.reportedTls){c.reportedTls=true;std::wcout<<L"airdrop_receive_tls_ready id="<<c.id<<L'\n'<<std::flush;}
            // Schannel marks a local shutdown closed as soon as it generates
            // close_notify. The response and alert still need TCP delivery.
            valid=valid&&(c.shutdown||c.tls->healthy())&&now-c.activity<180000&&
                (c.shutdown?now-c.closingAt<=10000:!c.tls->closed()&&(!canRead||!c.tcp->eof()));
            if(!valid){
                std::wcout<<L"airdrop_receive_connection_closed id="<<c.id<<L" tcp_error="<<c.tcp->error()
                    <<L" tls_error="<<c.tls->error()<<L" peer_current="<<receiver.name_peer_current(c.tcp->endpoint())
                    <<L" tcp_eof="<<c.tcp->eof()<<L" tls_closed="<<c.tls->closed()
                    <<L" idle_ms="<<now-c.activity
                    <<L" plaintext_bytes="<<c.receivedPlain<<L'\n'<<std::flush;
                constexpr std::array closeNotice{tx10ub::receive_worker_protocol::OrderlyTlsClose};
                const bool peerClosed=!c.shutdown&&c.tls->closed()&&c.tls->healthy()&&c.tcp->healthy();
                if(!worker.send(3,c.id,peerClosed?std::span<const std::uint8_t>(closeNotice):std::span<const std::uint8_t>{}))return 4;
                reportAckTiming(c);
                c.tcp->abort();if(!c.tls->close())return connectionFailure(L"tls_close",c);c=Connection{};continue;
            }
            if(!c.shutdown&&c.tls->ready()&&!c.plain.empty()&&c.cipher.size()<65536){
                const auto n=(std::min)(c.plain.size(),c.tls->max_message_size());
                if(!n||!c.tls->write(std::span(c.plain).first(n)))return connectionFailure(L"tls_write",c);
                c.plain.erase(c.plain.begin(),c.plain.begin()+n);
            }
            if(c.closeRequested&&c.plain.empty()&&!c.shutdown){
                if(!c.tls->shutdown()){
                    std::wcerr<<L"airdrop_receive_tls_shutdown_failed id="<<c.id
                              <<L" tls_error="<<c.tls->error()<<L'\n'<<std::flush;
                }
                c.shutdown=true;c.closingAt=now;
            }
            auto encrypted=c.tls->outbound();if(c.cipher.size()+encrypted.size()>131072)return connectionFailure(L"cipher_buffer",c);
            c.cipher.insert(c.cipher.end(),encrypted.begin(),encrypted.end());
            if(!c.cipher.empty()){
                const auto n=c.tcp->write(c.cipher);if(n){c.cipher.erase(c.cipher.begin(),c.cipher.begin()+n);c.activity=now;}
            }
            if (const auto* ip=c.tcp->outbound()) {
                const auto segment=tx10ub::tcp::parse(*ip);
                const bool ack=segment&&segment->flags==0x10&&segment->payload_size==0;
                if (ack&&!c.ackQueuedAt) c.ackQueuedAt=awdlwin::discovery::monotonic_now();
                if (!ack) c.ackQueuedAt.reset();
                if (receiver.name_send_ready(c.tcp->endpoint(),channel,channel==44)) {
                    const auto sendStart=ack?awdlwin::discovery::monotonic_now():awdlwin::discovery::MonotonicTime{};
                    const auto result=send(*ip,c.tcp->endpoint());if(result)return result;
                    if (c.ackQueuedAt) {
                        const auto completed=awdlwin::discovery::monotonic_now();
                        ++c.ackCount;
                        c.ackReadyWait+=sendStart-*c.ackQueuedAt;
                        c.ackSendTime+=completed-sendStart;
                        c.longestAck=(std::max)(c.longestAck,completed-*c.ackQueuedAt);
                        c.ackQueuedAt.reset();
                    }
                    c.tcp->sent();lastFrame=GetTickCount64();sentFrame=true;break;
                }
            } else {
                c.ackQueuedAt.reset();
            }
            if(c.shutdown&&c.cipher.empty()&&!c.tcp->write_pending()){
                if(!worker.send(3,c.id))return 4;
                reportAckTiming(c);
                c.tcp->abort();if(!c.tls->close())return connectionFailure(L"tls_close",c);c=Connection{};
            }
        }
        if(sentFrame)continue;
        if(const auto window=receiver.peer_action_channel_window(awdlwin::discovery::monotonic_now(),channel)){
            advertisement.observe_link(window->peer,channel);
            if(advertisement.announcement_due(now,mdnsDue || (standbyAnnouncementPending && tcpIdle && channel==6),tcpIdle)){
                const auto frame=advertisement.frame(sequence++);
                // The send pumps receive callbacks. Keep any new query they queue.
                mdnsDue=false;
                standbyAnnouncementPending=false;
                const auto result=SendRawDataFrame(luid,index,device,receiver,maintainAction,channel,control,frame,1,[]{return true;},{},false,true);
                if(result)return result;
                lastFrame=GetTickCount64();
                advertisement.announced(lastFrame);
                if(nextId==1 && startupAnnouncements<16){
                    ++startupAnnouncements;
                    std::wcout<<L"receive_discovery_stage=announcement_accepted tick_ms="<<lastFrame
                              <<L" committed_channel="<<channel<<L'\n'<<std::flush;
                }
                continue;
            }
        }
        if((!lastFrame||now-lastFrame>=100)&&maintainAction){const auto result=maintainAction();if(result)return result;}
        // An idle poll may block until input, then service TCP immediately.
        receiveWaitMs=1;
    }
    for(auto& c:connections)if(c.tcp){reportAckTiming(c);worker.send(3,c.id);c.tcp->abort();if(!c.tls->close())return 4;c=Connection{};}
    const bool workerClosed=worker.close();
    return identity.close()&&workerClosed?4:14; // Return through the existing operator-stop restoration path.
} catch(const std::exception& error){std::cerr<<"airdrop_receive_exception="<<error.what()<<'\n';return 4;}

void WithdrawReceiveService(NET_LUID luid,NET_IFINDEX index,HANDLE device,tx10ub::usb::DiscoveryReceiver& receiver,
    const std::function<int()>& maintainAction,ULONG channel,UnassociatedControl& control,USHORT& sequence,
    tx10ub::airdrop::ReceiveMdns& service) {
    if(!control.ready_to_withdraw() || (!service.mdns_announced() && !service.action_withdrawal_pending()))return;
    service.begin_withdrawal();
    const auto deadline=awdlwin::discovery::monotonic_now()+
        std::chrono::milliseconds{dropporter::session_markers::ReceiveWithdrawalWindowMs};
    // The normal scheduler now sends an empty service bitmap with a changed SUI.
    const auto sendAction=[&] {
        if(!control.ready_to_withdraw())return 4;
        return service.action_withdrawal_pending() ? maintainAction() : 0;
    };
    if(service.mdns_announced()){
        const auto goodbye=service.frame(sequence++);
        const auto result=SendRawDataFrame(luid,index,device,receiver,sendAction,channel,&control,goodbye,1,
            [&]{return control.ready_to_withdraw();},{},false,true,tx10ub::direct_ihv::DataRate::Mbps12,false,nullptr,deadline);
        std::wcout<<L"receive_mdns_goodbye_submitted="<<(result==0)<<L'\n'<<std::flush;
    }
    if(service.action_withdrawal_pending()){
        while(awdlwin::discovery::monotonic_now()<deadline && sendAction()==0 && service.action_withdrawal_pending())
            if(!receiver.poll(1))break;
    }
    std::wcout<<L"receive_awdl_withdrawal_submitted="<<service.withdrawal_action_sent()<<L'\n'<<std::flush;
}

// No TCP owner exists across this handoff. The controller owns physical tuning;
// the receive owner commits only the local fixed schedule after the exact reply.
int PreparePeerDataChannel(tx10ub::usb::DiscoveryReceiver& receiver,UnassociatedControl& control,
                          ULONG& dataChannel,ULONG& actionChannel,const awdlwin::wire::MacAddress& peer,
                          const std::function<int()>& maintainAction,bool receiving) {
    if(dataChannel!=6||actionChannel!=6)return 4;
    if(!receiver.uses_ndiscap()&&!receiver.await_action_out_fence())return 4;
    bool wide44=false;
    const auto preferred=receiver.preferred_data_channel(peer,receiving,&wide44);
    if(preferred!=44u) {
        std::wcout<<L"airdrop_data_channel_selected=6 reason="
            <<(preferred?L"peer_schedule_prefers_6":L"peer_schedule_unavailable")<<L'\n'<<std::flush;
        return 0;
    }
    const RadioHandoffWaiting waiting(receiving,wide44);
    const auto awaitPeer=[&](awdlwin::discovery::MonotonicTime switchedAt)->int {
        const auto deadline=GetTickCount64()+1500;
        do {
            if(!receiver.poll())return -1;
            if(receiver.target_action_after(peer,switchedAt))return 1;
            if(maintainAction&&maintainAction()!=0)return -1;
            if(!receiver.wait(1))return -1;
        }while(GetTickCount64()<deadline);
        return 0;
    };
    if(!ChangePeerDataChannel(receiver,control,dataChannel,actionChannel,44,receiving))return 4;
    const auto confirmed=awaitPeer(awdlwin::discovery::monotonic_now());
    if(confirmed<0)return 4;
    bool confirmedWide=false;
    if(confirmed&&receiver.preferred_data_channel(peer,receiving,&confirmedWide)==44u&&confirmedWide==wide44) {
        std::wcout<<L"airdrop_data_channel_selected=44\n"<<std::flush;
        return 0;
    }
    if(!ChangePeerDataChannel(receiver,control,dataChannel,actionChannel,6,receiving))return 4;
    if(!receiving&&awaitPeer(awdlwin::discovery::monotonic_now())!=1)return 4;
    std::wcout<<L"airdrop_data_channel_selected=6 reason=peer_not_confirmed_on_44\n"<<std::flush;
    return 0;
}

static std::wstring DiscoveryBodyHex(const AWDLWIN_ACTION_REQUEST_V1& action) {
    std::wstring body;
    constexpr wchar_t digits[] = L"0123456789abcdef";
    for (USHORT i = 0; i < action.BodyLength; ++i) {
        body += digits[action.Body[i] >> 4];
        body += digits[action.Body[i] & 15];
    }
    return body;
}

int RunPocDiscovery(int argc, wchar_t** argv, const std::atomic_bool* associationChanged = nullptr,
                    bool validateApPsf = false) try {
    if (argc < 8 || argc > 32) {
        std::wcerr << L"usage: poc-discovery <port> <channel> <band> <psf|mif|both> <count> <interval-ms> [--preview] [--off-channel] [--native-rx] [--usb-rx HUB ADDRESS] [--usb-save NEW.pcap] [--ndiscap-rx SESSION] [--mdns-browse] [--specific-action]\n"
            L"--mdns-browse continues PSF/MIF advertisements after count, up to 256 extra accepted advertisements\n"
            L"--ble-v2-everyone selects the captured V2 zero-hash comparison advertisement; requires --mdns-browse (default: V3)\n"
            L"--raw-action-preview requires --preview; prints the raw Action input without sending\n"
            L"--live-response uses response tasks only for fresh live USB Apple Actions (channel 44)\n"
            L"--predict-sync projects Sync to USB TX time learned in this USB session\n"
            L"--specific-action sends timestamped PSF/MIF through the raw Action OID with --mdns-browse\n"
            L"--tcp-connect-check checks SYN/SYN-ACK/ACK then resets the discovered AirDrop endpoint; requires unassociated raw Data and cipher disabled\n"
            L"--airdrop-discover exchanges HTTPS /Discover over the user-mode TCP/TLS stream; excludes --tcp-connect-check\n"
            L"--airdrop-send-file PATH continues with /Ask and /Upload for one regular file; requires --airdrop-discover\n"
            L"--airdrop-receive-destination DIR --airdrop-receive-control DIR receives with explicit desktop consent; requires unassociated raw Data and excludes sending\n"
            L"--direct-ihv uses serialized Realtek IHV calls for raw Action/Data/WPS/cipher requests; requires the auxiliary service stopped or absent\n"
            L"--verbose-log retains per-frame diagnostics during file sending (other diagnostic modes retain them by default)\n"
            L"--select-target waits for the desktop target selection; requires file sending and unassociated control\n"
            L"--peer-data-channel tries the selected peer's preferred channel before opening the transfer connection\n"
            L"--mdns-rf-lead-us 0..16000 applies explicit paired-capture Data scheduling calibration\n"
            L"--ndiscap-rx SESSION uses the selected adapter's Drop Porter NDIS receive session with --direct-ihv\n";
        return 2;
    }
    USHORT port = 0;
    ULONG channel = 0, band = 0, count = 0, interval = 0;
    const bool mif = wcscmp(argv[5], L"mif") == 0;
    const bool both = wcscmp(argv[5], L"both") == 0;
    if ((!mif && !both && wcscmp(argv[5], L"psf") != 0) || !ParsePortId(argv[2], port) || port != 0 ||
        !ParseUnsigned(argv[3], channel) || (channel != 6 && channel != 44 && channel != 149) ||
        !ParseUnsigned(argv[4], band) || band != (channel == 6 ? 1u : 2u) ||
        !ParseUnsigned(argv[6], count) || count == 0 || count > 200 ||
        !ParseUnsigned(argv[7], interval) || interval > 60000) return 2;
    bool preview = false, offChannel = false, nativeRx = false, nativeExplicit = false, mdnsBrowse=false, liveResponse=false, predictSync=false, specificAction=false;
    bool rawActionPreview=false,bleV2Everyone=false,rawVendorData=false,encryptionDisabled=false,tcpConnectCheck=false,airdropDiscover=false;
    bool pairedRfLeadExplicit=false,verboseLog=false,selectTarget=false,directIhvMode=false,adapterGuidGiven=false;
    GUID adapterGuid{};
    bool peerDataChannel=false;
    ULONG pairedRfLeadUs=0;
    const wchar_t* controlPath=nullptr;
    const wchar_t* sendFilePath=nullptr;
    bool sendFromStdin=false;
    bool sendSelected=false;
    const wchar_t* receiveDestination=nullptr;
    const wchar_t* receiveControl=nullptr;
    const wchar_t* usbHub=nullptr;
    const wchar_t* usbTrace=nullptr;
    std::wstring ndiscapSession;
    ULONG usbAddress=0;
    ULONG fileOwnerPid=0;
    ULONG receiveAckRateMbps=0;
    const auto validNdiscapSession=[](std::wstring_view value) {
        constexpr std::wstring_view prefix=L"DropPorter.NdisCap.";
        if(value.size()!=prefix.size()+32||value.substr(0,prefix.size())!=prefix)return false;
        return std::all_of(value.begin()+static_cast<std::ptrdiff_t>(prefix.size()),value.end(),[](wchar_t ch) {
            return (ch>=L'0'&&ch<=L'9')||(ch>=L'a'&&ch<=L'f');
        });
    };
    for (int i = 8; i < argc; ++i) {
        if (wcscmp(argv[i], L"--preview") == 0 && !preview) preview = true;
        else if (wcscmp(argv[i], L"--raw-action-preview") == 0 && !rawActionPreview) rawActionPreview = true;
        else if (wcscmp(argv[i], L"--off-channel") == 0 && !offChannel) offChannel = true;
        else if (wcscmp(argv[i], L"--native-rx") == 0 && !nativeExplicit) {nativeRx=true;nativeExplicit=true;}
        else if(wcscmp(argv[i],L"--unassociated-control")==0&&!controlPath&&i+1<argc)controlPath=argv[++i];
        else if(wcscmp(argv[i],L"--mdns-browse")==0&&!mdnsBrowse)mdnsBrowse=true;
        else if(wcscmp(argv[i],L"--ble-v2-everyone")==0&&!bleV2Everyone)bleV2Everyone=true;
        else if(wcscmp(argv[i],L"--live-response")==0&&!liveResponse)liveResponse=true;
        else if(wcscmp(argv[i],L"--predict-sync")==0&&!predictSync)predictSync=true;
        else if(wcscmp(argv[i],L"--specific-action")==0&&!specificAction)specificAction=true;
        else if(wcscmp(argv[i],L"--vendor-wps-raw-data")==0&&!rawVendorData)rawVendorData=true;
        else if(wcscmp(argv[i],L"--vendor-encryption-disabled")==0&&!encryptionDisabled)encryptionDisabled=true;
        else if(wcscmp(argv[i],L"--tcp-connect-check")==0&&!tcpConnectCheck)tcpConnectCheck=true;
        else if(wcscmp(argv[i],L"--airdrop-discover")==0&&!airdropDiscover)airdropDiscover=true;
        else if(wcscmp(argv[i],L"--direct-ihv")==0&&!directIhvMode)directIhvMode=true;
        else if(wcscmp(argv[i],L"--adapter-guid")==0&&!adapterGuidGiven&&i+1<argc) {
            if (FAILED(CLSIDFromString(argv[++i], &adapterGuid))) return 2;
            adapterGuidGiven=true;
        }
        else if(wcscmp(argv[i],L"--verbose-log")==0&&!verboseLog)verboseLog=true;
        else if(wcscmp(argv[i],L"--select-target")==0&&!selectTarget)selectTarget=true;
        else if(wcscmp(argv[i],L"--peer-data-channel")==0&&!peerDataChannel)peerDataChannel=true;
        else if(wcscmp(argv[i],L"--file-owner-pid")==0&&!fileOwnerPid&&i+1<argc) {
            if(!ParseUnsigned(argv[++i],fileOwnerPid)||!fileOwnerPid)return 2;
        }
        else if(wcscmp(argv[i],L"--receive-ack-rate-mbps")==0&&!receiveAckRateMbps&&i+1<argc) {
            if(!ParseUnsigned(argv[++i],receiveAckRateMbps)||(receiveAckRateMbps!=12&&receiveAckRateMbps!=24))return 2;
        }
        else if(wcscmp(argv[i],L"--airdrop-receive-destination")==0&&!receiveDestination&&i+1<argc)receiveDestination=argv[++i];
        else if(wcscmp(argv[i],L"--airdrop-receive-control")==0&&!receiveControl&&i+1<argc)receiveControl=argv[++i];
        else if(wcscmp(argv[i],L"--airdrop-send-selected")==0&&!sendSelected&&!sendFromStdin&&!sendFilePath)sendSelected=true;
        else if(wcscmp(argv[i],L"--airdrop-send-stdin")==0&&!sendFromStdin&&!sendFilePath&&!sendSelected)sendFromStdin=true;
        else if(wcscmp(argv[i],L"--airdrop-send-file")==0&&!sendFilePath&&!sendFromStdin&&!sendSelected&&i+1<argc) {
            sendFilePath=argv[++i];if(!*sendFilePath)return 2;
        }
        else if(wcscmp(argv[i],L"--mdns-rf-lead-us")==0&&!pairedRfLeadExplicit&&i+1<argc) {
            pairedRfLeadExplicit=true;
            if(!ParseUnsigned(argv[++i],pairedRfLeadUs)||
               pairedRfLeadUs>tx10ub::usb::Session::maximum_paired_rf_lead_us)return 2;
        }
        else if(wcscmp(argv[i],L"--usb-rx")==0&&!usbHub&&i+2<argc) {
            usbHub=argv[++i];
            if(!ParseUnsigned(argv[++i],usbAddress)||usbAddress<1||usbAddress>127||
               std::wstring(usbHub).rfind(L"\\\\.\\USBPcap",0)!=0)return 2;
            // USB receives before the miniport's NDIS software mask. Native
            // WDI observation remains explicitly selectable with --native-rx.
        }
        else if(wcscmp(argv[i],L"--usb-save")==0&&!usbTrace&&i+1<argc) {
            usbTrace=argv[++i];if(!*usbTrace)return 2;
        }
        else if(wcscmp(argv[i],L"--ndiscap-rx")==0&&ndiscapSession.empty()&&i+1<argc) {
            ndiscapSession=argv[++i];if(!validNdiscapSession(ndiscapSession))return 2;
        }
        else return 2;
    }
    const bool ndiscapRx=!ndiscapSession.empty();
    if((rawActionPreview&&(!preview||offChannel||nativeExplicit))||
       (usbHub&&preview)||(usbTrace&&!usbHub)||(ndiscapRx&&(usbHub||usbTrace||predictSync||pairedRfLeadExplicit||liveResponse))||
       (bleV2Everyone&&!mdnsBrowse)||
       (both&&(count<2||offChannel||(!preview&&!usbHub&&!ndiscapRx)))||
       (mdnsBrowse&&(preview||offChannel||(!usbHub&&!ndiscapRx)||(channel!=44&&!(channel==6&&specificAction))))||
       (liveResponse&&(preview||offChannel||!usbHub||channel!=44))||
       (specificAction&&(preview||offChannel||nativeExplicit||!mdnsBrowse||liveResponse||
           (ndiscapRx?(usbHub||predictSync):(!predictSync||!usbHub))||(channel!=44&&channel!=6)))||
       (predictSync&&!liveResponse&&!specificAction)||
       (pairedRfLeadExplicit&&(!mdnsBrowse||(!liveResponse&&!specificAction)||!predictSync)))return 2;
    if(controlPath&&(preview||offChannel||nativeExplicit||(!usbHub&&!ndiscapRx)||(!usbTrace&&!ndiscapRx)||
        !specificAction||!mdnsBrowse||(!predictSync&&!ndiscapRx)||!bleV2Everyone||channel!=6))return 2;
    if(ndiscapRx&&(!directIhvMode||!controlPath||!mdnsBrowse||!specificAction||tcpConnectCheck||
        !rawVendorData||!encryptionDisabled||nativeExplicit||channel!=6))return 2;
    if(directIhvMode&&(!controlPath||!rawVendorData||!encryptionDisabled||preview||offChannel||nativeExplicit||
        (!ndiscapRx&&(!usbHub||!usbTrace||!predictSync))||(ndiscapRx&&(usbHub||usbTrace||predictSync))||
        !specificAction||!mdnsBrowse||!bleV2Everyone||channel!=6))return 2;
    if(rawVendorData&&!controlPath)return 2;
    if(encryptionDisabled&&!rawVendorData)return 2;
    if(tcpConnectCheck&&(!rawVendorData||!encryptionDisabled||!controlPath))return 2;
    if(airdropDiscover&&(!rawVendorData||!encryptionDisabled||!controlPath||tcpConnectCheck))return 2;
    const bool sending=sendFilePath||sendFromStdin||sendSelected;
    if(sending&&!airdropDiscover)return 2;
    if(sendFromStdin&&!fileOwnerPid)return 2;
    if(sendSelected&&(!selectTarget||!fileOwnerPid))return 2;
    if(peerDataChannel&&(!sending||!selectTarget||!directIhvMode||receiveDestination))return 2;
    if(fileOwnerPid&&!sending&&!receiveDestination)return 2;
    if(receiveAckRateMbps&&(!receiveDestination||!directIhvMode))return 2;
    if(selectTarget&&(!sending||!controlPath))return 2;
    if((receiveDestination||receiveControl)&&(!receiveDestination||!receiveControl||!controlPath||!rawVendorData||!encryptionDisabled||airdropDiscover||tcpConnectCheck||sending||selectTarget||
        !std::filesystem::path(receiveDestination).is_absolute()||!std::filesystem::path(receiveControl).is_absolute()||
        !std::filesystem::is_directory(receiveDestination)||!std::filesystem::is_directory(receiveControl)))return 2;
    // A named adapter is a Drop Porter transfer session.
    if (adapterGuidGiven && (!directIhvMode || !controlPath || !fileOwnerPid || associationChanged ||
                            (!sending && !receiveDestination))) return 2;
    if (!associationChanged && !SelectProbeAdapter(adapterGuidGiven ? &adapterGuid : nullptr)) return 3;
    std::optional<tx10ub::airdrop::SendBatch> sendFile;
    if(sending&&!sendSelected) {
        try{
            std::vector<std::filesystem::path> paths;
            if(sendFromStdin) {
                const HANDLE input=GetStdHandle(STD_INPUT_HANDLE);
                LARGE_INTEGER size{};
                if(GetFileType(input)!=FILE_TYPE_DISK||!GetFileSizeEx(input,&size)||size.QuadPart<=0)return 2;
                const auto bytes=static_cast<std::uint64_t>(size.QuadPart);
                if(bytes%sizeof(wchar_t)||bytes>tx10ub::send_files::MaxPathListChars*sizeof(wchar_t))return 2;
                const auto length=static_cast<DWORD>(bytes);
                std::wstring list(length/sizeof(wchar_t),L'\0');
                DWORD read=0;
                if(!ReadFile(input,list.data(),length,&read,nullptr)||read!=length)return 2;
                paths=tx10ub::send_files::PathsFromLines(list);
                if(!std::all_of(paths.begin(),paths.end(),[](const auto& path){return path.is_absolute();}))return 2;
            } else paths.emplace_back(sendFilePath);
            tx10ub::ScopedUserFileAccess access(fileOwnerPid);
            sendFile=tx10ub::airdrop::prepare_files(paths);
        }
        catch(const std::exception& e){std::cerr<<"airdrop_file_invalid="<<e.what()<<'\n';return 2;}
    }
    std::unique_ptr<UnassociatedControl> control;
    NET_LUID luid{};
    NET_IFINDEX index = 0;
    if (!ResolveTarget(luid, index)) return 3;
    MIB_IF_ROW2 current{};
    current.InterfaceLuid = luid;
    if (GetIfEntry2(&current) != NO_ERROR || current.InterfaceIndex != index ||
        current.PhysicalAddressLength != 6 || (current.PhysicalAddress[0] & 1) != 0) return 3;
    UCHAR self[6]{};
    std::copy_n(current.PhysicalAddress, 6, self);
    const auto firstClock=(usbHub||ndiscapRx)?tx10ub::usb::observe_clock():awdlwin::tx10ub::usb_clock::Observation{};
    auto discovery = MakeExperimentalDiscovery(self, channel,
        mif ? awdlwin::wire::ActionSubtype::mif : awdlwin::wire::ActionSubtype::psf,
        (usbHub||ndiscapRx)?tx10ub::usb::clock_midpoint(firstClock):awdlwin::discovery::monotonic_now());
    discovery.allowOffChannel = offChannel;
    discovery.coexistenceAssociationChanged = associationChanged;
    discovery.bothSubtypes = both;
    discovery.respondToLiveAction=liveResponse;
    discovery.predictSync=predictSync;
    discovery.specificAction=specificAction;
    discovery.trackUsbActions=(mdnsBrowse||predictSync)&&!ndiscapRx;
    discovery.verboseLog=(!sending&&!receiveDestination)||verboseLog;
    discovery.receiving=receiveDestination!=nullptr;
    discovery.interactiveSendBrowse=sending&&selectTarget&&mdnsBrowse&&specificAction&&directIhvMode;
    std::wcout<<L"action_delivery="<<(rawActionPreview?L"raw_frame_preview":specificAction?L"specific_raw_action":liveResponse?L"live_response_task":L"request_task")<<L'\n';
    std::wcout << L"discovery_state=self_master_experiment\npeer_sync="
               <<(usbHub?L"awaiting_live_usb\n":ndiscapRx?L"awaiting_live_ndiscap\n":L"not_adopted\n")
               << L"source_mac=";
    PrintBytes(self, 6);
    std::wcout << L"\npost_ack_dwell_ms=0\nradio_tx_time=uncalibrated\n"
               << L"off_channel_requested=" << offChannel << L'\n'
               << L"native_rx_requested=" << nativeRx << L'\n';
    if (both) std::wcout << L"discovery_mode=psf_mif_alternating\n"
                           L"discovery_cadence=best_effort_after_vendor_admission\n";
    AWDLWIN_ACTION_REQUEST_V1 initial{};
    if (!GenerateDiscoveryBody(discovery, initial, preview)) return 2;
    if (validateApPsf) {
        initial.Size = sizeof(initial);
        initial.Version = AWDLWIN_ACTION_VERSION;
        initial.ExperimentMagic = AWDLWIN_ACTION_EXPERIMENT_MAGIC;
        initial.TargetIfIndex = index;
        initial.TargetNetLuidValue = luid.Value;
        initial.PortId = 0;
        initial.ChannelNumber = channel;
        initial.BandId = channel <= 14 ? 1u : 2u;
        initial.SendTimeoutMs = 1000;
        initial.PostAckDwellMs = 0;
        std::fill_n(initial.Peer, 6, static_cast<UCHAR>(0xff));
        const HANDLE device = CreateFileW(kDevice, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (device == INVALID_HANDLE_VALUE) return 4;
        AWDLWIN_ACTION_RESULT_V1 result{};
        DWORD bytes = 0;
        const BOOL ok = DeviceIoControl(device, IOCTL_AWDLWIN_VALIDATE_AP_PSF,
            &initial, sizeof(initial), &result, sizeof(result), &bytes, nullptr);
        const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        CloseHandle(device);
        if (!ok || bytes != sizeof(result) || result.Size != sizeof(result) ||
            result.Version != AWDLWIN_ACTION_VERSION || result.OidIssued) {
            std::wcerr << L"ap_psf_validation_failed=" << error << L'\n';
            return 4;
        }
        std::wcout << L"ap_psf_validated=1\noid_issued=0\n";
        return 0;
    }
    if (preview) {
        // No device open / OID / service operation in preview mode.
        for (ULONG i = 0; i < count; ++i) {
            if (i != 0 && !GenerateDiscoveryBody(discovery, initial, true, i)) return 2;
            if (rawActionPreview) {
                AWDLWIN_AF_PARAMETERS parameters{};
                std::fill_n(parameters.Peer, 6, static_cast<UCHAR>(0xff));
                parameters.BodyLength = initial.BodyLength;
                std::copy_n(initial.Body, initial.BodyLength, parameters.Body);
                UCHAR raw[AWDLWIN_AF_RAW_BODY_OFFSET + AWDLWIN_AF_MAX_BODY]{};
                size_t written = 0;
                if (!AwdlWinAfSerializeRawFrame(&parameters, self, raw, sizeof(raw), &written)) return 2;
                std::wcout << L"raw_action_inner_oid=0x" << std::hex << AWDLWIN_AF_RAW_INNER_OID
                          << std::dec << L"\nraw_action_input_hex=";
                PrintBytes(raw, written);
                std::wcout << L"\nraw_action_delivery=preview_only\n";
            }
        }
        std::wcout << L"oid_issued=0\n";
        return 0;
    }
    if(controlPath) {
        control=std::make_unique<UnassociatedControl>(controlPath,kGuidText);
        if(!control->healthy()){control->shutdown(true);return 4;}
    }
    std::unique_ptr<DirectIhvSession> directSession;
    if(directIhvMode) {
        try {
            directSession=std::make_unique<DirectIhvSession>(VerifyDirectIhvEnvironment(
                luid,index,sending,ndiscapRx && receiveDestination));
            std::wcout<<L"direct_ihv_ready=1 auxiliary_stopped_or_absent=1 stock_driver_verified=1\n";
        } catch(const std::exception& error) {
            std::wcerr<<L"direct_ihv_preflight_failed="<<error.what()<<L'\n';
            if(control)control->shutdown(true);
            return 4;
        }
    }
    discovery.directIhv=directSession.get();
    discovery.unassociated=control.get();
    tx10ub::BleAdvertisement ble;
    NativeRxLease nativeLease(luid, index);
    RxCamLease camLease(luid,index);
    VendorWpsTrial wpsTrial;
    std::unique_ptr<tx10ub::usb::DiscoveryReceiver> usbReceiver;
    bool receiveAdvertisementPending=ndiscapRx&&receiveDestination;
    const auto startBle=[&] {
        if(ble.start(bleV2Everyone?tx10ub::BleProfile::everyone_v2_comparison:tx10ub::BleProfile::everyone_v3)) {
            receiveAdvertisementPending=false;
            return true;
        }
        if (ble.radio_unavailable()) {
            std::wcerr << events::FailurePrefix.data() << events::Preparing << events::FailureReason.data()
                << events::BluetoothUnavailable << events::FailureHttpStatus.data() << L"0\n";
        }
        return false;
    };
    const auto run=[&]() -> int {
    if(mdnsBrowse&&!rawVendorData&&ReadDataQueryState(true)!=0)return 4;
    if(mdnsBrowse&&!receiveAdvertisementPending&&!startBle())return 4;
    if (nativeRx) {
        if (!nativeLease.enable()) return 4;
        discovery.nativeObserver = &nativeLease.observer();
    }
    const bool camRequested=usbHub&&!offChannel&&!control;
    if(camRequested) {
        const auto sta=ReadConnection(L"cam_before");
        if(!sta.connected||sta.channel!=channel)return 12;
    }
    if(camRequested&&!camLease.enable())return 4;
    if(usbHub||ndiscapRx) {
        usbReceiver=std::make_unique<tx10ub::usb::DiscoveryReceiver>(usbHub?std::wstring(usbHub):std::wstring{},
            usbHub?usbAddress:0,discovery.state,firstClock,usbTrace,
            [&]{return (!associationChanged || !associationChanged->load()) &&
                       (!mdnsBrowse||receiveAdvertisementPending||ble.healthy())&&
                       (!camRequested||camLease.refresh())&&(!control||control->healthy());},
            ndiscapSession,index);
        usbReceiver->set_verbose_logging(discovery.verboseLog);
        usbReceiver->log_coexistence_frames(associationChanged != nullptr);
        if(!usbReceiver->begin())return 4;
        discovery.usbObserver=usbReceiver.get();
        if(rawVendorData&&!wpsTrial.enable(luid,index,self,control.get(),directSession.get()))return 4;
        if(encryptionDisabled&&!IssueEncryptionDisabled(luid,index,control.get(),directSession.get()))return 4;
        if(control)std::wcout<<L"unassociated_active_ready=1\n"<<std::flush;
    }
    auto body = DiscoveryBodyHex(initial);
    wchar_t command[] = L"poc-repeat", broadcast[] = L"ffffffffffff";
    wchar_t timeout[] = L"1000", dwell[] = L"0";
    wchar_t* args[] = {argv[0], command, argv[2], argv[3], argv[4], broadcast,
                      argv[6], argv[7], timeout, dwell, body.data()};
    const auto receiveStarted = GetTickCount64();
    ActiveMdnsRunner activeMdnsRunner;
    if(mdnsBrowse)activeMdnsRunner=[&](HANDLE device,const std::function<int()>& maintainAction,ULONG& actionChannel,
                                      tx10ub::airdrop::ReceiveMdns* receiveService) {
        USHORT nextDataSequence=0;
        if(receiveDestination){
            if(!receiveService || !control)return 4;
            // Withdraw while the radio is available, before joining the file worker.
            tx10ub::airdrop::ReceiveWorker worker;
            const int result=RunAirDropReceive(luid,index,self,device,*usbReceiver,maintainAction,channel,actionChannel,control.get(),nextDataSequence,
                receiveDestination,receiveControl,fileOwnerPid,receiveAckRateMbps ? receiveAckRateMbps : 12,*receiveService,worker,
                [&]{return !receiveAdvertisementPending||startBle();});
            const auto cancelPath=std::filesystem::path(receiveControl)/dropporter::session_markers::CancelFileName;
            if(GetFileAttributesW(cancelPath.c_str())!=INVALID_FILE_ATTRIBUTES)
                WithdrawReceiveService(luid,index,device,*usbReceiver,maintainAction,channel,*control,nextDataSequence,*receiveService);
            return result;
        }
        const auto browse=[&] {
            return RunActiveMdns(luid,index,self,device,*usbReceiver,maintainAction,pairedRfLeadUs,specificAction,
                channel,control.get(),rawVendorData,&nextDataSequence,sending,nextDataSequence);
        };
        const auto result=browse();
        if(result!=0)return result;
        awdlwin::mdns::Endpoint selected;
        bool offerClientCertificate=true;
        if(selectTarget) {
            const auto invalidSelection = [] {
                std::wcerr << events::FailurePrefix.data() << events::Connect << events::FailureReason.data()
                           << dropporter::send_selection::InvalidReason << events::FailureHttpStatus.data()
                           << 0 << L'\n' << std::flush;
                return 2;
            };
            std::vector<std::filesystem::path> selectedFiles;
            std::function<std::optional<unsigned>(unsigned)> readCommittedTarget;
            if (sendSelected) {
                readCommittedTarget = [&](unsigned) -> std::optional<unsigned> {
                    const auto input = dropporter::send_selection::Read(
                        std::filesystem::path(controlPath) / dropporter::target_files::CommittedSelectionName);
                    if (!input) return std::nullopt;
                    auto selection = dropporter::send_selection::Parse(*input);
                    selectedFiles = std::move(selection.files);
                    return selection.target;
                };
            }
            std::optional<AirDropNameLookups> names;
            const auto startNames=[&]{names.emplace(luid,index,self,device,*usbReceiver,maintainAction,channel,control.get(),nextDataSequence);};
            startNames();
            int selection = 0;
            try {
                selection = SelectAirDropTarget(*usbReceiver,maintainAction,*control,selected,
                    [&](tx10ub::airdrop::TargetSelection& candidates,DWORD& waitMs){return names->pump(candidates,waitMs);},
                    [&] {
                        if(!names->close())return 4;
                        names.reset();
                        usbReceiver->clear_discovered_services();
                        const auto error=browse();
                        if(!error)startNames();
                        return error;
                    }, readCommittedTarget, &offerClientCertificate);
            } catch (const std::invalid_argument&) {
                selection = invalidSelection();
            } catch (const std::length_error&) {
                selection = invalidSelection();
            }
            const bool namesClosed=!names||names->close();
            if(selection)return selection;
            if(!namesClosed)return 4;
            if (sendSelected) {
                try {
                    tx10ub::ScopedUserFileAccess access(fileOwnerPid);
                    sendFile = tx10ub::airdrop::prepare_files(selectedFiles);
                } catch (const std::exception& error) {
                    std::cerr << "airdrop_file_invalid=" << error.what() << '\n';
                    return invalidSelection();
                }
            }
            discovery.transferPeerSelected=sendFile.has_value();
        }
        if(peerDataChannel) {
            if(PreparePeerDataChannel(*usbReceiver,*control,channel,actionChannel,selected.peer,maintainAction,false)!=0) {
                std::wcout<<events::FailurePrefix.data()<<events::Connect<<events::FailureReason.data()<<L"send_failed"
                     <<events::FailureHttpStatus.data()<<0<<L'\n'<<std::flush;
                return 4;
            }
        }
        if(airdropDiscover)return RunAirDropDiscover(luid,index,self,device,*usbReceiver,maintainAction,channel,control.get(),nextDataSequence,
            sendFile?&*sendFile:nullptr,discovery.verboseLog,selectTarget?&selected:nullptr,offerClientCertificate);
        if(tcpConnectCheck)return RunTcpConnectCheck(luid,index,self,device,*usbReceiver,maintainAction,channel,control.get(),nextDataSequence);
        return result;
    };
    // The initial AWDL advertisements already search for peers; do not label
    // that interval as preparation until the first DNS query is sent.
    if(sending)std::wcout<<events::StagePrefix.data()<<events::Discovery<<L'\n'<<std::flush;
    int result = RunPocRepeat(11, args, &discovery, mdnsBrowse?&activeMdnsRunner:nullptr);
    if(mdnsBrowse&&!receiveAdvertisementPending&&!ble.healthy())result=4;
    if (nativeRx || usbReceiver) {
        if(usbReceiver)std::wcout<<(usbReceiver->uses_ndiscap()?L"ndiscap_receive_tail_started_us=":L"usb_receive_tail_started_us=")
            <<awdlwin::discovery::monotonic_now().time_since_epoch().count()<<L'\n';
        while (result == 0 && (control || GetTickCount64() - receiveStarted < 30000)) {
            if(usbReceiver&&!usbReceiver->poll()){result=4;break;}
            if (nativeRx && !ReadNativeRx(nativeLease.observer())) { result = 4; break; }
            if(usbReceiver) {
                if(!usbReceiver->wait(200)){result=4;break;}
            } else Sleep(200);
        }
        if (nativeRx && !ReadNativeRx(nativeLease.observer(), true) && result == 0) result = 4;
        const bool camRestored=camLease.close();
        std::wcout<<L"cam_restore_exit="<<(camRestored?0:14)<<L'\n';
        if(!camRestored&&result==0)result=14;
        if(usbReceiver&&!usbReceiver->close()&&result==0)result=4;
        const bool restored = nativeLease.close();
        std::wcout << L"native_capture_exit=" << result
                   << L"\nnative_restore_exit=" << (restored ? 0 : 14) << L'\n';
        if (!restored) return 14;
    }
    return result;
    };
    gDirectIhvSession.store(directSession.get(),std::memory_order_release);
    int result=4;
    try {
        result=run();
    } catch(const std::exception& error) {
        std::wcerr<<L"discovery_exception="<<error.what()<<L'\n';
        result=4;
    } catch(...) {
        std::wcerr<<L"discovery_exception=unknown\n";
        result=4;
    }
    gDirectIhvSession.store(nullptr,std::memory_order_release);
    // All submission workers have joined before run() returns. A timed-out
    // lower send is latched by the control and prevents radio restoration.
    bool bleClosed=false,wpsClosed=false,camClosed=false,nativeClosed=false,usbStopped=!usbReceiver;
    try { bleClosed=ble.close(); } catch(...) { bleClosed=false; }
    try { wpsClosed=wpsTrial.close(); } catch(...) { wpsClosed=false; }
    if(usbReceiver) {
        try { (void)usbReceiver->close(); } catch(...) {}
        usbStopped=usbReceiver->stopped();
    }
    try { camClosed=camLease.close(); } catch(...) { camClosed=false; }
    try { nativeClosed=nativeLease.close(); } catch(...) { nativeClosed=false; }
    DWORD directCloseStatus=ERROR_SUCCESS;
    if(directSession)directCloseStatus=directSession->Close();
    const bool directDrained=!directSession||directSession->drained();
    if(control) {
        const bool wpsDrained=directIhvMode?(!directSession||wpsTrial.drained()):wpsClosed;
        control->shutdown(bleClosed&&wpsDrained&&usbStopped&&camClosed&&nativeClosed&&directDrained&&
            directCloseStatus==ERROR_SUCCESS);
        if(control->stopped()&&(result==4||result==5||result==11||result==12))result=16; // cancelled, not discovery success
    }
    const bool wpsCleanupReady=directIhvMode?(!directSession||wpsTrial.drained()):wpsClosed;
    if(!bleClosed||!wpsCleanupReady||!camClosed||!nativeClosed||directCloseStatus!=ERROR_SUCCESS)return 14;
    return result;
} catch(const std::exception& error) {
    std::wcerr<<L"discovery_exception="<<error.what()<<L'\n';return 4;
}

struct CoexistenceWatch {
    GUID guid{};
    std::atomic_bool changed{};
    std::atomic<int> scanState{}; // 0 idle, 1 awaiting an ACM result, 2 complete, 3 failed
    HANDLE client{};
    ~CoexistenceWatch() { if (client) WlanCloseHandle(client, nullptr); }

    static void WINAPI Notify(PWLAN_NOTIFICATION_DATA event, PVOID opaque) {
        auto& self = *static_cast<CoexistenceWatch*>(opaque);
        if (!event || !IsEqualGUID(event->InterfaceGuid, self.guid)) return;
        const DWORD code = event->NotificationCode;
        if (event->NotificationSource == WLAN_NOTIFICATION_SOURCE_ACM &&
            (code == wlan_notification_acm_scan_complete || code == wlan_notification_acm_scan_fail)) {
            int waiting = 1;
            self.scanState.compare_exchange_strong(waiting,
                code == wlan_notification_acm_scan_complete ? 2 : 3);
        }
        if ((event->NotificationSource == WLAN_NOTIFICATION_SOURCE_ACM &&
             (code == wlan_notification_acm_disconnecting || code == wlan_notification_acm_disconnected ||
              code == wlan_notification_acm_connection_start || code == wlan_notification_acm_connection_complete ||
              code == wlan_notification_acm_interface_removal)) ||
            (event->NotificationSource == WLAN_NOTIFICATION_SOURCE_MSM &&
             (code == wlan_notification_msm_roaming_start || code == wlan_notification_msm_roaming_end ||
              code == wlan_notification_msm_disconnected))) self.changed.store(true);
    }
};

static ULONGLONG FileTimeNow() {
    FILETIME ft{};
    GetSystemTimePreciseAsFileTime(&ft);
    return (static_cast<ULONGLONG>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

static std::optional<unsigned> CountCh6Bss(CoexistenceWatch& watch, ULONGLONG since, ULONGLONG until) {
    WLAN_BSS_LIST* list = nullptr;
    const DWORD error = WlanGetNetworkBssList(watch.client, &watch.guid, nullptr,
        dot11_BSS_type_any, FALSE, nullptr, &list);
    if (error != ERROR_SUCCESS) {
        std::wcerr << L"rx_bss_query_error=" << error << L'\n';
        return std::nullopt;
    }
    unsigned count = 0;
    for (DWORD i = 0; i < list->dwNumberOfItems; ++i) {
        const auto& bss = list->wlanBssEntries[i];
        if (bss.ulChCenterFrequency == 2437000 && bss.ullHostTimestamp >= since &&
            bss.ullHostTimestamp <= until) ++count;
    }
    WlanFreeMemory(list);
    return count;
}

static bool SampleManagementFilter(tx10ub::direct_ihv::DirectIhv& direct, unsigned cycle) {
    const auto start = FileTimeNow();
    const auto value = direct.ReadMac(tx10ub::direct_ihv::MacRegister::ManagementFilter);
    const auto end = FileTimeNow();
    if (!value.value || !DirectAccepted(value)) {
        std::wcerr << L"ce28_query_failed=" << value.win32Status << L" cycle=" << cycle
                   << L" start_filetime=" << start << L" end_filetime=" << end << L'\n';
        return false;
    }
    std::wcout << L"filter_sample_cycle=" << cycle << L" start_filetime=" << start
               << L" end_filetime=" << end << L" ce28=0x" << std::hex << *value.value << std::dec
               << L" action_route=" << ((*value.value >> 26) & 3) << L'\n';
    return true;
}

static int RunApReceiveScans(CoexistenceWatch& watch, const tx10ub::host::Adapter& adapter,
    const tx10ub::host::UsbCaptureTarget& usb, const ConnectionSnapshot& home, const wchar_t* trace,
    bool observeFilter, ULONG cycles, std::optional<awdlwin::wire::MacAddress> peer, bool sendPeerPsf,
    bool observeScanTail, wchar_t* idleLogger) {
    constexpr DWORD scanTimeoutMs = 6500;
    const DWORD homeMs = (observeScanTail || idleLogger != nullptr) ? 20000 : 3000;
    if (home.channel != 44) return 12;
    const auto homeConnected = [&] {
        return !watch.changed.load() && StaStillAssociated(watch.client, watch.guid, home.bssid) &&
            StaUsesChannel(watch.client, watch.guid, 44);
    };
    MIB_IF_ROW2 row{};
    row.InterfaceLuid = adapter.luid;
    if (GetIfEntry2(&row) != NO_ERROR || row.InterfaceIndex != adapter.index ||
        row.PhysicalAddressLength != 6) return 3;
    UCHAR self[6]{};
    std::copy_n(row.PhysicalAddress, 6, self);
    const auto clock = tx10ub::usb::observe_clock();
    auto discovery = MakeExperimentalDiscovery(self, 6, awdlwin::wire::ActionSubtype::psf,
        tx10ub::usb::clock_midpoint(clock));
    tx10ub::usb::DiscoveryReceiver rx(usb.filterPath, usb.address, discovery.state, clock, trace,
        [&] { return !watch.changed.load(); });
    rx.log_coexistence_frames(true);
    rx.select_receive_peer(peer);
    if (sendPeerPsf) {
        std::wcout << L"peer_psf_source=";
        PrintBytes(self, sizeof(self));
        std::wcout << L'\n';
    }
    std::unique_ptr<tx10ub::direct_ihv::DirectIhv> direct;
    if (observeFilter) {
        direct = std::make_unique<tx10ub::direct_ihv::DirectIhv>(
            VerifyDirectIhvEnvironment(adapter.luid, adapter.index, false, false));
    }
    if (!rx.begin() || (direct && !SampleManagementFilter(*direct, 0))) return 4;
    std::wcout << L"rx_cycles_planned=" << cycles << L"\nrx_home_observe_ms=" << homeMs << L'\n';
    if (!trace) {
        const auto cached = CountCh6Bss(watch, 0, FileTimeNow());
        if (!cached || !rx.wait(250) || !rx.close() || !homeConnected()) return 4;
        std::wcout << L"rx_cycles_ready=1 scans_issued=0 cached_ch6_bss=" << *cached << L'\n';
        return 0;
    }
    bool psfAccepted = false;
    Tx10ubScanIdle idle;
    if (idleLogger && !idle.open(idleLogger)) {
        std::wcerr << L"scan_idle_consumer_open_error=" << GetLastError() << L'\n';
        return 4;
    }
    discovery.allowOffChannel = true;
    discovery.coexistenceAssociationChanged = &watch.changed;
    discovery.usbObserver = &rx;
    for (unsigned cycle = 1; cycle <= cycles; ++cycle) {
        if (!homeConnected()) return 12;
        const auto scanStarted = awdlwin::discovery::monotonic_now();
        const auto start = FileTimeNow();
        if (idleLogger) idle.arm(start);
        watch.scanState.store(1);
        const auto tick = GetTickCount64();
        const DWORD error = WlanScan(watch.client, &watch.guid, nullptr, nullptr, nullptr);
        std::wcout << L"rx_scan_cycle=" << cycle << L" requested_filetime=" << start
                   << L" wlan_error=" << error << L'\n';
        if (error != ERROR_SUCCESS) return 4;
        while (watch.scanState.load() == 1 && GetTickCount64() - tick < scanTimeoutMs) {
            if (watch.changed.load() || !rx.wait(25)) return 11;
            if (direct && watch.scanState.load() == 1 && !watch.changed.load() &&
                !SampleManagementFilter(*direct, cycle)) {
                std::wcerr << L"ce28_sampling_stopped=1\n";
                direct.reset(); // Keep collecting the USB tuning and AP observations.
            }
        }
        const auto end = FileTimeNow();
        if (watch.scanState.exchange(0) != 2) {
            std::wcerr << L"rx_scan_incomplete=" << cycle << L'\n';
            return 4;
        }
        const auto fresh = CountCh6Bss(watch, start, end);
        if (!fresh || !homeConnected()) return 12;
        if (idleLogger) {
            const auto deadline = GetTickCount64() + 20000;
            while (!idle.empty_time() && idle.healthy() && GetTickCount64() < deadline) {
                if (watch.changed.load() || !rx.wait(25)) return 11;
            }
            const auto observedIdle = idle.empty_time();
            std::wcout << L"scan_idle_event_filetime=" << observedIdle << L'\n';
            if (!observedIdle || !homeConnected()) return 4;
            discovery.scanIdleForSubmit = [&, observedIdle, scanStarted] {
                return idle.empty_time() == observedIdle && rx.target_action_after(*peer, scanStarted);
            };
            std::wcout << L"scan_idle_peer_current=" << discovery.scanIdleForSubmit() << L'\n';
        }
        if (sendPeerPsf && !psfAccepted && rx.target_action_after(*peer, scanStarted)) {
            AWDLWIN_ACTION_REQUEST_V1 initial{};
            if (!GenerateDiscoveryBody(discovery, initial, false)) return 4;
            std::wstring words[] = {L"", L"poc-repeat", L"0", L"6", L"1", L"ffffffffffff",
                L"1", L"0", L"1000", L"0", DiscoveryBodyHex(initial)};
            wchar_t* args[std::size(words)]{};
            for (size_t i = 0; i < std::size(words); ++i) args[i] = words[i].data();
            std::wcout << L"peer_psf_trigger_cycle=" << cycle << L'\n';
            const int status = RunPocRepeat(static_cast<int>(std::size(args)), args, &discovery);
            if (status != 0) return status;
            if (!homeConnected()) return 12;
            psfAccepted = true;
        }
        const auto homeStart = std::chrono::system_clock::now();
        if (!rx.wait(homeMs) || !homeConnected()) return 12;
        const auto homeEnd = std::chrono::system_clock::now();
        const auto unixMs = [](auto t) {
            return std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count();
        };
        std::wcout << L"rx_cycle=" << cycle << L" scan_end_filetime=" << end
                   << L" fresh_ch6_bss=" << *fresh << L" home_begin_ms=" << unixMs(homeStart)
                   << L" home_end_ms=" << unixMs(homeEnd) << L'\n';
    }
    if (sendPeerPsf) std::wcout << L"peer_psf_request_accepted=" << psfAccepted << L'\n';
    if (direct) SampleManagementFilter(*direct, 0);
    if (!rx.close() || !homeConnected()) return 12;
    std::wcout << L"rx_cycles_completed=" << cycles << L" wlan_transition_seen=0 final_home_matches=1\n";
    return 0;
}

int RunApCoexistence(int argc, wchar_t** argv) try {
    const bool receive = wcscmp(argv[1], L"ap-rx-cycles-ready") == 0 ||
                         wcscmp(argv[1], L"ap-rx-cycles-run") == 0;
    const bool ready = wcscmp(argv[1], L"ap-coexistence-ready") == 0 ||
                       wcscmp(argv[1], L"ap-rx-cycles-ready") == 0;
    const bool check = ready || wcscmp(argv[1], L"ap-coexistence-check") == 0;
    ULONG away = 0, expectedIndex = 0, home = 0;
    UCHAR bssid[6]{};
    size_t bytes = 0;
    const int expectedArgs = check ? 3 : 7;
    int next = expectedArgs;
    const bool sendPeerPsf = receive && next < argc && wcscmp(argv[next], L"--send-peer-psf") == 0;
    if (sendPeerPsf) ++next;
    const bool observeScanTail = receive && !ready && !sendPeerPsf && next < argc &&
        wcscmp(argv[next], L"--observe-scan-tail") == 0;
    if (observeScanTail) ++next;
    const bool observeFilter = receive && next < argc && wcscmp(argv[next], L"--observe-rx-filter") == 0;
    if (observeFilter) ++next;
    ULONG cycles = 4;
    if (receive && next + 2 <= argc && wcscmp(argv[next], L"--cycles") == 0) {
        if (!ParseUnsigned(argv[next+1], cycles) || cycles < 1 || cycles > 12) return 2;
        next += 2;
    }
    std::optional<awdlwin::wire::MacAddress> peer;
    if (receive && next + 2 <= argc && wcscmp(argv[next], L"--peer") == 0) {
        awdlwin::wire::MacAddress mac{};
        if (!ParseHex(argv[next+1], mac.data(), mac.size(), bytes) || bytes != mac.size() ||
            (mac[0] & 1) || mac == awdlwin::wire::MacAddress{}) return 2;
        peer = mac;
        std::wcout << L"rx_peer_hex=" << argv[next+1] << L'\n';
        next += 2;
    }
    wchar_t* idleLogger = nullptr;
    if (receive && !ready && next + 2 == argc && wcscmp(argv[next], L"--idle-logger") == 0) {
        idleLogger = argv[next + 1];
        next += 2;
    }
    if ((idleLogger && (!peer || cycles != 1)) || (observeScanTail && cycles != 1) ||
        (sendPeerPsf && (!peer || observeFilter)) || next != argc || !ParseUnsigned(argv[2], away) ||
        (away != 6 && away != 44 && away != 149)) return 2;
    if (!check && (!ParseUnsigned(argv[3], expectedIndex) || !ParseUnsigned(argv[4], home) ||
        !ParseHex(argv[5], bssid, sizeof(bssid), bytes) || bytes != 6)) return 2;
    const auto selected = SelectProbeAdapter();
    if (!selected) return 3;
    const auto& adapter = *selected;
    if (observeFilter) tx10ub::host::RequireStockRealtekDriver();
    else tx10ub::host::RequireApCoexistenceDriver();
    auto usb = tx10ub::host::DiscoverUsbCaptureTarget(adapter);
    CoexistenceWatch watch;
    watch.guid = adapter.guid;
    DWORD version = 0;
    if (WlanOpenHandle(2, nullptr, &version, &watch.client) != ERROR_SUCCESS ||
        WlanRegisterNotification(watch.client, WLAN_NOTIFICATION_SOURCE_ACM | WLAN_NOTIFICATION_SOURCE_MSM,
            FALSE, CoexistenceWatch::Notify, &watch, nullptr, nullptr) != ERROR_SUCCESS) {
        std::wcerr << L"coexistence_wlan_watch_unavailable\n"; return 4;
    }
    const auto before = ReadConnection(L"home");
    std::wcout << L"coexistence_if_index=" << adapter.index << L"\naway_channel=" << away
               << L"\nusb_filter=" << usb.filterPath << L"\nusb_address=" << usb.address << L'\n';
    if (!before.connected || !before.channel || before.channel == away || watch.changed.load()) return 12;
    if (receive) {
        if (away != 6 || (!ready && (adapter.index != expectedIndex || before.channel != home ||
            std::memcmp(before.bssid, bssid, sizeof(bssid)) != 0))) return 12;
        return RunApReceiveScans(watch, adapter, usb, before, ready ? nullptr : argv[6], observeFilter, cycles, peer, sendPeerPsf, observeScanTail, idleLogger);
    }
    if (ready) {
        std::wstring words[] = {argv[0], L"poc-discovery", L"0", std::to_wstring(away),
            away == 6 ? L"1" : L"2", L"psf", L"1", L"0", L"--off-channel", L"--preview"};
        wchar_t* args[std::size(words)]{};
        for (size_t i = 0; i < std::size(words); ++i) args[i] = words[i].data();
        const int result = RunPocDiscovery(static_cast<int>(std::size(args)), args, &watch.changed, true);
        if (result) return result;
        const auto after = ReadConnection(L"final");
        return !watch.changed.load() && after.connected && after.channel == before.channel &&
            std::memcmp(before.bssid, after.bssid, sizeof(before.bssid)) == 0 ? 0 : 12;
    }
    if (check) return 0;
    if (adapter.index != expectedIndex || before.channel != home ||
        std::memcmp(before.bssid, bssid, sizeof(bssid)) != 0) return 12;

    std::wstring words[] = {argv[0], L"poc-discovery", L"0", std::to_wstring(away),
        away == 6 ? L"1" : L"2", L"psf", L"1", L"0", L"--off-channel",
        L"--usb-rx", usb.filterPath, std::to_wstring(usb.address), L"--usb-save", argv[6]};
    wchar_t* args[std::size(words)]{};
    for (size_t i = 0; i < std::size(words); ++i) args[i] = words[i].data();
    const int result = RunPocDiscovery(static_cast<int>(std::size(args)), args, &watch.changed);
    const auto after = ReadConnection(L"final");
    const bool same = after.connected && after.channel == home &&
        std::memcmp(after.bssid, bssid, sizeof(bssid)) == 0;
    const bool changed = watch.changed.load();
    std::wcout << L"wlan_transition_seen=" << changed << L"\nfinal_home_matches=" << same << L'\n';
    if (result != 0) return result;
    return same && !changed ? 0 : 11;
} catch (const std::exception& error) {
    std::cerr << "coexistence_error=" << error.what() << '\n'; return 4;
}

int RunNativeRxStatus(int argc) {
    if (argc != 2) return 2;
    NativeRxObserver observer{};
    if (!ResolveTarget(observer.luid, observer.index)) return 3;
    observer.device = CreateFileW(kDevice, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (observer.device == INVALID_HANDLE_VALUE) return 4;
    const bool statusOk = ControlNativeRx(observer, AWDLWIN_NATIVE_RX_OPERATION_STATUS);
    const bool snapshotOk = statusOk && ReadNativeRx(observer, true, false);
    CloseHandle(observer.device);
    return statusOk && snapshotOk ? 0 : 4;
}

int RunRxCamReceiveWindow(int argc) {
    if(argc!=2)return 2;
    NET_LUID luid{};
    NET_IFINDEX index=0;
    if(!ResolveTarget(luid,index))return 3;
    const auto sta=ReadConnection(L"receive_before");
    if(!sta.connected||sta.channel!=44)return 12;
    RxCamLease lease(luid,index);
    if(!lease.enable())return 4;
    std::wcout<<L"receive_cam_ready=1\naction_requests=0\n"<<std::flush;
    bool healthy=true;
    const auto deadline=GetTickCount64()+120000;
    while(GetTickCount64()<deadline) {
        if(!lease.refresh()){healthy=false;break;}
        Sleep(100);
    }
    const bool restored=lease.close();
    std::wcout<<L"cam_restore_exit="<<(restored?0:14)<<std::endl;
    return !restored?14:healthy?0:4;
}

int RunNativeRxCheck(int argc, wchar_t** argv) {
    const bool scan = argc == 3 && wcscmp(argv[2], L"--scan") == 0;
    const bool passive = argc == 3 && wcscmp(argv[2], L"--passive") == 0;
    if (argc != 2 && !scan && !passive) return 2;
    NET_LUID luid{};
    NET_IFINDEX index = 0;
    if (!ResolveTarget(luid, index)) return 3;
    NativeRxLease lease(luid, index);
    if (!lease.enable(passive)) return 4;
    ScanNotificationContext notification{lease.observer().guid, nullptr, 0};
    DWORD registerError = ERROR_SUCCESS;
    DWORD scanError = ERROR_SUCCESS;
    bool captured = true;
    if (scan) {
        notification.event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!notification.event) return 4;
        registerError = WlanRegisterNotification(lease.observer().wlan,
            WLAN_NOTIFICATION_SOURCE_ACM, FALSE, OnScanNotification,
            &notification, nullptr, nullptr);
        if (registerError == ERROR_SUCCESS)
            scanError = WlanScan(lease.observer().wlan, &lease.observer().guid,
                nullptr, nullptr, nullptr);
        std::wcout << L"native_scan_register_error=" << registerError
                   << L"\nnative_scan_request_error=" << scanError << L'\n';
        const ULONGLONG started = GetTickCount64();
        while (registerError == ERROR_SUCCESS && scanError == ERROR_SUCCESS &&
            GetTickCount64() - started < 10000) {
            if (!ReadNativeRx(lease.observer())) { captured = false; break; }
            Sleep(50);
        }
        DWORD unregisterError = ERROR_SUCCESS;
        if (registerError == ERROR_SUCCESS)
            unregisterError = WlanRegisterNotification(lease.observer().wlan, WLAN_NOTIFICATION_SOURCE_NONE,
                FALSE, nullptr, nullptr, nullptr, nullptr);
        std::wcout << L"native_scan_notification=" << notification.outcome
                   << L"\nnative_scan_unregister_error=" << unregisterError << L'\n';
        captured = captured && registerError == ERROR_SUCCESS &&
            scanError == ERROR_SUCCESS && notification.outcome == 1 && unregisterError == ERROR_SUCCESS;
    } else if (passive) {
        const auto deadline=GetTickCount64()+30000;
        do {
            if(!ReadNativeRx(lease.observer())){captured=false;break;}
            Sleep(50);
        }while(GetTickCount64()<deadline);
    } else Sleep(1000);
    captured = ReadNativeRx(lease.observer(), true) && captured;
    const bool restored = lease.close();
    // WlanCloseHandle drains notifications before the context/event disappear.
    if (notification.event) CloseHandle(notification.event);
    std::wcout << L"native_check_action_requests=0\nnative_restore_exit=" << (restored ? 0 : 14) << L'\n';
    if (!restored) return 14;
    return captured ? 0 : 4;
}
#endif

}

// Parse every manual assertion before target resolution or opening the device.
int wmain(int argc, wchar_t** argv) {
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
    if (argc == 3 && wcscmp(argv[1], L"ble-v2-advertise") == 0)
        return RunBleV2Advertise(argv[2]);
    if (argc > 1 && wcscmp(argv[1], L"poc-discovery") == 0)
        return RunPocDiscovery(argc, argv);
    if (argc > 1 && (wcscmp(argv[1], L"ap-coexistence-check") == 0 ||
        wcscmp(argv[1], L"ap-rx-cycles-ready") == 0 || wcscmp(argv[1], L"ap-rx-cycles-run") == 0 ||
        wcscmp(argv[1], L"ap-coexistence-ready") == 0 ||
        wcscmp(argv[1], L"ap-coexistence-run") == 0)) return RunApCoexistence(argc, argv);
#endif
    if (!SelectProbeAdapter()) return 3;
    if (argc >= 2 && wcscmp(argv[1], L"realtek-census") == 0) {
        const int result = RunRealtekCensus(argc, argv);
        if (result == 2) std::wcerr << L"usage: realtek-census <load_hex32> <filter> <action> <lifecycle> <port> <tid> <observation_generation> <challenge>\n";
        return result;
    }
    if (argc >= 2 && (wcscmp(argv[1], L"completion-gate-state") == 0 ||
        wcscmp(argv[1], L"completion-gate-evidence") == 0 ||
        wcscmp(argv[1], L"completion-gate-next") == 0)) {
        const int result = RunCompletionGateControl(argc, argv);
        if (result == 2) {
            std::wcerr << L"usage: completion-gate-state\n"
                << L"completion-gate-evidence <load_hex32> <filter> <action> <lifecycle> <port> <tid> <observation_generation> <challenge> realtek <observed_FILETIME_100ns> --nonbusy --held-list-empty --worker-ended --wdi-jobs-empty --wdi-commands-empty\n"
                << L"completion-gate-evidence <same_ids> wifi <observed_FILETIME_100ns> --wifi-maintained --no-reset --no-error\n"
                << L"completion-gate-next <same_ids> --confirm-next\n";
        }
        return result;
    }
    if (argc >= 2 && (wcscmp(argv[1], L"two-request-state") == 0 ||
        wcscmp(argv[1], L"two-request-permit") == 0))
        return RunTwoRequestControl(argc, argv);
    if (argc == 2 && wcscmp(argv[1], L"action-events") == 0)
        return ReadActionEvents();
    if (argc > 1 && wcscmp(argv[1], L"poc-repeat") == 0)
        return RunPocRepeat(argc, argv);
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
    if (argc == 2 && wcscmp(argv[1], L"data-query-state") == 0)
        return ReadDataQueryState();
    if (argc == 2 && wcscmp(argv[1], L"vendor-wps-clear") == 0) {
        NET_LUID luid{};NET_IFINDEX index=0;
        if(!ResolveTarget(luid,index))return 3;
        GUID guid{};HANDLE wlan=nullptr;DWORD version=0,size=0;PVOID value=nullptr;
        if(FAILED(CLSIDFromString(kGuidText,&guid))||
           WlanOpenHandle(2,nullptr,&version,&wlan)!=ERROR_SUCCESS)return 4;
        const auto error=WlanQueryInterface(wlan,&guid,wlan_intf_opcode_interface_state,
            nullptr,&size,&value,nullptr);
        const bool disconnected=error==ERROR_SUCCESS&&value&&size>=sizeof(WLAN_INTERFACE_STATE)&&
            *static_cast<WLAN_INTERFACE_STATE*>(value)==wlan_interface_state_disconnected;
        if(value)WlanFreeMemory(value);
        WlanCloseHandle(wlan,nullptr);
        if(!disconnected)return 12;
        if(ReadDataQueryState(true)!=0)return 4;
        VendorWpsTrial cleanup;
        return cleanup.clear_existing(luid,index)?0:14;
    }
    if (argc == 2 && (wcscmp(argv[1], L"data-query-trace") == 0 ||
        wcscmp(argv[1], L"data-query-correlation") == 0)) {
        NET_LUID luid{};
        NET_IFINDEX index = 0;
        if (!ResolveTarget(luid, index)) return 3;
        return wcscmp(argv[1], L"data-query-trace") == 0
            ? tx10ub::probe::ReadDataQueryTrace(kDevice, index, luid.Value)
            : tx10ub::probe::ReadDataQueryCorrelation(kDevice, index, luid.Value);
    }
    if (argc == 2 && wcscmp(argv[1], L"sta-status") == 0)
        return ReadStationStatus();
    if (argc > 1 && wcscmp(argv[1], L"sta-connect") == 0)
        return RunStaConnect(argc, argv, kGuidText);
    if (argc > 1 && wcscmp(argv[1], L"rx-cam-receive-window") == 0)
        return RunRxCamReceiveWindow(argc);
    if (argc > 1 && wcscmp(argv[1], L"native-rx-check") == 0)
        return RunNativeRxCheck(argc, argv);
    if (argc > 1 && wcscmp(argv[1], L"native-rx-status") == 0)
        return RunNativeRxStatus(argc);
    if (argc > 1 && wcscmp(argv[1], L"poc-awdl-action") == 0)
        return RunPocAwdlAction(argc, argv);
    if (argc > 1 && wcscmp(argv[1], L"poc-awdl-raw-action") == 0)
        return RunPocRawAwdlAction(argc, argv);
#endif
    if (argc > 1 && wcscmp(argv[1], L"poc-action") == 0)
        return RunPocAction(argc, argv);
    if (argc > 1 && (wcscmp(argv[1], L"experimental-action") == 0 ||
                     wcscmp(argv[1], L"manual-internal-action") == 0 ||
                     wcscmp(argv[1], L"experimental-abort") == 0 ||
                     wcscmp(argv[1], L"experimental-status") == 0)) {
        return RunExperimentalAction(argc, argv);
    }
    if (argc < 2 || argc > 4) {
        std::wcerr << L"usage: Tx10ubProbe.exe diagnostic | observe | scan | probe0 | probe1 <observed-port-id> <new-response-file>\n";
        return 2;
    }
    ULONG kind = AWDLWIN_TX_PROBE_DIAGNOSTIC;
    bool rxReadback=false;
    USHORT portId = 0;
    if (wcscmp(argv[1], L"diagnostic") == 0 && argc == 2) {
        kind = AWDLWIN_TX_PROBE_DIAGNOSTIC;
    } else if (wcscmp(argv[1], L"probe0") == 0 && argc == 2) {
        kind = AWDLWIN_TX_PROBE_VENDOR_ID;
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
    } else if (wcscmp(argv[1], L"rx-filter-readback") == 0 && argc == 2) {
        kind = AWDLWIN_TX_PROBE_RX_FILTER_IHV;rxReadback=true;
    } else if (wcscmp(argv[1], L"rx-data-filter-readback") == 0 && argc == 2) {
        kind = AWDLWIN_TX_PROBE_RX_DATA_FILTER_IHV;rxReadback=true;
    } else if (wcscmp(argv[1], L"rx-data-filter-read-ihv") == 0 && argc == 2) {
        kind = AWDLWIN_TX_PROBE_RX_DATA_FILTER_IHV;
    } else if (wcscmp(argv[1], L"rx-cam-ctrl-read-ihv") == 0 && argc == 2) {
        kind = AWDLWIN_TX_PROBE_RX_CAM_CTRL_IHV;
    } else if (wcscmp(argv[1], L"rx-cam-dis-read-ihv") == 0 && argc == 2) {
        kind = AWDLWIN_TX_PROBE_RX_CAM_DIS_IHV;
    } else if (wcscmp(argv[1], L"rx-filter-read-ihv") == 0 && argc == 2) {
        kind = AWDLWIN_TX_PROBE_RX_FILTER_IHV;
#endif
    } else if (wcscmp(argv[1], L"observe") == 0 && argc == 2) {
        kind = AWDLWIN_TX_PROBE_DIAGNOSTIC;
    } else if (wcscmp(argv[1], L"scan") == 0 && argc == 2) {
        kind = AWDLWIN_TX_PROBE_DIAGNOSTIC;
    } else if (wcscmp(argv[1], L"probe1") == 0 && argc == 4 && ParsePortId(argv[2], portId)) {
        kind = AWDLWIN_TX_PROBE_WDI_STATISTICS;
    } else {
        std::wcerr << L"invalid_arguments\n";
        return 2;
    }

    NET_LUID luid{};
    NET_IFINDEX index = 0;
    if (!ResolveTarget(luid, index)) {
        std::wcerr << L"target_identity_mismatch; no OID issued\n";
        return 3;
    }
    std::wcout << L"target_interface_guid=" << kGuidText << L'\n'
               << L"target_net_luid=" << luid.Value << L'\n'
               << L"target_if_index=" << index << L'\n'
               << L"filter_component_id=AWDLWIN_TX10UB_PROBE\n";

    if (wcscmp(argv[1], L"observe") == 0) return tx10ub::probe::ReadObservations(kDevice);
    if (wcscmp(argv[1], L"scan") == 0) return ScanTarget(kGuidText);

    HANDLE device = CreateFileW(kDevice, GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                OPEN_EXISTING, 0, nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        std::wcerr << L"device_open_error=" << GetLastError() << L'\n';
        return 4;
    }
    AWDLWIN_G2_REQUEST_V1 request{};
    request.Version = AWDLWIN_G2_VERSION;
    request.Flags = kind == AWDLWIN_TX_PROBE_DIAGNOSTIC
        ? AWDLWIN_G2_REQUEST_FLAG_DIAGNOSTIC_ONLY : rxReadback?AWDLWIN_G2_REQUEST_FLAG_RX_READBACK:0;
    request.TargetIfIndex = index;
    request.TargetNetLuidValue = luid.Value;
    request.ProbeKind = kind;
    request.ObservedPortId = portId;

    auto result = std::make_unique<AWDLWIN_G2_RESULT_V1>();
    DWORD bytesReturned = 0;
    DWORD queryCode = IOCTL_AWDLWIN_ISSUE_READONLY_WDI_QUERY;
    const BOOL ok = DeviceIoControl(device, queryCode,
                                    &request, sizeof(request), result.get(), sizeof(*result),
                                    &bytesReturned, nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(device);
    std::wcout << L"ioctl_success=" << (ok ? 1 : 0) << L'\n'
               << L"ioctl_error=" << error << L'\n'
               << L"bytes_returned=" << bytesReturned << L'\n';
    if (bytesReturned < offsetof(AWDLWIN_G2_RESULT_V1, Response) ||
        result->Size != sizeof(*result) || result->Version != AWDLWIN_G2_VERSION) {
        std::wcerr << L"invalid_result\n";
        return 5;
    }
    ULONG inputLength = kind == AWDLWIN_TX_PROBE_WDI_STATISTICS
        ? AWDLWIN_TX_WDI_HEADER_SIZE : 0;
    ULONG outputLength = kind == AWDLWIN_TX_PROBE_VENDOR_ID
        ? sizeof(ULONG) : (kind == AWDLWIN_TX_PROBE_WDI_STATISTICS
            ? AWDLWIN_TX_RESPONSE_CAPACITY : 0);
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
    if (AWDLWIN_IS_RX_REGISTER_PROBE(kind)) {
        inputLength = 68;
        outputLength = AWDLWIN_TX_RESPONSE_CAPACITY;
    }
#endif
    std::wcout << L"target_match_count=" << result->TargetMatchCount << L'\n'
               << L"classification=" << result->Classification << L'\n'
               << L"oid_issued=" << result->OidIssued << L'\n'
               << L"probe_kind=" << result->ProbeKind << L'\n'
               << L"request_type=" << result->RequestType << L'\n'
               << L"input_buffer_length=" << inputLength << L'\n'
               << L"output_buffer_length=" << outputLength << L'\n'
               << L"port_id=" << result->PortId << L'\n'
               << L"transaction_id=" << result->TransactionId << L'\n'
               << L"completion_mode=" << result->CompletionMode << L'\n'
               << L"completion_callback_observed=" << result->CompletionCallbackObserved << L'\n'
               << L"bytes_written=" << result->BytesWritten << L'\n'
               << L"bytes_read=" << result->BytesRead << L'\n'
               << L"bytes_needed=" << result->BytesNeeded << L'\n'
               << L"response_length=" << result->ResponseLength << L'\n'
               << L"tlv_count=" << result->TlvCount << L'\n'
               << L"mac_statistics_tlvs=" << result->MacStatisticsTlvCount << L'\n'
               << L"phy_statistics_tlvs=" << result->PhyStatisticsTlvCount << L'\n';
    PrintHex(L"oid", result->Oid);
    PrintHex(L"submit_ndis_status", result->SubmitNdisStatus);
    PrintHex(L"final_ndis_status", result->FinalNdisStatus);
    PrintHex(L"wdi_header_status", result->WdiHeaderStatus);
    PrintHex(L"vendor_id", result->VendorId);
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
    if (AWDLWIN_IS_RX_REGISTER_PROBE(kind) &&
        ok && bytesReturned >= offsetof(AWDLWIN_G2_RESULT_V1,Response)+68 &&
        result->Classification == AwdlWinG2Reachable && result->ResponseLength == 68 &&
        result->TargetMatchCount==1 && result->OidIssued==1 && result->TransactionId!=0) {
        ULONG filter = 0;
        memcpy(&filter, result->Response + 60, sizeof(filter));
        PrintHex(kind == AWDLWIN_TX_PROBE_RX_DATA_FILTER_IHV ? L"rx_data_filter_ce2c" :
                 kind == AWDLWIN_TX_PROBE_RX_CAM_CTRL_IHV ? L"rx_cam_ctrl_ce34" :
                 kind == AWDLWIN_TX_PROBE_RX_CAM_DIS_IHV ? L"rx_cam_dis_ce38" : L"rx_filter_ce20", filter);
    } else if(rxReadback) {
        return 9;
    }

#endif
    if (!ok) return 6;
    if (kind == AWDLWIN_TX_PROBE_WDI_STATISTICS && result->ResponseLength != 0 &&
        !SaveResponse(argv[3], *result)) return 7;
    if (kind == AWDLWIN_TX_PROBE_DIAGNOSTIC)
        return result->Classification == AwdlWinG2TargetSelected &&
               result->TargetMatchCount == 1 ? 0 : 8;
    return result->Classification == AwdlWinG2Reachable ? 0 : 9;
}
