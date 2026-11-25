#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "Tx10ubHost.h"
#include "Tx10ubDriverTrust.h"
#include "Tx10ubDirectIhv.h"
#include "Tx10ubNetworkRestart.h"
#include "Tx10ubRadioHandoff.h"
#include "Tx10ubRadioLease.h"
#include "Tx10ubProbeEvents.h"
#include "DropPorterBroker.h"
#include "Tx10ubSendFiles.h"
#include "Tx10ubReceiveState.h"
#include "DropPorterSupervisorState.h"
#include "DropPorterSessionMarkers.h"
#include "DropPorterHelperFiles.h"
#include "DropPorterRequestFile.h"
#include "DropPorterSendSelection.h"
#include "DropPorterTargetFiles.h"

#include <windows.h>
#include <bcrypt.h>
#include <aclapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <sddl.h>
#include <softpub.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <exception>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {
namespace supervisor = dropporter::supervisor;
namespace markers = dropporter::session_markers;
namespace request_file = dropporter::request_file;
namespace target_files = dropporter::target_files;
namespace events = tx10ub::probe_events;

namespace fs = std::filesystem;
using tx10ub::host::Adapter;
using tx10ub::host::BbState;
using tx10ub::host::Channel;
using tx10ub::host::VendorTransport;
using tx10ub::host::WifiRadio;
using tx10ub::host::WifiSnapshot;

constexpr wchar_t kServiceName[] = L"AWDLWinTx10ubProbe";
constexpr wchar_t kTargetNetLuid[] = L"TargetNetLuid";
constexpr char kProbeReadyPrefix[] = "data_query_running=1 restart_ready=1 pool_ready=1 backfill_known=1 ";

[[noreturn]] void Fail(const std::string& message) { throw std::runtime_error(message); }

[[noreturn]] void FailWin32(const char* action, DWORD error = GetLastError()) {
    throw std::system_error(static_cast<int>(error), std::system_category(), action);
}

class Handle {
public:
    Handle() = default;
    explicit Handle(HANDLE value) : value_(value) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value_(other.release()) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) reset(other.release());
        return *this;
    }
    HANDLE get() const { return value_; }
    explicit operator bool() const { return value_ && value_ != INVALID_HANDLE_VALUE; }
    HANDLE release() { HANDLE value = value_; value_ = nullptr; return value; }
    void reset(HANDLE value = nullptr) {
        if (*this) CloseHandle(value_);
        value_ = value;
    }
private:
    HANDLE value_{};
};

class ScHandle {
public:
    explicit ScHandle(SC_HANDLE value = nullptr) : value_(value) {}
    ~ScHandle() { if (value_) CloseServiceHandle(value_); }
    ScHandle(const ScHandle&) = delete;
    ScHandle& operator=(const ScHandle&) = delete;
    SC_HANDLE get() const { return value_; }
    void reset(SC_HANDLE value = nullptr) {
        if (value_) CloseServiceHandle(value_);
        value_ = value;
    }
private:
    SC_HANDLE value_{};
};

class OwnedMutex {
public:
    explicit OwnedMutex(const wchar_t* name, DWORD waitMs = 0) {
        handle_.reset(CreateMutexW(nullptr, FALSE, name));
        if (!handle_) FailWin32("mutex_create_failed");
        const DWORD result = WaitForSingleObject(handle_.get(), waitMs);
        if (result == WAIT_OBJECT_0 || result == WAIT_ABANDONED) owns_ = true;
        else if (result == WAIT_TIMEOUT) Fail("another_tx10ub_operation_is_running");
        else FailWin32("mutex_wait_failed");
    }
    ~OwnedMutex() { if (owns_) ReleaseMutex(handle_.get()); }
    OwnedMutex(const OwnedMutex&) = delete;
    OwnedMutex& operator=(const OwnedMutex&) = delete;
private:
    Handle handle_;
    bool owns_{};
};

struct Request {
    std::wstring filePath;
    std::vector<std::wstring> filePaths;
    std::wstring candidateName;
    DWORD ownerPid{};
    bool receive{};
    bool selectFiles{};
    bool ndiscap{true};
    unsigned wideChannelMhz{40};
    unsigned receiveAckRateMbps{};
};

std::string ReadUtf8File(const fs::path& path, size_t maximum) {
    std::ifstream input(path, std::ios::binary);
    if (!input) Fail("request_file_open_failed");
    input.seekg(0, std::ios::end);
    const auto size = input.tellg();
    if (size < 0 || static_cast<std::uint64_t>(size) > maximum) Fail("request_file_size_invalid");
    input.seekg(0, std::ios::beg);
    std::string value(static_cast<size_t>(size), '\0');
    input.read(value.data(), static_cast<std::streamsize>(value.size()));
    if (!input && !value.empty()) Fail("request_file_read_failed");
    if (value.size() >= 3 && static_cast<unsigned char>(value[0]) == 0xef &&
        static_cast<unsigned char>(value[1]) == 0xbb && static_cast<unsigned char>(value[2]) == 0xbf) {
        Fail("request_file_must_be_utf8_without_bom");
    }
    return value;
}

class JsonRequestParser {
public:
    explicit JsonRequestParser(std::string_view input) : input_(input) {}
    Request Parse() {
        Request result{};
        bool fileSeen = false, candidateSeen = false, ownerSeen = false, modeSeen = false, transportSeen = false;
        bool wideChannelSeen = false;
        Space(); Require('{'); Space();
        if (Take('}')) Fail("request_object_empty");
        for (;;) {
            const auto key = String(); Space(); Require(':'); Space();
            if (key == request_file::FilePath) {
                if (fileSeen) Fail("duplicate_request_field");
                result.filePath = ToWide(String()); fileSeen = true;
            } else if (key == request_file::FilePaths) {
                if (fileSeen) Fail("duplicate_request_field");
                fileSeen = true;
                Require('['); Space();
                for (;;) {
                    if (result.filePaths.size() == tx10ub::send_files::MaxFiles) Fail("request_file_count_invalid");
                    auto path = ToWide(String());
                    if (!tx10ub::send_files::ValidPath(path)) Fail("request_file_path_invalid");
                    result.filePaths.push_back(std::move(path));
                    Space();
                    if (Take(']')) break;
                    Require(','); Space();
                }
            } else if (key == request_file::CandidateName) {
                if (candidateSeen) Fail("duplicate_request_field");
                result.candidateName = ToWide(String()); candidateSeen = true;
            } else if (key == request_file::OwnerPid) {
                if (ownerSeen) Fail("duplicate_request_field");
                const auto number = Number();
                if (number == 0 || number > MAXDWORD) Fail("owner_pid_invalid");
                result.ownerPid = static_cast<DWORD>(number); ownerSeen = true;
            } else if (key == request_file::Mode) {
                if (modeSeen) Fail("duplicate_request_field");
                const auto mode = String();
                if (mode == request_file::ReceiveMode) result.receive = true;
                else if (mode == request_file::SendMode) result.selectFiles = true;
                else Fail("request_mode_invalid");
                modeSeen = true;
            } else if (key == request_file::Transport) {
                if (transportSeen) Fail("duplicate_request_field");
                const auto transport = String();
                if (transport == request_file::UsbTransport) result.ndiscap = false;
                else if (transport == request_file::NdiscapTransport) result.ndiscap = true;
                else Fail("request_transport_invalid");
                transportSeen = true;
            } else if (key == request_file::WideChannelMhz) {
                if (wideChannelSeen) Fail("duplicate_request_field");
                const auto width = Number();
                if (width != 40 && width != 80) Fail("request_wide_channel_invalid");
                result.wideChannelMhz = static_cast<unsigned>(width);
                wideChannelSeen = true;
            } else if (key == request_file::ReceiveAckRateMbps) {
                if (result.receiveAckRateMbps) Fail("duplicate_request_field");
                const auto rate = Number();
                if (rate != 12 && rate != 24) Fail("request_receive_ack_rate_invalid");
                result.receiveAckRateMbps = static_cast<unsigned>(rate);
            } else {
                Fail("request_field_unknown");
            }
            Space();
            if (Take('}')) break;
            Require(','); Space();
        }
        Space(); if (position_ != input_.size()) Fail("request_trailing_data");
        if ((!fileSeen && !result.selectFiles) || !candidateSeen || !ownerSeen) Fail("request_required_field_missing");
        if ((result.receive && !result.filePaths.empty()) || (result.selectFiles && fileSeen)) Fail("request_mode_invalid");
        if (result.receiveAckRateMbps && !result.receive) Fail("request_receive_ack_rate_invalid");
        return result;
    }
private:
    void Space() { while (position_ < input_.size() && (input_[position_] == ' ' || input_[position_] == '\t' ||
        input_[position_] == '\r' || input_[position_] == '\n')) ++position_; }
    bool Take(char ch) { if (position_ < input_.size() && input_[position_] == ch) { ++position_; return true; } return false; }
    void Require(char ch) { if (!Take(ch)) Fail("request_json_invalid"); }
    static void AppendUtf8(std::string& output, unsigned codepoint) {
        if (codepoint <= 0x7f) output.push_back(static_cast<char>(codepoint));
        else if (codepoint <= 0x7ff) {
            output.push_back(static_cast<char>(0xc0 | (codepoint >> 6)));
            output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
        } else if (codepoint <= 0xffff) {
            output.push_back(static_cast<char>(0xe0 | (codepoint >> 12)));
            output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
            output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
        } else {
            output.push_back(static_cast<char>(0xf0 | (codepoint >> 18)));
            output.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3f)));
            output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
            output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
        }
    }
    unsigned Hex4() {
        if (position_ + 4 > input_.size()) Fail("request_json_escape_invalid");
        unsigned value = 0;
        for (unsigned i = 0; i != 4; ++i) {
            const char ch = input_[position_++];
            value <<= 4;
            if (ch >= '0' && ch <= '9') value |= static_cast<unsigned>(ch - '0');
            else if (ch >= 'a' && ch <= 'f') value |= static_cast<unsigned>(ch - 'a' + 10);
            else if (ch >= 'A' && ch <= 'F') value |= static_cast<unsigned>(ch - 'A' + 10);
            else Fail("request_json_escape_invalid");
        }
        return value;
    }
    std::string String() {
        Require('"');
        std::string result;
        while (position_ < input_.size()) {
            const unsigned char ch = static_cast<unsigned char>(input_[position_++]);
            if (ch == '"') return result;
            if (ch < 0x20) Fail("request_json_string_control_character");
            if (ch != '\\') { result.push_back(static_cast<char>(ch)); continue; }
            if (position_ >= input_.size()) Fail("request_json_escape_invalid");
            const char escape = input_[position_++];
            switch (escape) {
            case '"': result.push_back('"'); break;
            case '\\': result.push_back('\\'); break;
            case '/': result.push_back('/'); break;
            case 'b': result.push_back('\b'); break;
            case 'f': result.push_back('\f'); break;
            case 'n': result.push_back('\n'); break;
            case 'r': result.push_back('\r'); break;
            case 't': result.push_back('\t'); break;
            case 'u': {
                unsigned codepoint = Hex4();
                if (codepoint >= 0xd800 && codepoint <= 0xdbff) {
                    if (position_ + 2 > input_.size() || input_[position_] != '\\' || input_[position_ + 1] != 'u')
                        Fail("request_json_surrogate_invalid");
                    position_ += 2;
                    const unsigned low = Hex4();
                    if (low < 0xdc00 || low > 0xdfff) Fail("request_json_surrogate_invalid");
                    codepoint = 0x10000 + ((codepoint - 0xd800) << 10) + (low - 0xdc00);
                } else if (codepoint >= 0xdc00 && codepoint <= 0xdfff) Fail("request_json_surrogate_invalid");
                AppendUtf8(result, codepoint);
                break;
            }
            default: Fail("request_json_escape_invalid");
            }
        }
        Fail("request_json_string_unterminated");
    }
    std::uint64_t Number() {
        const size_t start = position_;
        while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') ++position_;
        if (start == position_ || (position_ - start > 1 && input_[start] == '0')) Fail("request_number_invalid");
        std::uint64_t number = 0;
        const auto parsed = std::from_chars(input_.data() + start, input_.data() + position_, number);
        if (parsed.ec != std::errc{} || parsed.ptr != input_.data() + position_) Fail("request_number_invalid");
        return number;
    }
    static std::wstring ToWide(const std::string& value) {
        if (value.empty()) return {};
        const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), nullptr, 0);
        if (!count) FailWin32("request_utf8_invalid");
        std::wstring result(static_cast<size_t>(count), L'\0');
        if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), result.data(), count)) FailWin32("request_utf8_invalid");
        return result;
    }
    std::string_view input_;
    size_t position_{};
};

struct Context {
    fs::path requestPath, requestDir, candidate, capture, filePath;
    std::vector<fs::path> sendPaths;
    fs::path statusPath, progressPath, resultPath, cancelPath;
    Request request;
    Handle owner;
    Handle ownerImpersonationToken;
    std::wstring ownerSid;
    fs::path ownerLocalAppData;
    fs::path executableDir, probePath, workerPath, sysPath;
};

enum JournalFlag : ULONG {
    JournalWifiCaptured = 1u << 0,
    JournalServiceStartPending = 1u << 1,
    JournalServiceStarted = 1u << 2,
    JournalDisconnectPending = 1u << 3,
    JournalDisconnected = 1u << 4,
    JournalRxReadPending = 1u << 5,
    JournalRadioBaselineCaptured = 1u << 6,
    JournalWpsClearPending = 1u << 7,
    JournalWpsClearSettled = 1u << 8,
    JournalAutoconfPending = 1u << 9,
    JournalAutoconfChanged = 1u << 10,
    JournalMonitorPending = 1u << 11,
    JournalMonitorOwned = 1u << 12,
    JournalChannelPending = 1u << 13,
    JournalChannelOwned = 1u << 14,
    JournalProbeStartPending = 1u << 15,
    JournalProbeStarted = 1u << 16,
    JournalShutdownConfirmed = 1u << 17,
    JournalRestoreComplete = 1u << 18,
    JournalLowerFenceUnconfirmed = 1u << 19,
    JournalVendorOperationPending = 1u << 20,
    JournalRadioRestoreVerificationPending = 1u << 21,
    JournalDirectIhv = 1u << 22,
    JournalNetworkRestartPending = 1u << 23,
    JournalSharedDriverImage = 1u << 24,
    JournalRxBaselineMatchesSavedWifi = 1u << 25,
    JournalTx20u1281DriverImage = 1u << 26,
    JournalTx20u1132DriverImage = 1u << 27
};

#pragma pack(push, 1)
struct RuntimeJournal {
    ULONG magic{};
    ULONG version{};
    ULONG size{};
    DWORD ownerPid{};
    DWORD controllerPid{};
    DWORD controllerCreatedLow{};
    DWORD controllerCreatedHigh{};
    char ownerSid[184]{};
    char controllerSid[184]{};
    wchar_t ownerLocalAppData[32768]{};
    wchar_t candidateName[64]{};
    GUID adapterGuid{};
    ULONGLONG adapterLuid{};
    NET_IFINDEX adapterIndex{};
    ULONG wifiState{};
    ULONG wifiAutoconf{};
    ULONG wifiChannel{};
    UCHAR wifiBssid[6]{};
    wchar_t wifiProfile[WLAN_MAX_NAME_LENGTH]{};
    wchar_t originalServiceImagePath[32768]{};
    DWORD serviceStartType{};
    DWORD parameterKeyExisted{};
    DWORD parameterValuePresent{};
    ULONGLONG originalTargetNetLuid{};
    wchar_t runtimeSysPath[32768]{};
    ULONGLONG runtimeTargetNetLuid{};
    ULONG flags{};
    ULONG originalBbEncoded{};
    ULONG originalBbWidth{};
    ULONG originalBbPrimaryIndex{};
    ULONG originalBbSmallBand{};
    ULONG originalBbIs24Ghz{};
    ULONG originalChannelBand{};
    ULONG originalChannelPrimary{};
    ULONG originalChannelWidth{};
    ULONG originalChannelOffset{};
    ULONG originalRxFilter{};
    ULONG originalRxDataFilter{};
    wchar_t adapterInstanceId[512]{};
    DOT11_SSID wifiSsid{};
};
#pragma pack(pop)

constexpr ULONG kRuntimeJournalMagic = 0x31584444; // DDX1
constexpr ULONG kRuntimeJournalVersion = 3;
constexpr size_t kRuntimeJournalV1Size = offsetof(RuntimeJournal, adapterInstanceId);
constexpr size_t kRuntimeJournalV2Size = offsetof(RuntimeJournal, wifiSsid);

void WriteAtomic(const fs::path& path, const std::string& content, bool flushToDisk = true);

template<size_t Count>
void CopyJournalWide(wchar_t (&destination)[Count], const std::wstring& value, const char* field) {
    if (value.size() >= Count) Fail(std::string("journal_field_too_long_") + field);
    std::copy(value.begin(), value.end(), destination);
    destination[value.size()] = L'\0';
}

template<size_t Count>
std::wstring ReadJournalWide(const wchar_t (&source)[Count], const char* field) {
    const auto end = std::find(source, source + Count, L'\0');
    if (end == source + Count) Fail(std::string("journal_field_unterminated_") + field);
    return std::wstring(source, end);
}

std::wstring TokenSidString(HANDLE token) {
    DWORD bytes = 0;
    (void)GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes < sizeof(TOKEN_USER)) {
        FailWin32("request_owner_sid_size_failed");
    }
    std::vector<std::byte> storage(bytes);
    if (!GetTokenInformation(token, TokenUser, storage.data(), bytes, &bytes)) {
        FailWin32("request_owner_sid_read_failed");
    }
    const auto* user = reinterpret_cast<const TOKEN_USER*>(storage.data());
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(user->User.Sid, &text)) FailWin32("request_owner_sid_format_failed");
    std::wstring result(text);
    LocalFree(text);
    return result;
}

std::wstring FileOwnerSidString(const fs::path& path) {
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD error = GetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr, nullptr, &descriptor);
    if (error != ERROR_SUCCESS) FailWin32("session_directory_owner_query_failed", error);
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(owner, &text)) {
        const DWORD formatError = GetLastError();
        if (descriptor) LocalFree(descriptor);
        FailWin32("session_directory_owner_format_failed", formatError);
    }
    std::wstring result(text);
    LocalFree(text);
    if (descriptor) LocalFree(descriptor);
    return result;
}

bool MatchesWellKnownSid(PSID sid, WELL_KNOWN_SID_TYPE type) {
    std::array<std::byte, SECURITY_MAX_SID_SIZE> storage{};
    DWORD bytes = static_cast<DWORD>(storage.size());
    return CreateWellKnownSid(type, nullptr, storage.data(), &bytes) && EqualSid(sid, storage.data());
}

void ValidatePrivateRuntimeDirectorySecurity(const fs::path& path) {
    PSID owner = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD error = GetNamedSecurityInfoW(const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &dacl, nullptr, &descriptor);
    if (error != ERROR_SUCCESS) FailWin32("runtime_candidate_security_query_failed", error);
    auto release = [&]() { if (descriptor) LocalFree(descriptor); };
    if (!owner || (!MatchesWellKnownSid(owner, WinBuiltinAdministratorsSid) &&
        !MatchesWellKnownSid(owner, WinLocalSystemSid))) {
        release();
        Fail("runtime_candidate_owner_untrusted");
    }
    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision = 0;
    if (!GetSecurityDescriptorControl(descriptor, &control, &revision) ||
        (control & SE_DACL_PROTECTED) == 0 || !dacl || !IsValidAcl(dacl)) {
        release();
        Fail("runtime_candidate_dacl_untrusted");
    }
    ACL_SIZE_INFORMATION aclInfo{};
    if (!GetAclInformation(dacl, &aclInfo, sizeof(aclInfo), AclSizeInformation) || aclInfo.AceCount != 2) {
        release();
        Fail("runtime_candidate_dacl_untrusted");
    }
    bool administrators = false;
    bool system = false;
    for (DWORD index = 0; index < aclInfo.AceCount; ++index) {
        void* rawAce = nullptr;
        if (!GetAce(dacl, index, &rawAce)) {
            release();
            FailWin32("runtime_candidate_dacl_read_failed");
        }
        const auto* header = static_cast<const ACE_HEADER*>(rawAce);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
            header->AceFlags != (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)) {
            release();
            Fail("runtime_candidate_dacl_untrusted");
        }
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(rawAce);
        PSID aceSid = const_cast<DWORD*>(&ace->SidStart);
        if (ace->Mask != FILE_ALL_ACCESS) {
            release();
            Fail("runtime_candidate_dacl_untrusted");
        }
        if (MatchesWellKnownSid(aceSid, WinBuiltinAdministratorsSid) && !administrators) administrators = true;
        else if (MatchesWellKnownSid(aceSid, WinLocalSystemSid) && !system) system = true;
        else {
            release();
            Fail("runtime_candidate_dacl_untrusted");
        }
    }
    release();
    if (!administrators || !system) Fail("runtime_candidate_dacl_untrusted");
}

void CreatePrivateRuntimeDirectory(const fs::path& path, bool* createdByCaller = nullptr) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr)) {
        FailWin32("runtime_directory_security_create_failed");
    }
    SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
    const BOOL created = CreateDirectoryW(path.c_str(), &security);
    const DWORD error = created ? ERROR_SUCCESS : GetLastError();
    LocalFree(descriptor);
    if (!created) FailWin32("runtime_candidate_directory_create_failed", error);
    if (createdByCaller) *createdByCaller = true;
    ValidatePrivateRuntimeDirectorySecurity(path);
}

void WriteRuntimeJournal(const fs::path& path, RuntimeJournal& journal) {
    journal.magic = kRuntimeJournalMagic;
    journal.version = kRuntimeJournalVersion;
    journal.size = static_cast<ULONG>(sizeof(journal));
    const std::string bytes(reinterpret_cast<const char*>(&journal), sizeof(journal));
    WriteAtomic(path, bytes);
}

void ReadRuntimeJournal(const fs::path& path, RuntimeJournal& journal) {
    std::ifstream input(path, std::ios::binary);
    if (!input) Fail("runtime_recovery_journal_unavailable");
    input.seekg(0, std::ios::end);
    const auto size = input.tellg();
    if (size != static_cast<std::streamoff>(sizeof(RuntimeJournal)) &&
        size != static_cast<std::streamoff>(kRuntimeJournalV2Size) &&
        size != static_cast<std::streamoff>(kRuntimeJournalV1Size)) Fail("runtime_recovery_journal_size_invalid");
    input.seekg(0, std::ios::beg);
    journal = {};
    input.read(reinterpret_cast<char*>(&journal), static_cast<std::streamsize>(size));
    const bool legacy = journal.version == 1 && journal.size == kRuntimeJournalV1Size &&
        size == static_cast<std::streamoff>(kRuntimeJournalV1Size) && (journal.flags & ~((1u << 22) - 1u)) == 0;
    const bool previous = journal.version == 2 && journal.size == kRuntimeJournalV2Size &&
        size == static_cast<std::streamoff>(kRuntimeJournalV2Size);
    const bool current = journal.version == kRuntimeJournalVersion && journal.size == sizeof(journal) &&
        size == static_cast<std::streamoff>(sizeof(journal));
    if (!input || journal.magic != kRuntimeJournalMagic || (!legacy && !previous && !current) ||
        journal.wifiSsid.uSSIDLength > DOT11_SSID_MAX_LENGTH)
        Fail("runtime_recovery_journal_header_invalid");
}

bool HasJournalFlag(const RuntimeJournal& journal, JournalFlag flag) {
    return (journal.flags & static_cast<ULONG>(flag)) != 0;
}

std::string JournalAscii(const char (&value)[184], const char* field) {
    const auto end = std::find(value, value + sizeof(value), '\0');
    if (end == value + sizeof(value)) Fail(std::string("journal_field_unterminated_") + field);
    return std::string(value, end);
}

void CopyJournalAscii(char (&destination)[184], const std::wstring& value, const char* field) {
    if (value.size() >= sizeof(destination)) Fail(std::string("journal_field_too_long_") + field);
    for (size_t i = 0; i < value.size(); ++i) {
        if (value[i] > 0x7f) Fail(std::string("journal_field_not_ascii_") + field);
        destination[i] = static_cast<char>(value[i]);
    }
    destination[value.size()] = '\0';
}

void SetJournalFlag(RuntimeJournal& journal, JournalFlag flag, bool value) {
    if (value) journal.flags |= static_cast<ULONG>(flag);
    else journal.flags &= ~static_cast<ULONG>(flag);
}

tx10ub::host::DriverImage ReadJournalDriverImage(const RuntimeJournal& journal) {
    using tx10ub::host::DriverImage;
    const bool shared = HasJournalFlag(journal, JournalSharedDriverImage);
    const bool tx20u1281 = HasJournalFlag(journal, JournalTx20u1281DriverImage);
    const bool tx20u1132 = HasJournalFlag(journal, JournalTx20u1132DriverImage);
    if (static_cast<unsigned>(shared) + tx20u1281 + tx20u1132 > 1)
        Fail("runtime_recovery_journal_state_invalid");
    if (tx20u1132) return DriverImage::Tx20u1132;
    if (tx20u1281) return DriverImage::Tx20u1281;
    return shared ? DriverImage::Shared : DriverImage::Stock;
}

class OwnerImpersonation {
public:
    explicit OwnerImpersonation(HANDLE token) {
        if (!ImpersonateLoggedOnUser(token)) FailWin32("request_owner_impersonation_failed");
        active_ = true;
    }
    ~OwnerImpersonation() {
        if (active_ && !RevertToSelf()) {
            TerminateProcess(GetCurrentProcess(), ERROR_ACCESS_DENIED);
            std::terminate();
        }
    }
    OwnerImpersonation(const OwnerImpersonation&) = delete;
    OwnerImpersonation& operator=(const OwnerImpersonation&) = delete;
    void Revert() {
        if (active_ && !RevertToSelf()) {
            TerminateProcess(GetCurrentProcess(), ERROR_ACCESS_DENIED);
            std::terminate();
        }
        active_ = false;
    }
private:
    bool active_{};
};

void ValidateOwnerInputCapability(HANDLE ownerToken, const fs::path& path, bool receive) {
    const DWORD desiredAccess = receive
        ? FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_READ_ATTRIBUTES
        : GENERIC_READ;
    const DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    const DWORD flags = FILE_FLAG_OPEN_REPARSE_POINT |
        (receive ? FILE_FLAG_BACKUP_SEMANTICS : FILE_FLAG_SEQUENTIAL_SCAN);
    HANDLE rawFile = INVALID_HANDLE_VALUE;
    DWORD openError = ERROR_SUCCESS;
    {
        OwnerImpersonation impersonation(ownerToken);
        rawFile = CreateFileW(path.c_str(), desiredAccess, share, nullptr, OPEN_EXISTING, flags, nullptr);
        if (rawFile == INVALID_HANDLE_VALUE) openError = GetLastError();
        impersonation.Revert();
    }
    if (rawFile == INVALID_HANDLE_VALUE) FailWin32("request_input_owner_access_denied", openError);
    Handle file(rawFile);
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(file.get(), &info)) FailWin32("request_input_owner_info_failed");
    if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) Fail("request_input_must_not_be_reparse_point");
    const bool directory = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if (directory != receive) Fail(receive ? "receive_destination_must_be_directory" : "select_one_regular_file");
    if (!directory && GetFileType(file.get()) != FILE_TYPE_DISK) Fail("send_input_must_be_regular_file");
}

fs::path FullPath(const fs::path& path) {
    std::error_code error;
    const auto full = fs::absolute(path, error).lexically_normal();
    if (error || !full.is_absolute()) Fail("absolute_path_resolution_failed");
    return full;
}

void EnsureNotReparse(const fs::path& path, bool mustExist, const char* missingReason = nullptr) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        if (mustExist) {
            const auto error = GetLastError();
            if (missingReason && (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)) Fail(missingReason);
            FailWin32("required_path_unavailable", error);
        }
        return;
    }
    if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) Fail("request_path_must_not_be_reparse_point");
}

bool SamePath(const fs::path& left, const fs::path& right) {
    return _wcsicmp(FullPath(left).c_str(), FullPath(right).c_str()) == 0;
}

Context ValidateRequest(const fs::path& requestPath, const fs::path& executableDir) {
    if (!requestPath.is_absolute()) Fail("request_path_must_be_absolute");
    Context context{};
    context.requestPath = FullPath(requestPath);
    if (context.requestPath.filename() != request_file::FileName) Fail("request_filename_invalid");
    EnsureNotReparse(context.requestPath, true);
    context.requestDir = context.requestPath.parent_path();
    EnsureNotReparse(context.requestDir, true);
    if (!request_file::ValidDirectory(context.requestDir.filename().wstring())) Fail("request_directory_name_invalid");

    context.request = JsonRequestParser(ReadUtf8File(context.requestPath, tx10ub::send_files::MaxRequestBytes)).Parse();
    if (!context.request.ndiscap) Fail("request_transport_invalid");
    if (!context.request.selectFiles && context.request.filePath.empty() && context.request.filePaths.empty())
        Fail("request_file_path_empty");
    HANDLE owner = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, context.request.ownerPid);
    if (!owner) FailWin32("request_owner_unavailable");
    context.owner.reset(owner);
    if (WaitForSingleObject(owner, 0) != WAIT_TIMEOUT) Fail("request_owner_has_exited");
    std::array<wchar_t, 32768> ownerImage{};
    DWORD ownerImageChars = static_cast<DWORD>(ownerImage.size());
    if (!QueryFullProcessImageNameW(owner, 0, ownerImage.data(), &ownerImageChars) || ownerImageChars == 0 || ownerImageChars >= ownerImage.size()) {
        FailWin32("request_owner_image_unavailable");
    }
    if (_wcsicmp(fs::path(std::wstring(ownerImage.data(), ownerImageChars)).filename().c_str(), L"DropPorter.exe") != 0) {
        Fail("request_owner_process_invalid");
    }
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(owner, TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, &rawToken)) {
        FailWin32("request_owner_token_open_failed");
    }
    Handle ownerToken(rawToken);
    context.ownerSid = TokenSidString(ownerToken.get());
    HANDLE rawImpersonationToken = nullptr;
    if (!DuplicateTokenEx(ownerToken.get(), TOKEN_QUERY | TOKEN_IMPERSONATE, nullptr,
        SecurityImpersonation, TokenImpersonation, &rawImpersonationToken)) {
        FailWin32("request_owner_token_duplicate_failed");
    }
    Handle ownerImpersonationToken(rawImpersonationToken);
    PWSTR localAppDataRaw = nullptr;
    const HRESULT folderResult = SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, ownerToken.get(), &localAppDataRaw);
    if (FAILED(folderResult)) throw std::system_error(static_cast<int>(folderResult), std::system_category(), "local_appdata_unavailable");
    fs::path localAppData(localAppDataRaw);
    CoTaskMemFree(localAppDataRaw);
    context.ownerLocalAppData = localAppData;
    const auto sessions = localAppData / L"DropPorter" / L"Sessions";
    if (!SamePath(context.requestDir.parent_path(), sessions)) Fail("request_directory_outside_app_sessions");

    std::wstring expectedName = context.requestDir.filename().wstring();
    expectedName.resize(expectedName.size() - request_file::DirectorySuffix.size());
    if (_wcsicmp(expectedName.c_str(), context.request.candidateName.c_str()) != 0) Fail("request_identity_mismatch");

    context.candidate = context.requestDir.parent_path() / context.request.candidateName;
    if (GetFileAttributesW(context.candidate.c_str()) != INVALID_FILE_ATTRIBUTES) Fail("run_already_exists");
    if (context.request.selectFiles) {
        context.ownerImpersonationToken = std::move(ownerImpersonationToken);
    } else if (context.request.filePaths.empty()) {
        context.filePath = FullPath(context.request.filePath);
        ValidateOwnerInputCapability(ownerImpersonationToken.get(), context.filePath, context.request.receive);
    } else {
        for (const auto& path : context.request.filePaths) {
            auto full = FullPath(path);
            if (!tx10ub::send_files::ValidPath(full.native())) Fail("request_file_path_invalid");
            ValidateOwnerInputCapability(ownerImpersonationToken.get(), full, false);
            context.sendPaths.push_back(std::move(full));
        }
    }

    context.statusPath = context.requestDir / supervisor::StatusFileName;
    context.progressPath = context.requestDir / events::ProgressFileName;
    context.resultPath = context.requestDir / supervisor::ResultFileName;
    context.cancelPath = context.requestDir / markers::CancelFileName;
    context.executableDir = executableDir;
    context.sysPath = executableDir / L"AWDLWinTx10ubProbe.sys";
    return context;
}

void RequireSavedControllerExited(const RuntimeJournal& journal) {
    if (!journal.controllerPid) Fail("runtime_recovery_controller_pid_invalid");
    HANDLE raw = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE, journal.controllerPid);
    if (!raw) {
        const DWORD error = GetLastError();
        if (error == ERROR_INVALID_PARAMETER) return;
        FailWin32("runtime_recovery_previous_controller_query_failed", error);
    }
    Handle process(raw);
    const DWORD state = WaitForSingleObject(process.get(), 0);
    if (state == WAIT_OBJECT_0) return;
    if (state == WAIT_FAILED) FailWin32("runtime_recovery_previous_controller_wait_failed");
    if (state != WAIT_TIMEOUT) Fail("runtime_recovery_previous_controller_state_invalid");
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(process.get(), &created, &exited, &kernel, &user)) {
        FailWin32("runtime_recovery_previous_controller_identity_failed");
    }
    if (created.dwLowDateTime == journal.controllerCreatedLow &&
        created.dwHighDateTime == journal.controllerCreatedHigh) {
        Fail("runtime_recovery_previous_controller_still_running");
    }
}

Context ValidateRecoveryRequest(const fs::path& requestPath, const fs::path& executableDir,
    RuntimeJournal& journal) {
    if (!requestPath.is_absolute()) Fail("request_path_must_be_absolute");
    Context context{};
    context.requestPath = FullPath(requestPath);
    if (context.requestPath.filename() != request_file::FileName) Fail("request_filename_invalid");
    EnsureNotReparse(context.requestPath, true);
    context.requestDir = context.requestPath.parent_path();
    EnsureNotReparse(context.requestDir, true);
    const auto requestToken = context.requestDir.filename().wstring();
    if (!request_file::ValidDirectory(requestToken)) Fail("request_directory_name_invalid");
    context.request = JsonRequestParser(ReadUtf8File(context.requestPath, tx10ub::send_files::MaxRequestBytes)).Parse();
    std::wstring expectedCandidate = requestToken;
    expectedCandidate.resize(expectedCandidate.size() - request_file::DirectorySuffix.size());
    if (_wcsicmp(expectedCandidate.c_str(), context.request.candidateName.c_str()) != 0) {
        Fail("request_identity_mismatch");
    }
    context.candidate = context.requestDir.parent_path() / context.request.candidateName;
    EnsureNotReparse(context.candidate, true, supervisor::RecoverySnapshotMissingReason);
    context.capture = context.candidate / L"capture";
    EnsureNotReparse(context.capture, true, supervisor::RecoverySnapshotMissingReason);
    const auto journalPath = context.candidate / markers::RadioSnapshotFileName;
    EnsureNotReparse(journalPath, true, supervisor::RecoverySnapshotMissingReason);
    ReadRuntimeJournal(journalPath, journal);
    if (!HasJournalFlag(journal, JournalWifiCaptured) ||
        (journal.flags & ~((1u << 28) - 1u)) != 0 ||
        (HasJournalFlag(journal, JournalRxBaselineMatchesSavedWifi) &&
         (!HasJournalFlag(journal, JournalDirectIhv) || !context.request.ndiscap || journal.wifiAutoconf != 1)) ||
        (ReadJournalDriverImage(journal) != tx10ub::host::DriverImage::Stock &&
         (!HasJournalFlag(journal, JournalDirectIhv) ||
          ReadJournalWide(journal.adapterInstanceId, "adapter_instance_id").empty()))) {
        Fail("runtime_recovery_journal_state_invalid");
    }
    if (journal.ownerPid != context.request.ownerPid ||
        _wcsicmp(ReadJournalWide(journal.candidateName, "candidate_name").c_str(),
            context.request.candidateName.c_str()) != 0) {
        Fail("runtime_recovery_journal_session_mismatch");
    }
    const std::wstring savedLocalAppData = ReadJournalWide(journal.ownerLocalAppData, "local_appdata");
    const auto expectedSessions = fs::path(savedLocalAppData) / L"DropPorter" / L"Sessions";
    if (!SamePath(context.requestDir.parent_path(), expectedSessions)) {
        Fail("runtime_recovery_session_path_mismatch");
    }
    const std::string ownerSid = JournalAscii(journal.ownerSid, "owner_sid");
    const std::string controllerSid = JournalAscii(journal.controllerSid, "controller_sid");
    if (ownerSid.empty() || controllerSid.empty() ||
        FileOwnerSidString(context.requestDir) != std::wstring(ownerSid.begin(), ownerSid.end())) {
        Fail("runtime_recovery_session_owner_mismatch");
    }
    ValidatePrivateRuntimeDirectorySecurity(context.candidate);
    if ((!HasJournalFlag(journal, JournalDirectIhv) && journal.serviceStartType != SERVICE_DEMAND_START) || journal.adapterLuid == 0 ||
        journal.runtimeTargetNetLuid == 0 || journal.runtimeTargetNetLuid != journal.adapterLuid) {
        Fail("runtime_recovery_snapshot_contract_invalid");
    }
    const auto callerSid = [&]() {
        HANDLE tokenRaw = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenRaw)) FailWin32("runtime_token_open_failed");
        Handle token(tokenRaw);
        return TokenSidString(token.get());
    }();
    if (callerSid != std::wstring(controllerSid.begin(), controllerSid.end())) {
        Fail("runtime_recovery_caller_identity_mismatch");
    }
    RequireSavedControllerExited(journal);

    context.statusPath = context.requestDir / supervisor::StatusFileName;
    context.progressPath = context.requestDir / events::ProgressFileName;
    context.resultPath = context.requestDir / supervisor::ResultFileName;
    context.cancelPath = context.requestDir / markers::CancelFileName;
    context.executableDir = executableDir;
    context.sysPath = executableDir / L"AWDLWinTx10ubProbe.sys";
    return context;
}

std::wstring QuoteArgument(const std::wstring& value) {
    std::wstring result = L"\"";
    size_t slashes = 0;
    for (wchar_t ch : value) {
        if (ch == L'\\') { ++slashes; continue; }
        if (ch == L'"') {
            result.append(slashes * 2 + 1, L'\\');
            result.push_back(ch);
            slashes = 0;
            continue;
        }
        result.append(slashes, L'\\');
        slashes = 0;
        result.push_back(ch);
    }
    result.append(slashes * 2, L'\\');
    result.push_back(L'"');
    return result;
}

std::wstring BuildCommandLine(const fs::path& executable, const std::vector<std::wstring>& arguments) {
    std::wstring line = QuoteArgument(executable.wstring());
    for (const auto& argument : arguments) { line.push_back(L' '); line += QuoteArgument(argument); }
    return line;
}

std::string NarrowAscii(const std::wstring& value) {
    std::string result;
    result.reserve(value.size());
    for (wchar_t ch : value) {
        if (ch > 0x7f) Fail("expected_ascii_process_output");
        result.push_back(static_cast<char>(ch));
    }
    return result;
}

std::string Utf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (length <= 0) FailWin32("wide_text_utf8_conversion_failed");
    std::string result(static_cast<size_t>(length), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), result.data(), length, nullptr, nullptr) != length) {
        FailWin32("wide_text_utf8_conversion_failed");
    }
    return result;
}

struct CapturedProcess {
    DWORD exitCode{};
    std::string output;
};

CapturedProcess RunCaptured(const fs::path& executable, const std::vector<std::wstring>& arguments,
    const std::function<void()>& pump = {}, const std::function<void()>& onStarted = {}) {
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    HANDLE rawRead = nullptr, rawWrite = nullptr;
    if (!CreatePipe(&rawRead, &rawWrite, &security, 0)) FailWin32("child_pipe_create_failed");
    Handle read(rawRead), write(rawWrite);
    if (!SetHandleInformation(read.get(), HANDLE_FLAG_INHERIT, 0)) FailWin32("child_pipe_inherit_clear_failed");
    auto commandLine = BuildCommandLine(executable, arguments);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = write.get();
    startup.hStdError = write.get();
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(executable.c_str(), commandLine.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, executable.parent_path().c_str(), &startup, &process)) {
        FailWin32("child_process_start_failed");
    }
    Handle processHandle(process.hProcess), threadHandle(process.hThread);
    write.reset();
    if (onStarted) onStarted();
    CapturedProcess result{};
    std::array<char, 4096> buffer{};
    std::string captureError;
    bool outputExceeded = false;
    auto drain = [&]() {
        for (;;) {
            DWORD available = 0;
            if (!PeekNamedPipe(read.get(), nullptr, 0, nullptr, &available, nullptr)) {
                const DWORD error = GetLastError();
                if (error == ERROR_BROKEN_PIPE) return;
                if (captureError.empty()) captureError = "child_pipe_query_failed_" + std::to_string(error);
                return;
            }
            if (!available) return;
            DWORD count = 0;
            const DWORD request = std::min<DWORD>(available, static_cast<DWORD>(buffer.size()));
            if (!ReadFile(read.get(), buffer.data(), request, &count, nullptr)) {
                const DWORD error = GetLastError();
                if (error != ERROR_BROKEN_PIPE && captureError.empty()) {
                    captureError = "child_pipe_read_failed_" + std::to_string(error);
                }
                return;
            }
            const size_t remaining = 4 * 1024 * 1024 - std::min<size_t>(4 * 1024 * 1024, result.output.size());
            const size_t keep = std::min<size_t>(remaining, count);
            result.output.append(buffer.data(), keep);
            if (keep != count) outputExceeded = true;
        }
    };
    for (;;) {
        drain();
        const DWORD wait = WaitForSingleObject(processHandle.get(), 50);
        if (wait == WAIT_OBJECT_0) break;
        if (wait == WAIT_FAILED) {
            const DWORD waitError = GetLastError();
            DWORD currentExit = STILL_ACTIVE;
            if (GetExitCodeProcess(processHandle.get(), &currentExit) && currentExit != STILL_ACTIVE) break;
            if (captureError.empty()) captureError = "child_process_wait_unconfirmed_" + std::to_string(waitError);
            Sleep(50);
        }
        if (pump) {
            try { pump(); }
            catch (const std::exception& error) {
                if (captureError.empty()) captureError = std::string("child_pump_failed_") + error.what();
            }
        }
    }
    if (!GetExitCodeProcess(processHandle.get(), &result.exitCode)) FailWin32("child_exit_code_query_failed");
    drain();
    if (!captureError.empty()) Fail(captureError);
    if (outputExceeded) Fail("child_output_limit_exceeded");
    return result;
}

std::wstring NormalizeImagePath(std::wstring path) {
    while (!path.empty() && (path.front() == L' ' || path.front() == L'\t')) path.erase(path.begin());
    while (!path.empty() && (path.back() == L' ' || path.back() == L'\t')) path.pop_back();
    if (path.size() >= 2 && path.front() == L'"' && path.back() == L'"') {
        path = path.substr(1, path.size() - 2);
    }
    if (path.rfind(L"\\??\\", 0) == 0) path.erase(0, 4);
    if (path.rfind(L"\\SystemRoot\\", 0) == 0) {
        std::vector<wchar_t> buffer(32768);
        const UINT count = GetWindowsDirectoryW(buffer.data(), static_cast<UINT>(buffer.size()));
        if (!count || count >= buffer.size()) FailWin32("windows_directory_unavailable");
        path = std::wstring(buffer.data(), count) + path.substr(11);
    }
    return FullPath(path).wstring();
}

class TargetNetLuidValue {
public:
    TargetNetLuidValue() {
        const LONG opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\AWDLWinTx10ubProbe\\Parameters",
            0, KEY_QUERY_VALUE | KEY_SET_VALUE, &key_);
        if (opened == ERROR_FILE_NOT_FOUND || opened == ERROR_PATH_NOT_FOUND) return;
        if (opened != ERROR_SUCCESS) throw std::system_error(opened, std::system_category(), "driver_parameter_key_open_failed");
        keyExistedBeforeRuntime_ = true;
        DWORD bytes = sizeof(original_), type = 0;
        const LONG queried = RegQueryValueExW(key_, kTargetNetLuid, nullptr, &type,
            reinterpret_cast<BYTE*>(&original_), &bytes);
        if (queried == ERROR_FILE_NOT_FOUND) return;
        if (queried != ERROR_SUCCESS) throw std::system_error(queried, std::system_category(), "driver_parameter_read_failed");
        if (type != REG_QWORD || bytes != sizeof(original_)) Fail("driver_parameter_existing_value_invalid");
        hadValue_ = true;
    }
    ~TargetNetLuidValue() { if (key_) RegCloseKey(key_); }
    TargetNetLuidValue(const TargetNetLuidValue&) = delete;
    TargetNetLuidValue& operator=(const TargetNetLuidValue&) = delete;

    void Set(ULONGLONG value) {
        if (value == 0) Fail("target_net_luid_invalid");
        if (!key_) {
            const LONG created = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Services\\AWDLWinTx10ubProbe\\Parameters",
                0, nullptr, REG_OPTION_NON_VOLATILE, KEY_QUERY_VALUE | KEY_SET_VALUE,
                nullptr, &key_, &disposition_);
            if (created != ERROR_SUCCESS) throw std::system_error(created, std::system_category(), "driver_parameter_key_open_failed");
            createdKey_ = disposition_ == REG_CREATED_NEW_KEY;
        }
        changed_ = true;
        const LONG status = RegSetValueExW(key_, kTargetNetLuid, 0, REG_QWORD,
            reinterpret_cast<const BYTE*>(&value), sizeof(value));
        if (status != ERROR_SUCCESS) throw std::system_error(status, std::system_category(), "driver_parameter_set_failed");
        expected_ = value;
    }

    bool KeyExistedBeforeRuntime() const { return keyExistedBeforeRuntime_; }
    bool HadValueBeforeRuntime() const { return hadValue_; }
    ULONGLONG OriginalValue() const { return original_; }

    static void RestoreSaved(const RuntimeJournal& journal) {
        if (journal.parameterKeyExisted > 1 || journal.parameterValuePresent > 1) {
            Fail("runtime_recovery_target_parameter_snapshot_invalid");
        }
        HKEY key = nullptr;
        const LONG opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\AWDLWinTx10ubProbe\\Parameters",
            0, KEY_QUERY_VALUE | KEY_SET_VALUE, &key);
        if (opened == ERROR_FILE_NOT_FOUND || opened == ERROR_PATH_NOT_FOUND) {
            if (!journal.parameterKeyExisted && !journal.parameterValuePresent) return;
            Fail("runtime_recovery_target_parameter_key_missing");
        }
        if (opened != ERROR_SUCCESS) throw std::system_error(opened, std::system_category(), "runtime_recovery_target_parameter_open_failed");
        struct KeyClose { HKEY value; ~KeyClose() { if (value) RegCloseKey(value); } } close{key};

        ULONGLONG current = 0;
        DWORD currentType = 0, bytes = sizeof(current);
        const LONG queried = RegQueryValueExW(key, kTargetNetLuid, nullptr, &currentType,
            reinterpret_cast<BYTE*>(&current), &bytes);
        const bool currentPresent = queried == ERROR_SUCCESS;
        if (queried != ERROR_SUCCESS && queried != ERROR_FILE_NOT_FOUND) {
            throw std::system_error(queried, std::system_category(), "runtime_recovery_target_parameter_query_failed");
        }
        if (currentPresent && (currentType != REG_QWORD || bytes != sizeof(current))) {
            Fail("runtime_recovery_target_parameter_type_changed");
        }
        const bool alreadyOriginal = journal.parameterValuePresent
            ? currentPresent && current == journal.originalTargetNetLuid
            : !currentPresent;
        if (!alreadyOriginal) {
            if (!currentPresent || current != journal.runtimeTargetNetLuid) {
                Fail("runtime_recovery_target_parameter_changed_outside_runtime");
            }
            LONG status = ERROR_SUCCESS;
            if (journal.parameterValuePresent) {
                status = RegSetValueExW(key, kTargetNetLuid, 0, REG_QWORD,
                    reinterpret_cast<const BYTE*>(&journal.originalTargetNetLuid), sizeof(journal.originalTargetNetLuid));
            } else {
                status = RegDeleteValueW(key, kTargetNetLuid);
                if (status == ERROR_FILE_NOT_FOUND) status = ERROR_SUCCESS;
            }
            if (status != ERROR_SUCCESS) throw std::system_error(status, std::system_category(), "runtime_recovery_target_parameter_restore_failed");
        }
        if (!journal.parameterKeyExisted) {
            close.value = nullptr;
            RegCloseKey(key);
            const LONG deleted = RegDeleteKeyW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Services\\AWDLWinTx10ubProbe\\Parameters");
            if (deleted != ERROR_SUCCESS && deleted != ERROR_FILE_NOT_FOUND && deleted != ERROR_ACCESS_DENIED) {
                throw std::system_error(deleted, std::system_category(), "runtime_recovery_target_parameter_key_cleanup_failed");
            }
        }
    }

    void Restore() {
        if (!changed_) return;
        ULONGLONG current = 0;
        DWORD currentBytes = sizeof(current), currentType = 0;
        const LONG queried = RegQueryValueExW(key_, kTargetNetLuid, nullptr, &currentType,
            reinterpret_cast<BYTE*>(&current), &currentBytes);
        if (queried != ERROR_SUCCESS || currentType != REG_QWORD || currentBytes != sizeof(current) || current != expected_) {
            Fail("driver_parameter_changed_outside_runtime; restore_deferred");
        }
        LONG status = ERROR_SUCCESS;
        if (hadValue_) {
            status = RegSetValueExW(key_, kTargetNetLuid, 0, REG_QWORD,
                reinterpret_cast<const BYTE*>(&original_), sizeof(original_));
        } else {
            status = RegDeleteValueW(key_, kTargetNetLuid);
            if (status == ERROR_FILE_NOT_FOUND) status = ERROR_SUCCESS;
        }
        if (status != ERROR_SUCCESS) throw std::system_error(status, std::system_category(), "driver_parameter_restore_failed");
        changed_ = false;
        if (createdKey_) {
            if (key_) { RegCloseKey(key_); key_ = nullptr; }
            const LONG deleted = RegDeleteKeyW(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Services\\AWDLWinTx10ubProbe\\Parameters");
            if (deleted != ERROR_SUCCESS && deleted != ERROR_FILE_NOT_FOUND && deleted != ERROR_ACCESS_DENIED) {
                throw std::system_error(deleted, std::system_category(), "driver_parameter_empty_key_cleanup_failed");
            }
        }
    }
private:
    HKEY key_{};
    DWORD disposition_{};
    ULONGLONG original_{};
    ULONGLONG expected_{};
    bool hadValue_{}, keyExistedBeforeRuntime_{}, createdKey_{}, changed_{};
};

class AuxiliaryService {
public:
    AuxiliaryService(fs::path sysPath, ULONGLONG targetLuid)
        : sysPath_(FullPath(sysPath)), targetLuid_(targetLuid) {
        manager_.reset(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (!manager_.get()) FailWin32("service_manager_open_failed");
        service_.reset(OpenServiceW(manager_.get(), kServiceName,
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_START |
            SERVICE_STOP | SERVICE_CHANGE_CONFIG));
        if (!service_.get()) {
            if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) Fail("driver_setup_required_run_DropPorterSetup.exe_once");
            FailWin32("auxiliary_service_open_failed");
        }
        QueryConfig();
        if (config_->dwStartType != SERVICE_DEMAND_START) Fail("auxiliary_service_start_mode_must_be_manual");
        if (QueryState() != SERVICE_STOPPED) Fail("auxiliary_service_must_be_stopped_before_runtime");
        originalImagePath_ = config_->lpBinaryPathName;
        registry_ = std::make_unique<TargetNetLuidValue>();
    }

    void Start() {
        registry_->Set(targetLuid_);
        registrationChanged_ = true;
        serviceStarted_ = true;
        if (!ChangeImagePath(sysPath_.wstring())) FailWin32("auxiliary_image_registration_failed");
        if (!StartServiceW(service_.get(), 0, nullptr)) FailWin32("auxiliary_service_start_failed");
        WaitState(SERVICE_RUNNING, 20000);
        QueryConfig();
        if (_wcsicmp(NormalizeImagePath(config_->lpBinaryPathName).c_str(), sysPath_.c_str()) != 0) {
            Fail("auxiliary_running_image_path_mismatch");
        }
        const auto probe = RunCaptured(probePath_, {L"data-query-state"});
        if (probe.exitCode != 0 || probe.output.find(kProbeReadyPrefix) == std::string::npos) {
            Fail("auxiliary_data_query_state_not_ready");
        }
        ready_ = true;
    }

    bool ready() const { return ready_; }

    void Restore() {
        if (serviceStarted_) {
            const DWORD state = QueryState();
            if (state != SERVICE_STOPPED) {
                QueryConfig();
                if (_wcsicmp(NormalizeImagePath(config_->lpBinaryPathName).c_str(), sysPath_.c_str()) != 0) {
                    Fail("auxiliary_path_changed_while_owned; stop_deferred");
                }
                SERVICE_STATUS status{};
                if (!ControlService(service_.get(), SERVICE_CONTROL_STOP, &status) &&
                    GetLastError() != ERROR_SERVICE_NOT_ACTIVE) FailWin32("auxiliary_service_stop_failed");
                WaitState(SERVICE_STOPPED, 20000);
            }
        }
        if (registrationChanged_) {
            if (QueryState() != SERVICE_STOPPED) Fail("auxiliary_service_not_stopped; path_restore_deferred");
            QueryConfig();
            const auto currentPath = NormalizeImagePath(config_->lpBinaryPathName);
            const auto runtimePath = NormalizeImagePath(sysPath_.wstring());
            const auto savedPath = NormalizeImagePath(originalImagePath_);
            if (_wcsicmp(currentPath.c_str(), savedPath.c_str()) == 0) {
                registrationChanged_ = false;
            } else if (_wcsicmp(currentPath.c_str(), runtimePath.c_str()) == 0) {
                if (!ChangeImagePath(originalImagePath_)) FailWin32("auxiliary_registration_restore_failed");
            } else {
                Fail("auxiliary_service_path_changed_outside_runtime; restore_deferred");
            }
            if (registrationChanged_) {
                QueryConfig();
                if (config_->dwStartType != SERVICE_DEMAND_START || config_->lpBinaryPathName != originalImagePath_) {
                    Fail("auxiliary_registration_restore_mismatch");
                }
                registrationChanged_ = false;
            }
        }
        if (registry_) registry_->Restore();
        restored_ = true;
    }

    static void RestoreSaved(const RuntimeJournal& journal) {
        const auto savedPath = ReadJournalWide(journal.originalServiceImagePath, "service_path");
        const auto runtimePath = ReadJournalWide(journal.runtimeSysPath, "runtime_sys_path");
        if (savedPath.empty() || runtimePath.empty() || journal.serviceStartType != SERVICE_DEMAND_START) {
            Fail("runtime_recovery_service_snapshot_invalid");
        }
        ScHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (!manager.get()) FailWin32("service_manager_open_failed");
        ScHandle service(OpenServiceW(manager.get(), kServiceName,
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_STOP | SERVICE_CHANGE_CONFIG));
        if (!service.get()) FailWin32("runtime_recovery_service_open_failed");
        auto queryConfig = [&](std::vector<BYTE>& storage) {
            DWORD needed = 0;
            (void)QueryServiceConfigW(service.get(), nullptr, 0, &needed);
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed < sizeof(QUERY_SERVICE_CONFIGW)) {
                FailWin32("runtime_recovery_service_config_size_failed");
            }
            storage.resize(needed);
            auto* config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(storage.data());
            if (!QueryServiceConfigW(service.get(), config, needed, &needed) || !config->lpBinaryPathName) {
                FailWin32("runtime_recovery_service_config_query_failed");
            }
            return config;
        };
        auto queryState = [&]() {
            SERVICE_STATUS_PROCESS state{};
            DWORD bytes = 0;
            if (!QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO,
                reinterpret_cast<BYTE*>(&state), sizeof(state), &bytes) || bytes != sizeof(state)) {
                FailWin32("runtime_recovery_service_state_query_failed");
            }
            return state.dwCurrentState;
        };
        std::vector<BYTE> configStorage;
        auto* config = queryConfig(configStorage);
        if (config->dwStartType != journal.serviceStartType) Fail("runtime_recovery_service_start_mode_changed");
        const auto currentPath = NormalizeImagePath(config->lpBinaryPathName);
        const auto savedNormalized = NormalizeImagePath(savedPath);
        const auto runtimeNormalized = NormalizeImagePath(runtimePath);
        if (_wcsicmp(currentPath.c_str(), savedNormalized.c_str()) != 0 &&
            _wcsicmp(currentPath.c_str(), runtimeNormalized.c_str()) != 0) {
            Fail("runtime_recovery_service_path_changed_outside_runtime");
        }
        DWORD state = queryState();
        if (_wcsicmp(currentPath.c_str(), runtimeNormalized.c_str()) == 0 && state != SERVICE_STOPPED) {
            if (state == SERVICE_START_PENDING || state == SERVICE_CONTINUE_PENDING) {
                const ULONGLONG deadline = GetTickCount64() + 20000;
                do {
                    Sleep(200);
                    state = queryState();
                    if (state == SERVICE_RUNNING || state == SERVICE_STOPPED) break;
                    if (state != SERVICE_START_PENDING && state != SERVICE_CONTINUE_PENDING) {
                        Fail("runtime_recovery_service_unexpected_pending_state");
                    }
                } while (GetTickCount64() < deadline);
                if (state != SERVICE_RUNNING && state != SERVICE_STOPPED) Fail("runtime_recovery_service_start_timeout");
            }
            if (state != SERVICE_STOPPED) {
                SERVICE_STATUS status{};
                if (!ControlService(service.get(), SERVICE_CONTROL_STOP, &status) &&
                    GetLastError() != ERROR_SERVICE_NOT_ACTIVE) FailWin32("runtime_recovery_service_stop_failed");
                const ULONGLONG deadline = GetTickCount64() + 20000;
                do {
                    state = queryState();
                    if (state == SERVICE_STOPPED) break;
                    if (state != SERVICE_STOP_PENDING) Fail("runtime_recovery_service_stop_state_invalid");
                    Sleep(200);
                } while (GetTickCount64() < deadline);
                if (state != SERVICE_STOPPED) Fail("runtime_recovery_service_stop_timeout");
            }
        }
        if (_wcsicmp(currentPath.c_str(), runtimeNormalized.c_str()) == 0) {
            if (!ChangeServiceConfigW(service.get(), SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                SERVICE_NO_CHANGE, savedPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
                FailWin32("runtime_recovery_service_path_restore_failed");
            }
        } else if (state != SERVICE_STOPPED) {
            Fail("runtime_recovery_original_service_not_stopped");
        }
        std::vector<BYTE> restoredStorage;
        auto* restoredConfig = queryConfig(restoredStorage);
        if (restoredConfig->dwStartType != journal.serviceStartType ||
            _wcsicmp(NormalizeImagePath(restoredConfig->lpBinaryPathName).c_str(), savedNormalized.c_str()) != 0 ||
            queryState() != SERVICE_STOPPED) {
            Fail("runtime_recovery_service_registration_not_restored");
        }
        TargetNetLuidValue::RestoreSaved(journal);
    }

    bool restored() const { return restored_; }
    const std::wstring& original_path() const { return originalImagePath_; }
    const fs::path& probe_path() const { return probePath_; }
    void SetProbePath(fs::path value) { probePath_ = std::move(value); }
    DWORD original_start_type() const { return config_->dwStartType; }
    bool parameter_key_existed() const { return registry_->KeyExistedBeforeRuntime(); }
    bool parameter_value_present() const { return registry_->HadValueBeforeRuntime(); }
    ULONGLONG original_target_luid_parameter() const { return registry_->OriginalValue(); }

private:
    DWORD QueryState() const {
        SERVICE_STATUS_PROCESS status{};
        DWORD bytes = 0;
        if (!QueryServiceStatusEx(service_.get(), SC_STATUS_PROCESS_INFO,
            reinterpret_cast<BYTE*>(&status), sizeof(status), &bytes)) FailWin32("auxiliary_state_query_failed");
        if (bytes != sizeof(status)) Fail("auxiliary_state_query_invalid_length");
        return status.dwCurrentState;
    }

    void WaitState(DWORD expected, DWORD timeout) const {
        const ULONGLONG deadline = GetTickCount64() + timeout;
        DWORD last = SERVICE_STOPPED;
        do {
            last = QueryState();
            if (last == expected) return;
            if (last != SERVICE_START_PENDING && last != SERVICE_STOP_PENDING &&
                last != SERVICE_CONTINUE_PENDING && last != SERVICE_PAUSE_PENDING) {
                Fail("auxiliary_service_unexpected_state_" + std::to_string(last));
            }
            Sleep(200);
        } while (GetTickCount64() < deadline);
        Fail("auxiliary_service_state_timeout_" + std::to_string(last));
    }

    void QueryConfig() {
        DWORD needed = 0;
        (void)QueryServiceConfigW(service_.get(), nullptr, 0, &needed);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed < sizeof(QUERY_SERVICE_CONFIGW)) {
            FailWin32("auxiliary_config_size_query_failed");
        }
        configStorage_.resize(needed);
        config_ = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(configStorage_.data());
        if (!QueryServiceConfigW(service_.get(), config_, needed, &needed)) FailWin32("auxiliary_config_query_failed");
        if (!config_->lpBinaryPathName) Fail("auxiliary_image_path_missing");
    }

    bool ChangeImagePath(const std::wstring& path) const {
        return ChangeServiceConfigW(service_.get(), SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
            SERVICE_NO_CHANGE, path.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != FALSE;
    }

    ScHandle manager_, service_;
    fs::path sysPath_, probePath_;
    ULONGLONG targetLuid_{};
    std::vector<BYTE> configStorage_;
    LPQUERY_SERVICE_CONFIGW config_{};
    std::wstring originalImagePath_;
    std::unique_ptr<TargetNetLuidValue> registry_;
    bool registrationChanged_{}, serviceStarted_{}, ready_{}, restored_{};
};

std::array<UCHAR, 32> Sha256(const fs::path& path) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status < 0) Fail("runtime_sha256_provider_failed");
    struct Alg { BCRYPT_ALG_HANDLE h; ~Alg() { if (h) BCryptCloseAlgorithmProvider(h, 0); } } alg{algorithm};
    DWORD objectLength = 0, resultLength = 0, bytes = 0;
    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &bytes, 0);
    if (status < 0 || bytes != sizeof(objectLength)) Fail("runtime_sha256_object_length_failed");
    status = BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&resultLength), sizeof(resultLength), &bytes, 0);
    if (status < 0 || bytes != sizeof(resultLength) || resultLength != 32) Fail("runtime_sha256_digest_length_invalid");
    std::vector<UCHAR> object(objectLength);
    BCRYPT_HASH_HANDLE hash = nullptr;
    status = BCryptCreateHash(algorithm, &hash, object.data(), objectLength, nullptr, 0, 0);
    if (status < 0) Fail("runtime_sha256_hash_create_failed");
    struct Hash { BCRYPT_HASH_HANDLE h; ~Hash() { if (h) BCryptDestroyHash(h); } } hashOwner{hash};
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!file) FailWin32("runtime_image_open_failed");
    std::array<UCHAR, 65536> buffer{};
    for (;;) {
        DWORD count = 0;
        if (!ReadFile(file.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &count, nullptr)) FailWin32("runtime_image_read_failed");
        if (!count) break;
        status = BCryptHashData(hash, buffer.data(), count, 0);
        if (status < 0) Fail("runtime_sha256_update_failed");
    }
    std::array<UCHAR, 32> result{};
    status = BCryptFinishHash(hash, result.data(), static_cast<ULONG>(result.size()), 0);
    if (status < 0) Fail("runtime_sha256_finish_failed");
    return result;
}

std::wstring HexWide(const std::array<UCHAR, 32>& value) {
    std::wostringstream out;
    out << std::hex << std::uppercase << std::setfill(L'0');
    for (UCHAR byte : value) out << std::setw(2) << static_cast<unsigned>(byte);
    return out.str();
}

void WriteAtomic(const fs::path& path, const std::string& content, bool flushToDisk) {
    auto temporary = path;
    temporary += L".tmp";
    Handle file(CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file) FailWin32("atomic_file_create_failed");
    size_t offset = 0;
    while (offset < content.size()) {
        const DWORD request = static_cast<DWORD>((std::min)(content.size() - offset,
            static_cast<size_t>(1024 * 1024)));
        DWORD written = 0;
        if (!WriteFile(file.get(), content.data() + offset, request, &written, nullptr) || !written) {
            FailWin32("atomic_file_write_failed");
        }
        offset += written;
    }
    if (flushToDisk && !FlushFileBuffers(file.get())) FailWin32("atomic_file_flush_failed");
    file.reset();
    const DWORD moveFlags = MOVEFILE_REPLACE_EXISTING | (flushToDisk ? MOVEFILE_WRITE_THROUGH : 0);
    if (!MoveFileExW(temporary.c_str(), path.c_str(), moveFlags)) {
        FailWin32("atomic_file_replace_failed");
    }
}

void AppendLine(const fs::path& path, const std::string& line) {
    Handle file(CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file) FailWin32("controller_log_open_failed");
    std::string text = line;
    text.push_back('\n');
    DWORD written = 0;
    if (!WriteFile(file.get(), text.data(), static_cast<DWORD>(text.size()), &written, nullptr) ||
        written != text.size()) FailWin32("controller_log_write_failed");
}

std::string ReadAppended(const fs::path& path, std::uint64_t& position) {
    Handle file(CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND) return {};
        FailWin32("child_log_open_failed");
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.get(), &size) || size.QuadPart < 0) FailWin32("child_log_size_failed");
    if (static_cast<std::uint64_t>(size.QuadPart) < position) position = 0;
    if (static_cast<std::uint64_t>(size.QuadPart) - position > 4 * 1024 * 1024) {
        Fail("child_log_unexpected_growth");
    }
    LARGE_INTEGER at{};
    at.QuadPart = static_cast<LONGLONG>(position);
    if (!SetFilePointerEx(file.get(), at, nullptr, FILE_BEGIN)) FailWin32("child_log_seek_failed");
    const DWORD want = static_cast<DWORD>(static_cast<std::uint64_t>(size.QuadPart) - position);
    std::string result(want, '\0');
    DWORD count = 0;
    if (want && !ReadFile(file.get(), result.data(), want, &count, nullptr)) FailWin32("child_log_read_failed");
    result.resize(count);
    position += count;
    return result;
}

std::string ReadTextIfPresent(const fs::path& path, size_t maximum = 65536) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    input.seekg(0, std::ios::end);
    const auto size = input.tellg();
    if (size < 0 || static_cast<std::uint64_t>(size) > maximum) Fail("text_file_size_invalid");
    input.seekg(0, std::ios::beg);
    std::string result(static_cast<size_t>(size), '\0');
    input.read(result.data(), static_cast<std::streamsize>(result.size()));
    if (!input && !result.empty()) Fail("text_file_read_failed");
    return result;
}

std::wstring GuidText(const GUID& value) {
    std::array<wchar_t, 40> buffer{};
    const int count = StringFromGUID2(value, buffer.data(), static_cast<int>(buffer.size()));
    if (count <= 1) Fail("runtime_guid_format_failed");
    std::wstring result(buffer.data(), static_cast<size_t>(count - 1));
    for (auto& ch : result) {
        if (ch >= L'A' && ch <= L'F') ch = static_cast<wchar_t>(ch - L'A' + L'a');
    }
    return result;
}

std::wstring NewNdiscapSessionName() {
    std::array<UCHAR, 16> bytes{};
    const NTSTATUS status = BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0) Fail("ndiscap_session_name_random_failed");
    static constexpr wchar_t digits[] = L"0123456789abcdef";
    std::wstring name = L"DropPorter.NdisCap.";
    name.reserve(name.size() + bytes.size() * 2);
    for (const UCHAR value : bytes) {
        name.push_back(digits[value >> 4]);
        name.push_back(digits[value & 0x0f]);
    }
    return name;
}

void WriteNdiscapSessionScript(const fs::path& path) {
    HMODULE module = GetModuleHandleW(nullptr);
    if (!module) FailWin32("ndiscap_script_module_unavailable");
    const HRSRC resource = FindResourceW(module, MAKEINTRESOURCEW(101), RT_RCDATA);
    if (!resource) FailWin32("ndiscap_script_resource_unavailable");
    const DWORD size = SizeofResource(module, resource);
    if (!size || size > 64 * 1024) Fail("ndiscap_script_resource_size_invalid");
    const HGLOBAL loaded = LoadResource(module, resource);
    if (!loaded) FailWin32("ndiscap_script_resource_load_failed");
    const void* data = LockResource(loaded);
    if (!data) FailWin32("ndiscap_script_resource_lock_failed");
    Handle file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!file) FailWin32("ndiscap_script_file_create_failed");
    DWORD written = 0;
    if (!WriteFile(file.get(), data, size, &written, nullptr) || written != size) {
        FailWin32("ndiscap_script_file_write_failed");
    }
    if (!FlushFileBuffers(file.get())) FailWin32("ndiscap_script_file_flush_failed");
}

fs::path WindowsPowerShellExecutable() {
    std::array<wchar_t, MAX_PATH> buffer{};
    const UINT length = GetSystemDirectoryW(buffer.data(), static_cast<UINT>(buffer.size()));
    if (!length || length >= buffer.size()) FailWin32("system_directory_unavailable");
    return fs::path(std::wstring(buffer.data(), length)) /
        L"WindowsPowerShell/v1.0/powershell.exe";
}

fs::path ProtectedProgramFilesDirectory() {
    PWSTR raw = nullptr;
    const HRESULT result = SHGetKnownFolderPath(FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, nullptr, &raw);
    if (FAILED(result)) throw std::system_error(static_cast<int>(result), std::system_category(),
        "program_files_directory_unavailable");
    fs::path directory(raw);
    CoTaskMemFree(raw);
    directory = FullPath(directory);
    EnsureNotReparse(directory, true, "program_files_directory_unavailable");
    if (!fs::is_directory(directory)) Fail("program_files_directory_unavailable");
    return directory;
}

bool RemoveOwnedNdiscapHelperFile(const fs::path& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return true;
        return false;
    }
    if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) || (attributes & FILE_ATTRIBUTE_DIRECTORY)) return false;
    if (DeleteFileW(path.c_str())) return true;
    const DWORD error = GetLastError();
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

class NdiscapSessionOwner {
public:
    ~NdiscapSessionOwner() { (void)Stop(std::chrono::seconds{10}); }
    NdiscapSessionOwner() = default;
    NdiscapSessionOwner(const NdiscapSessionOwner&) = delete;
    NdiscapSessionOwner& operator=(const NdiscapSessionOwner&) = delete;

    void Start(const Adapter& adapter, const std::function<void()>& checkIntent) {
        if (process_) Fail("ndiscap_session_already_started");
        checkIntent();
        sessionName_ = NewNdiscapSessionName();
        helperDirectory_ = ProtectedProgramFilesDirectory() / (L"AWDLWin." + sessionName_);
        scriptPath_ = helperDirectory_ / L"ndiscap-session.ps1";
        readyPath_ = helperDirectory_ / L"ndiscap-ready.txt";
        readyTempPath_ = helperDirectory_ / L"ndiscap-ready.txt.tmp";
        stopPath_ = helperDirectory_ / L"ndiscap-stop.txt";
        stopTempPath_ = helperDirectory_ / L"ndiscap-stop.txt.tmp";
        logPath_ = helperDirectory_ / L"ndiscap-session.txt";
        CreatePrivateRuntimeDirectory(helperDirectory_, &helperDirectoryCreated_);
        WriteNdiscapSessionScript(scriptPath_);

        log_.reset(CreateFileW(logPath_.c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        if (!log_) FailWin32("ndiscap_session_log_create_failed");
        if (!SetHandleInformation(log_.get(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
            FailWin32("ndiscap_session_log_inherit_failed");
        }

        const fs::path executable = WindowsPowerShellExecutable();
        if (!fs::is_regular_file(executable)) Fail("ndiscap_powershell_unavailable");
        const std::vector<std::wstring> arguments{
            L"-NoLogo", L"-NoProfile", L"-NonInteractive", L"-ExecutionPolicy", L"Bypass",
            L"-File", scriptPath_.wstring(), L"-Name", sessionName_,
            L"-AdapterGuid", GuidText(adapter.guid), L"-AdapterIndex", std::to_wstring(adapter.index),
            L"-ControllerPid", std::to_wstring(GetCurrentProcessId()),
            L"-ReadyPath", readyPath_.wstring(), L"-StopPath", stopPath_.wstring()
        };
        auto commandLine = BuildCommandLine(executable, arguments);
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        startup.wShowWindow = SW_HIDE;
        startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        startup.hStdOutput = log_.get();
        startup.hStdError = log_.get();
        PROCESS_INFORMATION process{};
        if (!CreateProcessW(executable.c_str(), commandLine.data(), nullptr, nullptr, TRUE,
            CREATE_NO_WINDOW, nullptr, helperDirectory_.c_str(), &startup, &process)) {
            FailWin32("ndiscap_session_helper_start_failed");
        }
        process_.reset(process.hProcess);
        launched_ = true;
        Handle thread(process.hThread);

        const auto expectedName = NarrowAscii(sessionName_);
        const auto expectedAdapter = NarrowAscii(GuidText(adapter.guid));
        const auto expectedIndex = std::to_string(adapter.index);
        const ULONGLONG deadline = GetTickCount64() + 30000;
        while (GetTickCount64() < deadline) {
            checkIntent();
            DWORD exitCode = STILL_ACTIVE;
            if (!GetExitCodeProcess(process_.get(), &exitCode)) FailWin32("ndiscap_session_helper_state_failed");
            if (exitCode != STILL_ACTIVE) {
                Fail("ndiscap_session_helper_exit_" + std::to_string(exitCode));
            }
            const auto ready = ReadTextIfPresent(readyPath_, 1024);
            if (!ready.empty()) {
                ValidateReadyRecord(ready, expectedName, expectedAdapter, expectedIndex);
                if (WaitForSingleObject(process_.get(), 0) != WAIT_TIMEOUT) {
                    Fail("ndiscap_session_helper_exited_after_ready");
                }
                started_ = true;
                return;
            }
            Sleep(50);
        }
        (void)Stop(std::chrono::seconds{30});
        Fail("ndiscap_session_start_timeout");
    }

    bool IsRunning() const {
        if (!process_) return false;
        const DWORD state = WaitForSingleObject(process_.get(), 0);
        if (state == WAIT_TIMEOUT) return true;
        if (state == WAIT_OBJECT_0) return false;
        if (state == WAIT_FAILED) FailWin32("ndiscap_session_helper_wait_failed");
        Fail("ndiscap_session_helper_state_invalid");
    }

    bool Stop(std::chrono::seconds timeout = std::chrono::seconds{30}) {
        if (!process_) {
            if (launched_) return stopped_;
            if (!helperDirectoryCreated_) return true;
            stopped_ = CleanupHelperDirectory();
            return stopped_;
        }
        const DWORD initialState = WaitForSingleObject(process_.get(), 0);
        if (initialState == WAIT_FAILED) return false;
        if (initialState == WAIT_TIMEOUT && !stopRequested_) {
            try {
                WriteAtomic(stopPath_, "ndiscap_stop=1\n");
                stopRequested_ = true;
            } catch (...) {
                return false;
            }
        }
        const ULONGLONG deadline = GetTickCount64() +
            static_cast<ULONGLONG>(std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count());
        for (;;) {
            const DWORD state = WaitForSingleObject(process_.get(), 0);
            if (state == WAIT_OBJECT_0) break;
            if (state == WAIT_FAILED) return false;
            if (state != WAIT_TIMEOUT || GetTickCount64() >= deadline) return false;
            Sleep(50);
        }
        DWORD exitCode = STILL_ACTIVE;
        if (!GetExitCodeProcess(process_.get(), &exitCode) || exitCode == STILL_ACTIVE) return false;
        process_.reset();
        const bool scriptCompleted = exitCode == 0 || (!started_ && exitCode == 1);
        const bool filesRemoved = CleanupHelperDirectory();
        stopped_ = scriptCompleted && filesRemoved;
        return stopped_;
    }

    const std::wstring& name() const { return sessionName_; }
    bool wasStarted() const { return started_; }

private:
    static void ValidateReadyRecord(const std::string& contents, const std::string& name,
        const std::string& adapterGuid, const std::string& adapterIndex) {
        std::istringstream input(contents);
        std::array<std::string, 5> lines{};
        for (auto& line : lines) {
            if (!std::getline(input, line)) Fail("ndiscap_ready_record_invalid");
        }
        std::string extra;
        if (std::getline(input, extra) || lines[0] != "ndiscap_ready=1" ||
            lines[1] != "session_name=" + name || lines[3] != "adapter_guid=" + adapterGuid ||
            lines[4] != "adapter_ifindex=" + adapterIndex || !lines[2].starts_with("session_guid=")) {
            Fail("ndiscap_ready_record_invalid");
        }
        const auto guidText = std::wstring(lines[2].begin() + 13, lines[2].end());
        GUID sessionGuid{};
        if (guidText.size() != 38 || CLSIDFromString(guidText.c_str(), &sessionGuid) != S_OK ||
            IsEqualGUID(sessionGuid, GUID_NULL)) Fail("ndiscap_ready_session_identity_invalid");
    }

    bool CleanupHelperDirectory() {
        log_.reset();
        bool filesRemoved = true;
        filesRemoved = RemoveOwnedNdiscapHelperFile(scriptPath_) && filesRemoved;
        filesRemoved = RemoveOwnedNdiscapHelperFile(readyPath_) && filesRemoved;
        filesRemoved = RemoveOwnedNdiscapHelperFile(readyTempPath_) && filesRemoved;
        filesRemoved = RemoveOwnedNdiscapHelperFile(stopPath_) && filesRemoved;
        filesRemoved = RemoveOwnedNdiscapHelperFile(stopTempPath_) && filesRemoved;
        filesRemoved = RemoveOwnedNdiscapHelperFile(logPath_) && filesRemoved;
        if (!helperDirectoryCreated_ || !filesRemoved) return filesRemoved;
        if (RemoveDirectoryW(helperDirectory_.c_str())) {
            helperDirectoryCreated_ = false;
            return true;
        }
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            helperDirectoryCreated_ = false;
            return true;
        }
        return false;
    }

    fs::path helperDirectory_, scriptPath_, readyPath_, readyTempPath_, stopPath_, stopTempPath_, logPath_;
    std::wstring sessionName_;
    Handle process_, log_;
    bool helperDirectoryCreated_{}, launched_{}, started_{}, stopRequested_{}, stopped_{};
};

bool HasExactMarker(const fs::path& path, const char* expected) {
    const std::string actual = ReadTextIfPresent(path, 4096);
    if (actual == expected) return true;
    std::string windowsText;
    windowsText.reserve(std::char_traits<char>::length(expected) + 4);
    for (const char* cursor = expected; *cursor; ++cursor) {
        if (*cursor == '\n') windowsText.push_back('\r');
        windowsText.push_back(*cursor);
    }
    return actual == windowsText;
}

bool IsAdministrator() {
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID administrators = nullptr;
    if (!AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administrators)) FailWin32("administrator_sid_create_failed");
    BOOL member = FALSE;
    const BOOL queried = CheckTokenMembership(nullptr, administrators, &member);
    FreeSid(administrators);
    if (!queried) FailWin32("administrator_token_query_failed");
    return member != FALSE;
}

std::optional<PROCESSENTRY32W> FindActiveTransferHelper() {
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) FailWin32("process_snapshot_failed");
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot.get(), &entry)) FailWin32("process_snapshot_read_failed");
    do {
        if (entry.th32ProcessID == GetCurrentProcessId()) continue;
        namespace helpers = dropporter::helper_files;
        if (_wcsicmp(entry.szExeFile, helpers::Wireless) == 0 ||
            _wcsicmp(entry.szExeFile, helpers::Receiver) == 0 ||
            _wcsicmp(entry.szExeFile, helpers::DiagnosticProbe) == 0 ||
            _wcsicmp(entry.szExeFile, helpers::DiagnosticReceiver) == 0) {
            return entry;
        }
    } while (Process32NextW(snapshot.get(), &entry));
    const DWORD error = GetLastError();
    if (error != ERROR_NO_MORE_FILES) FailWin32("process_snapshot_read_failed", error);
    return std::nullopt;
}

void WaitForTransferHelpersToExit(const std::function<void()>& checkIntent,
    const std::function<void(const std::string&)>& record) {
    const ULONGLONG deadline = GetTickCount64() + 3000;
    for (bool first = true; ; first = false) {
        checkIntent();
        const auto active = FindActiveTransferHelper();
        if (!active) return;
        if (first) record("waiting_for_helper pid=" + std::to_string(active->th32ProcessID) +
            " image=" + NarrowAscii(active->szExeFile));
        if (GetTickCount64() >= deadline) {
            record("blocking_helper pid=" + std::to_string(active->th32ProcessID) +
                " image=" + NarrowAscii(active->szExeFile));
            Fail(supervisor::TransferHelperBusyReason);
        }
        Sleep(100);
    }
}

void PublishRadioLease(const fs::path& capture) {
    OwnedMutex guard(tx10ub::radio_lease::MutexName, tx10ub::radio_lease::MutexWaitMs);
    // The timestamp only serves the live child. Recovery uses the durable journal.
    WriteAtomic(capture / tx10ub::radio_lease::FileName,
                tx10ub::radio_lease::Encode(GetCurrentProcessId(), GetTickCount64()), false);
}

// Keep the child's lease fresh while the supervisor performs bounded work.
// If the supervisor stalls, publication stops and the child expires its lease.
class RadioLeaseHeartbeat {
    std::mutex mutex_;
    std::condition_variable condition_;
    std::chrono::steady_clock::time_point deadline_;
    bool stopping_=false,failed_=false;
    std::thread worker_;
public:
    RadioLeaseHeartbeat(fs::path capture, std::chrono::milliseconds supervisorBudget):
        deadline_(std::chrono::steady_clock::now()+supervisorBudget),
        worker_([this,capture=std::move(capture)] {
        std::unique_lock lock(mutex_);
        while(!condition_.wait_for(lock,std::chrono::milliseconds{250},[&]{return stopping_;})) {
            if(std::chrono::steady_clock::now()>=deadline_) {failed_=true;return;}
            lock.unlock();
            try {PublishRadioLease(capture);}
            catch(...) {lock.lock();failed_=true;return;}
            lock.lock();
        }
    }) {}
    ~RadioLeaseHeartbeat() {
        {std::lock_guard lock(mutex_);stopping_=true;}
        condition_.notify_one();
        worker_.join();
    }
    void SupervisedFor(std::chrono::milliseconds budget) {
        std::lock_guard lock(mutex_);
        const auto now=std::chrono::steady_clock::now();
        if(failed_||now>=deadline_)Fail("radio_lease_heartbeat_failed");
        deadline_=now+budget;
    }
};

struct EventState {
    std::string transferStage = events::Preparing;
    supervisor::Phase status = supervisor::Phase::Preparing;
    std::string failureStage;
    std::string failureReason;
    std::string failureHttpStatus = "0";
    std::string progress;
    std::string carry;
    bool uploadSucceeded{};
    bool transportClosed{};
    bool receiveWaiting{};
    bool targetSelected{};
    bool radioHandoffWaiting{};
    bool sendWide44{};
    bool receiveHandoffWaiting{};
    bool receiveWide44{};
    bool receiveTcpActive{};
    bool discoveryEmpty{};
};

void RecordDiscoveryCompletion(EventState& state, DWORD childExit) {
    // Code 15 is also used by later connection timeouts. Only a completed
    // browse with an explicit zero-endpoint result establishes "not found".
    if (childExit == 15 && state.transferStage == events::Discovery &&
        state.discoveryEmpty && state.failureReason.empty()) {
        state.failureStage = events::Discovery;
        state.failureReason = "not_found";
    }
}

bool SendUploadCompleted(const EventState& state, DWORD childExit) {
    // The controller requests normal discovery shutdown after the upload
    // owner drains. The probe can then return its operator-stop code (16).
    // Only the peer's upload success and closed transport establish transfer
    // completion; final status still requires confirmed shutdown and Wi-Fi.
    return state.uploadSucceeded && state.transportClosed && (childExit == 0 || childExit == 16);
}

void ParseChildLines(EventState& state, std::string_view text, bool final = false) {
    std::string combined = state.carry;
    combined.append(text);
    size_t start = 0;
    for (;;) {
        const size_t newline = combined.find('\n', start);
        if (newline == std::string::npos) break;
        std::string line = combined.substr(start, newline - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line == events::ReceiveWaiting) { state.receiveWaiting = true; state.status = supervisor::Phase::Listening; }
        if (line.starts_with(events::ReceiveConnected)) {
            state.receiveTcpActive=true;
            state.receiveHandoffWaiting=false;
        }
        if (line == events::ReceiveTcpIdle) state.receiveTcpActive=false;
        if (line == events::NoEndpoints && state.transferStage == events::Discovery) state.discoveryEmpty = true;
        if (line.starts_with(events::StagePrefix)) {
            const auto stage = line.substr(events::StagePrefix.size());
            if (stage == events::Discovery || stage == events::Connect || stage == events::Tls || stage == events::Discover || stage == events::Ask || stage == events::Upload) {
                state.transferStage = stage;
                if(stage != events::Discovery)state.radioHandoffWaiting=false;
                if (stage == events::Discovery) state.status = supervisor::Phase::Discovering;
                else if (stage == events::Ask) state.status = supervisor::Phase::WaitingAccept;
                else if (stage == events::Upload) state.status = supervisor::Phase::Sending;
                else state.status = supervisor::Phase::Connecting;
            }
        }
        if (line == events::TargetWaiting) { state.status = supervisor::Phase::Selecting; state.transferStage = events::Select; }
        if (line == events::TargetSelected) {
            state.targetSelected=true; state.status = supervisor::Phase::Connecting; state.transferStage = events::Connect;
        }
        if (line.starts_with(events::RadioHandoff)) {
            const auto mode = std::string_view(line).substr(std::string_view(events::RadioHandoff).size());
            if ((mode == events::HandoffSend || mode == events::HandoffSendWide) && state.targetSelected) {
                state.radioHandoffWaiting = true;
                state.sendWide44 = mode == events::HandoffSendWide;
            }
            if ((mode == events::HandoffReceive || mode == events::HandoffReceiveWide) &&
                state.receiveWaiting && !state.receiveTcpActive) {
                state.receiveHandoffWaiting = true;
                state.receiveWide44 = mode == events::HandoffReceiveWide;
            }
            if (mode == events::HandoffIdle) {
                state.radioHandoffWaiting = false;
                state.sendWide44 = false;
                state.receiveHandoffWaiting = false;
                state.receiveWide44 = false;
            }
        }
        if (line.starts_with(events::AskQueued)) state.status = supervisor::Phase::WaitingAccept;
        if (line.starts_with(events::AskAccepted)) state.status = supervisor::Phase::Sending;
        if (line == events::UploadWaiting) state.status = supervisor::Phase::Finalizing;
        if (line.rfind(events::UploadSucceeded, 0) == 0) state.uploadSucceeded = true;
        if (line.rfind(events::TransportClosed, 0) == 0) state.transportClosed = true;
        if (state.failureReason.empty() && line.starts_with(events::FailurePrefix)) {
            const auto stageAt = events::FailurePrefix.size();
            const auto reasonAt = line.find(events::FailureReason, stageAt);
            const auto httpAt = line.find(events::FailureHttpStatus, reasonAt == std::string::npos ? stageAt : reasonAt + events::FailureReason.size());
            if (reasonAt != std::string::npos && httpAt != std::string::npos) {
                state.failureStage = line.substr(stageAt, reasonAt - stageAt);
                state.failureReason = line.substr(reasonAt + events::FailureReason.size(), httpAt - (reasonAt + events::FailureReason.size()));
                state.failureHttpStatus = line.substr(httpAt + events::FailureHttpStatus.size());
            }
        }
        if (const auto progress = events::ParseProgressEvent(line, tx10ub::send_files::MaxBytes))
            state.progress = events::EncodeProgressFile(*progress);
        start = newline + 1;
    }
    state.carry = combined.substr(start);
    if (state.carry.size() > 4096) state.carry.erase(0, state.carry.size() - 4096);
    if (final && !state.carry.empty()) {
        const std::string tail = state.carry;
        state.carry.clear();
        ParseChildLines(state, tail + "\n", false);
    }
}

void WriteStatus(const Context& context, const std::string& status, const std::string& progress,
    bool updateProgress) {
    try {
        WriteAtomic(context.statusPath, status);
    } catch (...) { }
    if (updateProgress && !progress.empty()) {
        try { WriteAtomic(context.progressPath, progress); }
        catch (...) { }
    }
}

bool CopyTargetBridge(const Context& context, std::string& lastTargets,unsigned& refreshGeneration) {
    const auto targetPath = context.capture / target_files::ListName;
    const auto contents = ReadTextIfPresent(targetPath, 1024 * 1024);
    if (contents.empty()) return false;
    if (!contents.starts_with(target_files::Round)) return false;
    const auto lineEnd = contents.find('\n');
    if (lineEnd == std::string::npos) return false;
    const auto number = std::string_view(contents).substr(target_files::Round.size(), lineEnd - target_files::Round.size());
    const auto round = target_files::ParseNumber(number, target_files::MaxRound);
    if (!round) return false;
    if (contents != lastTargets) {
        WriteAtomic(context.requestDir / target_files::ListName, contents);
        lastTargets = contents;
    }
    if(refreshGeneration < target_files::MaxRound) {
        const auto marker=target_files::RefreshName(refreshGeneration + 1);
        if(HasExactMarker(context.requestDir / marker, target_files::RefreshContent)) {
            WriteAtomic(context.capture / marker, target_files::RefreshContent);
            ++refreshGeneration;
        }
    }
    const auto selection = context.requestDir / (context.request.selectFiles ?
        std::wstring(target_files::CommittedSelectionName) : target_files::SelectionName(*round));
    const auto forwarded = context.capture / selection.filename();
    if (GetFileAttributesW(forwarded.c_str()) != INVALID_FILE_ATTRIBUTES) return true;
    if (context.request.selectFiles) {
        std::optional<std::string> committed;
        try {
            OwnerImpersonation owner(context.ownerImpersonationToken.get());
            committed = dropporter::send_selection::Read(selection);
            owner.Revert();
            if (!committed) return true;
            (void)dropporter::send_selection::Parse(*committed);
        } catch (const std::exception&) {
            Fail(dropporter::send_selection::InvalidReason);
        }
        WriteAtomic(forwarded, *committed);
        return true;
    }
    if (GetFileAttributesW(selection.c_str()) == INVALID_FILE_ATTRIBUTES) return true;
    const auto selected = ReadTextIfPresent(selection, 32);
    if (selected.size() > 3 || !target_files::ParseNumber(selected, target_files::MaxTargetId)) {
        Fail("target_selection_invalid");
    }
    WriteAtomic(forwarded, selected);
    return true;
}

void LocateRuntimeFiles(Context& context) {
    namespace helpers = dropporter::helper_files;
    context.probePath = context.executableDir / helpers::Wireless;
    context.workerPath = context.executableDir / helpers::Receiver;

    fs::path root = context.executableDir;
    for (unsigned depth = 0; depth < 8 && !root.empty(); ++depth) {
        if (fs::is_regular_file(root / L"tools/Tx10ubProbe.vcxproj")) {
            const auto probe = root / L"tools/x64/Tx10ubProbe/AwdlFormat/Release/Tx10ubProbe.exe";
            const auto worker = root / helpers::DiagnosticReceiverPath;
            const auto packageSys = root / L"artifacts/DropPorter/AWDLWinTx10ubProbe.sys";
            if (!fs::is_regular_file(context.probePath) && !fs::is_regular_file(context.workerPath) &&
                fs::is_regular_file(probe) && fs::is_regular_file(worker)) {
                context.probePath = probe;
                context.workerPath = worker;
            }
            if (!fs::is_regular_file(context.sysPath) && fs::is_regular_file(packageSys)) context.sysPath = packageSys;
            break;
        }
        const auto parent = root.parent_path();
        if (parent == root) break;
        root = parent;
    }
    if (!fs::is_regular_file(context.probePath) || !fs::is_regular_file(context.workerPath)) {
        Fail("runtime_package_incomplete_probe_or_receive_worker");
    }
}

void RequireAuxiliaryStopped() {
    ScHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager.get()) FailWin32("auxiliary_manager_open_failed");
    ScHandle service(OpenServiceW(manager.get(), kServiceName, SERVICE_QUERY_STATUS));
    if (!service.get()) {
        if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) return;
        FailWin32("auxiliary_status_open_failed");
    }
    SERVICE_STATUS_PROCESS status{}; DWORD bytes{};
    if (!QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO,
        reinterpret_cast<BYTE*>(&status), sizeof(status), &bytes)) FailWin32("auxiliary_state_query_failed");
    if (status.dwCurrentState != SERVICE_STOPPED) Fail("auxiliary_must_be_stopped_for_direct_control");
}

std::pair<ULONG, ULONG> ReadDirectRxSettings(const Adapter& adapter) {
    tx10ub::direct_ihv::DirectIhv direct(adapter);
    const auto filter = direct.ReadMac(tx10ub::direct_ihv::MacRegister::Ce20);
    const auto data = direct.ReadMac(tx10ub::direct_ihv::MacRegister::Ce2c);
    const auto valid = [](const auto& result) {
        return result.win32Status == ERROR_SUCCESS && result.value.has_value() &&
            result.responseValidation == tx10ub::direct_ihv::ResponseValidation::Valid &&
            result.acceptance == tx10ub::direct_ihv::RequestAcceptance::Accepted;
    };
    if (!valid(filter) || !valid(data)) throw tx10ub::host::RxReadbackError(
        "direct_rx_readback_failed ce20_status=" + std::to_string(filter.win32Status) +
        " ce20_bytes=" + std::to_string(filter.response.size()) +
        " ce20_validation=" + std::to_string(static_cast<unsigned>(filter.responseValidation)) +
        " ce2c_status=" + std::to_string(data.win32Status) +
        " ce2c_bytes=" + std::to_string(data.response.size()) +
        " ce2c_validation=" + std::to_string(static_cast<unsigned>(data.responseValidation)),
        filter.transportQuarantined || data.transportQuarantined);
    return {*filter.value, *data.value};
}

void SaveRxBaselineForSavedWifi(RuntimeJournal& journal, const std::pair<ULONG, ULONG>& filters) {
    journal.originalRxFilter = filters.first;
    journal.originalRxDataFilter = filters.second;
    SetJournalFlag(journal, JournalRxBaselineMatchesSavedWifi, true);
}

void WaitForTransferWifiState(const WifiRadio& radio, const std::function<void()>& checkIntent,
    bool disconnectedOnly) {
    constexpr ULONGLONG stableMs = 750;
    const ULONGLONG deadline = GetTickCount64() + 8000;
    auto previous = wlan_interface_state_not_ready;
    ULONGLONG stableSince = 0;
    while (GetTickCount64() < deadline) {
        checkIntent();
        const auto state = radio.InterfaceState();
        const auto now = GetTickCount64();
        const bool eligible = state == wlan_interface_state_disconnected ||
            (!disconnectedOnly && state == wlan_interface_state_connected);
        if (!eligible || state != previous) stableSince = now;
        if (eligible && now - stableSince >= stableMs) return;
        previous = state;
        Sleep(50);
    }
    Fail("target_wifi_interface_not_stable");
}

void CaptureConnectedRxBaseline(RuntimeJournal& journal, const Adapter& adapter,
    const WifiRadio& radio, const WifiSnapshot& savedWifi) {
    if (savedWifi.state != wlan_interface_state_connected || !savedWifi.autoconfEnabled) return;
    const auto filters = ReadDirectRxSettings(adapter);
    const auto sampledWifi = radio.Capture();
    if (sampledWifi.state != savedWifi.state || sampledWifi.autoconfEnabled != savedWifi.autoconfEnabled ||
        sampledWifi.profileName != savedWifi.profileName || sampledWifi.bssid != savedWifi.bssid ||
        sampledWifi.channel != savedWifi.channel) Fail("target_wifi_interface_not_stable");
    SaveRxBaselineForSavedWifi(journal, filters);
}

class RxSettingsMismatch final : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

bool RestoredRxMatches(const std::pair<ULONG, ULONG>& expected,
    const std::pair<ULONG, ULONG>& actual, bool disconnectedSharedNdiscap) {
    if (actual == expected) return true;
    // The 128.4 driver returned both complete CE20 values in disconnected
    // station mode, before and after AutoConfig ran. CE2C must still match.
    const auto observedDisconnected = [](ULONG ce20) {
        return ce20 == 0x0816440Eu || ce20 == 0x081644BEu;
    };
    return disconnectedSharedNdiscap && actual.second == expected.second &&
        observedDisconnected(actual.first) && observedDisconnected(expected.first);
}

void VerifyRestoredRxSettings(const Adapter& adapter, const std::pair<ULONG, ULONG>& expected,
    bool disconnectedSharedNdiscap) {
    const ULONGLONG deadline = GetTickCount64() + 5000;
    std::exception_ptr readError;
    std::pair<ULONG, ULONG> actual{};
    do {
        try {
            actual = ReadDirectRxSettings(adapter);
            if (RestoredRxMatches(expected, actual, disconnectedSharedNdiscap)) return;
            readError = nullptr;
        } catch (const tx10ub::host::RxReadbackError& error) {
            if (error.lowerCompletionUnconfirmed()) throw;
            readError = std::current_exception();
        }
        Sleep(200);
    } while (GetTickCount64() < deadline);
    if (readError) std::rethrow_exception(readError);
    std::ostringstream error;
    error << "original_rx_filters_not_restored expected=" << std::hex << expected.first << '/' << expected.second
          << " actual=" << actual.first << '/' << actual.second;
    throw RxSettingsMismatch(error.str());
}

std::optional<std::pair<ULONG, ULONG>> RxSettingsForRestart(
    const RuntimeJournal& journal, const tx10ub::host::AdapterProfile* legacyUsbProfile) {
    const bool ndiscap = legacyUsbProfile == nullptr;
    if (ndiscap && HasJournalFlag(journal, JournalRxBaselineMatchesSavedWifi))
        return std::pair{journal.originalRxFilter, journal.originalRxDataFilter};
    // Older snapshots recorded filters while disconnected, even if the saved Wi-Fi was connected.
    if (HasJournalFlag(journal, JournalRadioBaselineCaptured) &&
        (ndiscap ? journal.wifiState == wlan_interface_state_disconnected && journal.wifiAutoconf == 1
                 : legacyUsbProfile->verifiesRxSettingsAfterRestart))
        return std::pair{journal.originalRxFilter, journal.originalRxDataFilter};
    return std::nullopt;
}

Adapter RestartTransferAdapter(const Adapter& adapter, const WifiSnapshot& wifi,
    tx10ub::host::NetworkRestartTimings* timings, bool ndiscap, const RuntimeJournal& journal) {
    using namespace tx10ub::host;
    const auto* legacyUsbProfile = ndiscap ? nullptr : &ProfileOf(adapter);
    const auto savedRx = RxSettingsForRestart(journal, legacyUsbProfile);
    const auto purpose = ndiscap ? RestartPurpose::DirectIhvSession : RestartPurpose::UsbCaptureSession;
    const bool portCycle = legacyUsbProfile && legacyUsbProfile->usbCaptureRestartCyclesPort;
    auto restored = RestartNetworkAndRestoreWifi(adapter, wifi, timings, purpose);
    if (savedRx) {
        const bool disconnectedSharedNdiscap = ndiscap && wifi.state == wlan_interface_state_disconnected &&
            adapter.driverImage == DriverImage::Shared;
        try {
            VerifyRestoredRxSettings(restored, *savedRx, disconnectedSharedNdiscap);
        } catch (const RxSettingsMismatch&) {
            if (!portCycle) throw;
            // A second port cycle can restore the stock RX settings after a
            // completed first cycle that left different readable values.
            restored = RestartNetworkAndRestoreWifi(restored, wifi, timings, purpose);
            VerifyRestoredRxSettings(restored, *savedRx, false);
        }
    }
    return restored;
}


class Supervisor {
public:
    explicit Supervisor(Context context) : context_(std::move(context)), events_{} {}

    int Run() {
        const auto started = GetTickCount64();
        bool transferSucceeded = false;
        bool cancelled = false;
        bool shutdownConfirmed = false;
        bool restorationRequired = false;
        bool apRestored = false, auxiliaryRestored = false, rxReinitialized = false;
        bool vendorStateUnchanged = false;
        bool childStarted = false, childExited = false;
        bool safeToRestore = true;
        bool preparationCancelled = false;
        std::string primaryFailure, statusWarning, restoreBlockReason;
        auto finalStatus = supervisor::Phase::Failed;
        auto lastPublishedStatus = supervisor::Phase::Unknown;
        std::string lastPublishedProgress;
        ULONGLONG lastStatusWrite = 0;
        std::string lastTargets;
        unsigned refreshGeneration=0;
        bool stopRequested{};
        std::uint64_t logPosition = 0;
        fs::path controllerLog = context_.candidate / L"controller.txt";
        Handle child, childLog;
        std::unique_ptr<OwnedMutex> globalMutex;
        std::unique_ptr<OwnedMutex> legacyRadioMutex;
        std::unique_ptr<WifiRadio> radio;
        std::unique_ptr<VendorTransport> vendor;
        std::unique_ptr<NdiscapSessionOwner> ndiscapSession;
        WifiSnapshot savedWifi{};
        BbState originalBb{};
        Channel originalChannel{};
        ULONG activeChannel=6;
        const Channel activeRadio{0,6,0,0};
        BbState expectedActiveBb{6,0,0,0,1};
        unsigned completedChannelGeneration=0;
        std::array<UCHAR, 32> realtekHash{};
        bool realtekCaptured = false;
        Adapter sessionAdapter{};
        auto journalStorage = std::make_unique<RuntimeJournal>();
        RuntimeJournal& journal = *journalStorage;
        bool journalReady = false;
        const fs::path journalPath = context_.candidate / markers::RadioSnapshotFileName;
        auto persistJournal = [&]() {
            if (journalReady) WriteRuntimeJournal(journalPath, journal);
        };
        auto beginVendorOperation = [&]() {
            SetJournalFlag(journal, JournalVendorOperationPending, true);
            persistJournal();
        };
        auto completeVendorOperation = [&]() {
            SetJournalFlag(journal, JournalVendorOperationPending, false);
            try { persistJournal(); }
            catch (...) {
                SetJournalFlag(journal, JournalVendorOperationPending, true);
                throw;
            }
        };
        auto markVendorOperationUnconfirmed = [&]() {
            safeToRestore = false;
            restoreBlockReason = "vendor_transport_completion_unconfirmed";
            SetJournalFlag(journal, JournalLowerFenceUnconfirmed, true);
            persistJournal();
        };
        auto readVendorBb = [&]() {
            beginVendorOperation();
            try {
                const BbState value = vendor->ReadBb();
                completeVendorOperation();
                return value;
            } catch (...) {
                markVendorOperationUnconfirmed();
                throw;
            }
        };
        auto closeVendorTransport = [&]() {
            if (!vendor) return true;
            const bool priorOperationUnconfirmed = HasJournalFlag(journal, JournalVendorOperationPending);
            if (!priorOperationUnconfirmed) beginVendorOperation();
            try {
                vendor->Close();
                if (priorOperationUnconfirmed || vendor->undrained() || vendor->has_pending() || vendor->poisoned()) {
                    markVendorOperationUnconfirmed();
                    return false;
                }
                completeVendorOperation();
                vendor.reset();
                return true;
            } catch (...) {
                markVendorOperationUnconfirmed();
                return false;
            }
        };

        auto record = [&](const std::string& line) {
            try { AppendLine(controllerLog, line); }
            catch (const std::exception& error) {
                if (statusWarning.empty()) statusWarning = std::string("controller_log_write_failed: ") + error.what();
            }
        };
        auto setStatus = [&](supervisor::Phase value, bool force = false) {
            events_.status = value;
            const ULONGLONG now = GetTickCount64();
            const bool statusChanged = value != lastPublishedStatus;
            const bool progressChanged = events_.progress != lastPublishedProgress;
            const bool due = now - lastStatusWrite >= 250;
            if (!force && !statusChanged && !due) return;
            const bool writeProgress = progressChanged && (force || statusChanged || due);
            try { WriteStatus(context_, supervisor::PhaseName(value), events_.progress, writeProgress); }
            catch (const std::exception& error) {
                if (statusWarning.empty()) statusWarning = std::string("status_write_failed: ") + error.what();
            }
            lastPublishedStatus = value;
            if (writeProgress) lastPublishedProgress = events_.progress;
            lastStatusWrite = now;
        };
        auto recordPrimary = [&](const std::string& value) {
            if (primaryFailure.empty()) { primaryFailure = value; record("controller_failure=" + value); }
        };
        auto requestStop = [&](const char* reason) {
            if (stopRequested) return;
            try {
                WriteAtomic(context_.capture / markers::ProbeStopFileName, reason);
                stopRequested = true;
                record(std::string("controller_stop_requested=") + reason);
            } catch (const std::exception& error) {
                if (statusWarning.empty()) statusWarning = std::string("stop_request_write_failed: ") + error.what();
            }
        };
        auto checkPreparationIntent = [&]() {
            if (GetFileAttributesW(context_.cancelPath.c_str()) != INVALID_FILE_ATTRIBUTES ||
                WaitForSingleObject(context_.owner.get(), 0) != WAIT_TIMEOUT) {
                cancelled = true;
                preparationCancelled = true;
                Fail("cancelled_before_active_probe");
            }
        };
        auto probeStillRunning = [&]() {
            const DWORD wait = WaitForSingleObject(child.get(), 0);
            if (wait == WAIT_OBJECT_0) return false;
            if (wait == WAIT_TIMEOUT) return true;
            if (wait == WAIT_FAILED) {
                const DWORD waitError = GetLastError();
                DWORD exitCode = STILL_ACTIVE;
                if (GetExitCodeProcess(child.get(), &exitCode) && exitCode != STILL_ACTIVE) {
                    if (statusWarning.empty()) statusWarning = "probe_wait_failed_exit_confirmed_" + std::to_string(waitError);
                    return false;
                }
                if (statusWarning.empty()) statusWarning = "probe_wait_failed_exit_unconfirmed_" + std::to_string(waitError);
                return true;
            }
            if (statusWarning.empty()) statusWarning = "probe_wait_returned_unexpected_state_" + std::to_string(wait);
            return true;
        };

        try {
            setStatus(supervisor::Phase::Preparing);
            LocateRuntimeFiles(context_);
            CreatePrivateRuntimeDirectory(context_.candidate);
            context_.capture = context_.candidate / L"capture";
            if (!CreateDirectoryW(context_.capture.c_str(), nullptr)) FailWin32("capture_directory_create_failed");
            record("runtime_start_tick=" + std::to_string(started));

            globalMutex = std::make_unique<OwnedMutex>(L"Global\\AWDLWinSend");
            legacyRadioMutex = std::make_unique<OwnedMutex>(L"Local\\AWDLWin-TX10UB-UnassociatedRx");
            if (!IsAdministrator()) Fail("administrator_token_required");
            WaitForTransferHelpersToExit(checkPreparationIntent, record);
            checkPreparationIntent();

            setStatus(supervisor::Phase::PreparingAdapter);
            record("send_state=preparing_adapter");
            auto adapter = tx10ub::host::DiscoverTransferAdapter();
            realtekHash = Sha256(tx10ub::host::RealtekServiceDriverPath());
            if (tx10ub::host::ClassifyDriverImage(realtekHash) != adapter.driverImage)
                Fail(supervisor::UnsupportedDriverReason);
            const bool sharedImage = adapter.driverImage == tx10ub::host::DriverImage::Shared;
            sessionAdapter = adapter;
            checkPreparationIntent();
            record("adapter_alias_utf8=" + Utf8(adapter.alias));
            record("adapter_luid=" + std::to_string(adapter.luid.Value));
            RequireAuxiliaryStopped();
            record("transfer_transport=ndiscap");
            checkPreparationIntent();
            realtekCaptured = true;
            record("stock_realtek_hash=" + NarrowAscii(HexWide(realtekHash)));

            // Set up capture before taking the Wi-Fi connection away from AutoConfig.
            // Starting the capture helper can take seconds, during which Windows may associate.
            ndiscapSession = std::make_unique<NdiscapSessionOwner>();
            ndiscapSession->Start(adapter, checkPreparationIntent);
            record("ndiscap_session_started=1");
            record("ndiscap_session_name=" + NarrowAscii(ndiscapSession->name()));
            record("ndiscap_session_adapter_guid=" + NarrowAscii(GuidText(adapter.guid)));
            record("ndiscap_session_adapter_ifindex=" + std::to_string(adapter.index));

            radio = std::make_unique<WifiRadio>(adapter);
            WaitForTransferWifiState(*radio, checkPreparationIntent, false);
            savedWifi = radio->Capture();
            if (savedWifi.state != wlan_interface_state_connected &&
                savedWifi.state != wlan_interface_state_disconnected) Fail("target_wifi_interface_not_stable");
            CaptureConnectedRxBaseline(journal, adapter, *radio, savedWifi);
            checkPreparationIntent();

            journal.ownerPid = context_.request.ownerPid;
            journal.controllerPid = GetCurrentProcessId();
            FILETIME created{}, exited{}, kernel{}, user{};
            if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) {
                FailWin32("runtime_process_creation_time_unavailable");
            }
            journal.controllerCreatedLow = created.dwLowDateTime;
            journal.controllerCreatedHigh = created.dwHighDateTime;
            CopyJournalAscii(journal.ownerSid, context_.ownerSid, "owner_sid");
            HANDLE currentTokenRaw = nullptr;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &currentTokenRaw)) FailWin32("runtime_token_open_failed");
            Handle currentToken(currentTokenRaw);
            CopyJournalAscii(journal.controllerSid, TokenSidString(currentToken.get()), "controller_sid");
            CopyJournalWide(journal.ownerLocalAppData, context_.ownerLocalAppData.wstring(), "local_appdata");
            CopyJournalWide(journal.candidateName, context_.request.candidateName, "candidate_name");
            journal.adapterGuid = adapter.guid;
            journal.adapterLuid = adapter.luid.Value;
            journal.adapterIndex = adapter.index;
            journal.wifiState = savedWifi.state;
            journal.wifiAutoconf = savedWifi.autoconfEnabled ? 1u : 0u;
            journal.wifiChannel = savedWifi.channel;
            std::copy(savedWifi.bssid.begin(), savedWifi.bssid.end(), journal.wifiBssid);
            CopyJournalWide(journal.wifiProfile, savedWifi.profileName, "wifi_profile");
            journal.wifiSsid = savedWifi.ssid;
            CopyJournalWide(journal.adapterInstanceId, adapter.instanceId, "adapter_instance_id");
            journal.runtimeTargetNetLuid = adapter.luid.Value;
            SetJournalFlag(journal, JournalDirectIhv, true);
            SetJournalFlag(journal, JournalSharedDriverImage, sharedImage);
            SetJournalFlag(journal, JournalTx20u1281DriverImage,
                adapter.driverImage == tx10ub::host::DriverImage::Tx20u1281);
            SetJournalFlag(journal, JournalTx20u1132DriverImage,
                adapter.driverImage == tx10ub::host::DriverImage::Tx20u1132);
            SetJournalFlag(journal, JournalWifiCaptured, true);
            WriteRuntimeJournal(journalPath, journal);
            journalReady = true;

            restorationRequired = true;
            checkPreparationIntent();
            auxiliaryRestored = true;
            record("direct_ihv_runtime=1; auxiliary_started=0");
            checkPreparationIntent();
            setStatus(supervisor::Phase::PreparingNetwork);
            record("send_state=preparing_network");

            if (radio->InterfaceState() == wlan_interface_state_connected) {
                if (savedWifi.state != wlan_interface_state_connected) Fail("target_wifi_interface_not_stable");
                restorationRequired = true;
                SetJournalFlag(journal, JournalDisconnectPending, true);
                persistJournal();
                radio->Disconnect();
                SetJournalFlag(journal, JournalDisconnectPending, false);
                SetJournalFlag(journal, JournalDisconnected, true);
                persistJournal();
            }
            checkPreparationIntent();

            restorationRequired = true;
            SetJournalFlag(journal, JournalAutoconfPending, true);
            persistJournal();
            // WlanIhvControl on this stack returns ERROR_NOT_SUPPORTED when
            // per-interface autoconfiguration is disabled. Keep the WLAN
            // control path available; the session lease requires disconnection.
            if (!radio->AutoconfEnabled()) radio->SetAutoconf(true);
            if (!radio->AutoconfEnabled()) Fail("autoconf_enable_not_confirmed");
            SetJournalFlag(journal, JournalAutoconfPending, false);
            SetJournalFlag(journal, JournalAutoconfChanged, true);
            persistJournal();
            WaitForTransferWifiState(*radio, checkPreparationIntent, true);
            checkPreparationIntent();

            // WPS state is reset with the exact Wi-Fi function at session end.
            // WLAN-only preparation cancellation needs no device restart.
            setStatus(supervisor::Phase::PreparingRadio);
            record("send_state=preparing_radio");
            SetJournalFlag(journal, JournalNetworkRestartPending, true);
            persistJournal();
            vendor = std::make_unique<VendorTransport>(adapter);
            try {
                beginVendorOperation();
                vendor->Open(adapter.driverImage);
                completeVendorOperation();
            } catch (...) {
                markVendorOperationUnconfirmed();
                throw;
            }
            checkPreparationIntent();

            const ULONGLONG stableDeadline = GetTickCount64() + 5000;
            bool baselineCaptured = false;
            std::pair<ULONG, ULONG> disconnectedRx{};
            do {
                originalBb = readVendorBb();
                Sleep(300);
                checkPreparationIntent();
                if (!(readVendorBb() == originalBb)) continue;

                SetJournalFlag(journal, JournalRxReadPending, true);
                persistJournal();
                try {
                    disconnectedRx = ReadDirectRxSettings(adapter);
                } catch (const tx10ub::host::RxReadbackError& error) {
                    SetJournalFlag(journal, JournalRxReadPending, false);
                    if (error.lowerCompletionUnconfirmed()) {
                        safeToRestore = false;
                        restoreBlockReason = "original_rx_readback_completion_unconfirmed";
                        SetJournalFlag(journal, JournalLowerFenceUnconfirmed, true);
                    }
                    persistJournal();
                    throw;
                } catch (...) {
                    safeToRestore = false;
                    restoreBlockReason = "original_rx_readback_failed";
                    SetJournalFlag(journal, JournalLowerFenceUnconfirmed, true);
                    persistJournal();
                    throw;
                }
                if (readVendorBb() == originalBb) {
                    baselineCaptured = true;
                    break;
                }
                SetJournalFlag(journal, JournalRxReadPending, false);
                persistJournal();
                break;
            } while (GetTickCount64() < stableDeadline);
            if (!baselineCaptured) Fail("original_channel_not_stable");
            SetJournalFlag(journal, JournalRxReadPending, false);
            record("original_bb encoded=" + std::to_string(originalBb.encoded) +
                " width=" + std::to_string(originalBb.width) +
                " primary_index=" + std::to_string(originalBb.primaryIndex) +
                " small_band=" + std::to_string(originalBb.smallBand) +
                " is_24ghz=" + std::to_string(originalBb.is24Ghz));
            originalChannel = vendor->ChannelFromBb(originalBb);
            journal.originalBbEncoded = originalBb.encoded;
            journal.originalBbWidth = originalBb.width;
            journal.originalBbPrimaryIndex = originalBb.primaryIndex;
            journal.originalBbSmallBand = originalBb.smallBand;
            journal.originalBbIs24Ghz = originalBb.is24Ghz;
            journal.originalChannelBand = originalChannel.band;
            journal.originalChannelPrimary = originalChannel.primary;
            journal.originalChannelWidth = originalChannel.width;
            journal.originalChannelOffset = originalChannel.offset;
            if (savedWifi.state == wlan_interface_state_disconnected && savedWifi.autoconfEnabled) {
                SaveRxBaselineForSavedWifi(journal, disconnectedRx);
            }
            SetJournalFlag(journal, JournalRadioBaselineCaptured, true);
            persistJournal();
            checkPreparationIntent();

            restorationRequired = true;
            SetJournalFlag(journal, JournalMonitorPending, true);
            persistJournal();
            beginVendorOperation();
            const auto monitorReply = vendor->Command({"echo", "core", "mon_mode", "0", "1"});
            completeVendorOperation();
            if (monitorReply.find("already in monitor mode") != std::string::npos) {
                SetJournalFlag(journal, JournalMonitorPending, false);
                SetJournalFlag(journal, JournalChannelOwned, false);
                persistJournal();
                Fail("preexisting_monitor_mode");
            }
            if (monitorReply.find("port 0 entered mon mode successfully") == std::string::npos) {
                if (monitorReply.find("scan in progress") != std::string::npos) {
                    SetJournalFlag(journal, JournalMonitorPending, false);
                    SetJournalFlag(journal, JournalChannelOwned, false);
                    persistJournal();
                } else {
                    if (monitorReply.find("enter mon mode failed") != std::string::npos)
                        record("monitor_enter_driver_failure=1");
                    safeToRestore = false;
                    restoreBlockReason = "monitor_enable_completion_unconfirmed";
                    SetJournalFlag(journal, JournalLowerFenceUnconfirmed, true);
                    persistJournal();
                }
                Fail("monitor_enable_not_confirmed");
            }
            SetJournalFlag(journal, JournalMonitorPending, false);
            SetJournalFlag(journal, JournalMonitorOwned, true);
            SetJournalFlag(journal, JournalRadioRestoreVerificationPending, true);
            persistJournal();
            checkPreparationIntent();
            SetJournalFlag(journal, JournalChannelPending, true);
            persistJournal();
            beginVendorOperation();
            record("session_channel="+std::to_string(activeChannel));
            vendor->SetChannel(activeRadio);
            const auto channelReadback = vendor->ReadBb();
            if (!(channelReadback == expectedActiveBb)) Fail("channel_readback_failed");
            completeVendorOperation();
            SetJournalFlag(journal, JournalChannelPending, false);
            SetJournalFlag(journal, JournalChannelOwned, true);
            persistJournal();
            checkPreparationIntent();

            if (context_.request.receive && GetFileAttributesW(
                (context_.requestDir / tx10ub::receive_state::FileName).c_str()) != INVALID_FILE_ATTRIBUTES) {
                Fail("receive_state_preexists");
            }

            childLog.reset(CreateFileW((context_.capture / events::LogFileName).c_str(), GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, nullptr));
            if (!childLog) FailWin32("probe_log_create_failed");
            if (!SetHandleInformation(childLog.get(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
                FailWin32("probe_log_inherit_failed");
            }
            constexpr auto monitorBudget = std::chrono::seconds{10};
            std::vector<std::wstring> childArgs{
                L"poc-discovery", L"0", std::to_wstring(activeChannel),
                std::to_wstring(activeChannel==6?1u:2u), L"both", L"20", L"0"
            };
            if (!ndiscapSession->IsRunning()) Fail("ndiscap_session_not_running");
            childArgs.insert(childArgs.end(), {L"--ndiscap-rx", ndiscapSession->name()});
            childArgs.insert(childArgs.end(), {L"--mdns-browse", L"--specific-action"});
            childArgs.insert(childArgs.end(), {L"--ble-v2-everyone", L"--unassociated-control",
                context_.capture.wstring(), L"--vendor-wps-raw-data", L"--vendor-encryption-disabled",
                L"--direct-ihv", L"--file-owner-pid", std::to_wstring(context_.request.ownerPid)});
            childArgs.insert(childArgs.end(), {L"--adapter-guid", GuidText(adapter.guid)});
            Handle sendInput;
            if (context_.request.receive) {
                childArgs.insert(childArgs.end(), {L"--airdrop-receive-destination", context_.filePath.wstring(),
                    L"--airdrop-receive-control", context_.requestDir.wstring()});
                if (context_.request.receiveAckRateMbps) {
                    childArgs.insert(childArgs.end(), {L"--receive-ack-rate-mbps",
                        std::to_wstring(context_.request.receiveAckRateMbps)});
                }
            } else if (context_.request.selectFiles) {
                childArgs.insert(childArgs.end(), {L"--airdrop-discover", L"--airdrop-send-selected",
                    L"--select-target", L"--peer-data-channel"});
            } else if (context_.sendPaths.empty()) {
                childArgs.insert(childArgs.end(), {L"--airdrop-discover", L"--airdrop-send-file",
                    context_.filePath.wstring(), L"--select-target", L"--peer-data-channel"});
            } else {
                // Pass the validated snapshot by handle, even when the paths exceed the process command-line limit.
                SECURITY_ATTRIBUTES inheritable{sizeof(inheritable), nullptr, TRUE};
                sendInput.reset(CreateFileW((context_.capture / L"send-files.tmp").c_str(), GENERIC_READ | GENERIC_WRITE,
                    0, &inheritable, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE |
                    FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
                if (!sendInput) FailWin32("send_file_list_create_failed");
                std::wstring paths;
                for (const auto& path : context_.sendPaths) { paths += path.native(); paths += L'\n'; }
                const DWORD size = static_cast<DWORD>(paths.size() * sizeof(wchar_t));
                DWORD written = 0;
                LARGE_INTEGER beginning{};
                if (!WriteFile(sendInput.get(), paths.data(), size, &written, nullptr) || written != size ||
                    !SetFilePointerEx(sendInput.get(), beginning, nullptr, FILE_BEGIN)) FailWin32("send_file_list_write_failed");
                childArgs.insert(childArgs.end(), {L"--airdrop-discover", L"--airdrop-send-stdin",
                    L"--select-target", L"--peer-data-channel"});
            }
            auto commandLine = BuildCommandLine(context_.probePath, childArgs);
            checkPreparationIntent();
            if (radio->InterfaceState() != wlan_interface_state_disconnected)
                Fail("target_wifi_interface_not_stable");
            PublishRadioLease(context_.capture);
            STARTUPINFOW startup{};
            startup.cb = sizeof(startup);
            startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            startup.wShowWindow = SW_HIDE;
            startup.hStdInput = sendInput ? sendInput.get() : GetStdHandle(STD_INPUT_HANDLE);
            startup.hStdOutput = childLog.get();
            startup.hStdError = childLog.get();
            PROCESS_INFORMATION process{};
            SetJournalFlag(journal, JournalProbeStartPending, true);
            persistJournal();
            if (!CreateProcessW(context_.probePath.c_str(), commandLine.data(), nullptr, nullptr,
                TRUE, CREATE_NO_WINDOW, nullptr, context_.probePath.parent_path().c_str(),
                &startup, &process)) FailWin32("probe_process_start_failed");
            child.reset(process.hProcess);
            sendInput.reset();
            Handle childThread(process.hThread);
            childStarted = true;
            // Four register reads, each with two one-second completion waits,
            // plus time for the supervisor's journal and status I/O.
            RadioLeaseHeartbeat heartbeat(context_.capture, monitorBudget);
            SetJournalFlag(journal, JournalProbeStartPending, false);
            SetJournalFlag(journal, JournalProbeStarted, true);
            persistJournal();
            setStatus(supervisor::Phase::Discovering);
            record("active_probe_started=1");
            ULONGLONG nextRadioCheck = 0;
            ULONGLONG receiveStopDeadline = 0;
            while (probeStillRunning()) {
                heartbeat.SupervisedFor(monitorBudget);
                const auto now = GetTickCount64();
                if (ndiscapSession && !ndiscapSession->IsRunning()) {
                    recordPrimary("ndiscap_session_helper_exited_during_transfer");
                    cancelled = true;
                }
                ParseChildLines(events_, ReadAppended(context_.capture / events::LogFileName, logPosition));
                if (events_.receiveWaiting && !context_.request.receive) {
                    recordPrimary("probe_receive_mode_mismatch");
                    cancelled = true;
                }
                if (events_.status == supervisor::Phase::Selecting) {
                    try { (void)CopyTargetBridge(context_, lastTargets,refreshGeneration); }
                    catch (const std::exception& error) {
                        statusWarning = std::string("target_selection_bridge_failed: ") + error.what();
                        if (std::string_view(error.what()) == dropporter::send_selection::InvalidReason) {
                            events_.failureReason = dropporter::send_selection::InvalidReason;
                            recordPrimary(events_.failureReason);
                            cancelled = true;
                        }
                    }
                }
                const bool operatorStop = GetFileAttributesW(context_.cancelPath.c_str()) != INVALID_FILE_ATTRIBUTES;
                if (operatorStop) {
                    cancelled = true;
                }
                const bool ownerAlive = WaitForSingleObject(context_.owner.get(), 0) == WAIT_TIMEOUT;
                if (!ownerAlive) cancelled = true;
                if (events_.transportClosed) cancelled = true; // The upload owner has drained its transport.
                const bool receiving = context_.request.receive;
                if(!cancelled && (receiving || completedChannelGeneration < 2) &&
                   completedChannelGeneration != (std::numeric_limits<unsigned>::max)()) {
                    const auto bytes=ReadTextIfPresent(context_.capture/
                        tx10ub::radio_handoff::request_name(completedChannelGeneration+1),96);
                    if(!bytes.empty()) {
                        const auto request=tx10ub::radio_handoff::parse(bytes, receiving);
                        if(!request)Fail("radio_channel_request_invalid");
                        if(request->generation>completedChannelGeneration) {
                            // waiting/selection are flushed before the child
                            // publishes its request; the loop's earlier read
                            // may have run just before those lines arrived.
                            ParseChildLines(events_,ReadAppended(context_.capture/events::LogFileName,logPosition));
                            if(!tx10ub::radio_handoff::admissible(*request,GetProcessId(child.get()),
                                    completedChannelGeneration,activeChannel,context_.request.receive?
                                    events_.receiveHandoffWaiting:events_.radioHandoffWaiting,
                                    cancelled,receiving))Fail("radio_channel_request_not_admissible");
                            checkPreparationIntent();
                            heartbeat.SupervisedFor(std::chrono::milliseconds{tx10ub::radio_handoff::acknowledgement_timeout_ms});
                            SetJournalFlag(journal,JournalChannelPending,true);
                            persistJournal();
                            beginVendorOperation();
                            const bool wide=request->to==44 &&
                                (context_.request.receive?events_.receiveWide44:events_.sendWide44);
                            const bool use80Mhz = wide && sharedImage && context_.request.wideChannelMhz == 80;
                            const ULONG channelWidth = use80Mhz ? 2u : (wide ? 1u : 0u);
                            const Channel requested{request->to==6?0u:1u,request->to,channelWidth,wide?1u:0u};
                            vendor->SetChannel(requested);
                            const auto expected=vendor->ReadBb();
                            const auto decoded=vendor->ChannelFromBb(expected);
                            if(decoded.band!=requested.band||decoded.primary!=requested.primary||
                               decoded.width!=requested.width||decoded.offset!=requested.offset)
                                Fail("radio_channel_handoff_readback_failed");
                            completeVendorOperation();
                            SetJournalFlag(journal,JournalChannelPending,false);
                            persistJournal();
                            activeChannel=request->to;
                            expectedActiveBb=expected;
                            completedChannelGeneration=request->generation;
                            heartbeat.SupervisedFor(monitorBudget);
                            WriteAtomic(context_.capture/tx10ub::radio_handoff::acknowledgement_name(request->generation),
                                tx10ub::radio_handoff::acknowledgement(*request));
                            record("data_channel_committed="+std::to_string(activeChannel));
                            if(use80Mhz)record(context_.request.receive?"receive_channel_readback=primary44_center42_width80":
                                "send_channel_readback=primary44_center42_width80");
                            else if(wide)record(context_.request.receive?"receive_channel_readback=primary44_center46_width40":
                                "send_channel_readback=primary44_center46_width40");
                        }
                    }
                }
                if (now >= nextRadioCheck) {
                    nextRadioCheck = now + 250;
                    try {
                        const auto wifiState = radio->InterfaceState();
                        if (wifiState != wlan_interface_state_disconnected || !(readVendorBb() == expectedActiveBb)) {
                            record("active_wifi_state=" + std::to_string(wifiState));
                            recordPrimary("target_radio_state_changed_during_active_session");
                            cancelled = true;
                        }
                    } catch (const std::exception& error) {
                        recordPrimary(std::string("active_radio_monitor_failed: ") + error.what());
                        cancelled = true;
                    }
                }
                if (cancelled) {
                    // The receiver observes cancel.request itself. Keep the radio lease
                    // for its final announcement only on an orderly receive stop.
                    const bool allowWithdrawal = receiving && events_.receiveWaiting && operatorStop &&
                        ownerAlive && primaryFailure.empty() && !events_.transportClosed && !stopRequested;
                    if (allowWithdrawal && !receiveStopDeadline)
                        receiveStopDeadline = now + markers::ReceiveWithdrawalWindowMs + 1000;
                    if (!allowWithdrawal || now >= receiveStopDeadline) requestStop("operator_request");
                    setStatus(supervisor::Phase::Restoring);
                } else {
                    setStatus(events_.status);
                }
                Sleep(50);
            }
            childExited = true;
            // A receiver can finish an orderly stop before the next supervisor poll.
            if (context_.request.receive && GetFileAttributesW(context_.cancelPath.c_str()) != INVALID_FILE_ATTRIBUTES)
                cancelled = true;
            DWORD childExit = 0;
            if (!GetExitCodeProcess(child.get(), &childExit)) FailWin32("probe_exit_code_query_failed");
            if (childExit == STILL_ACTIVE) {
                childExited = false;
                safeToRestore = false;
                restoreBlockReason = "active_probe_exit_state_unconfirmed";
                Fail("active_probe_exit_state_unconfirmed");
            }
            ParseChildLines(events_, ReadAppended(context_.capture / events::LogFileName, logPosition), true);
            RecordDiscoveryCompletion(events_, childExit);
            if (!context_.request.receive && SendUploadCompleted(events_, childExit)) transferSucceeded = true;
            shutdownConfirmed = HasExactMarker(context_.capture / markers::ProbeShutdownFileName,
                                                markers::ProbeShutdownContent);
            if (!shutdownConfirmed) {
                safeToRestore = false;
                restoreBlockReason = "active_probe_shutdown_unconfirmed";
                recordPrimary("active_probe_shutdown_unconfirmed; radio_and_service_restore_deferred");
            } else {
                SetJournalFlag(journal, JournalProbeStarted, false);
                SetJournalFlag(journal, JournalProbeStartPending, false);
                SetJournalFlag(journal, JournalShutdownConfirmed, true);
                persistJournal();
            }
            if (childExit != 0 && !cancelled && primaryFailure.empty()) {
                recordPrimary("active_probe_exit_" + std::to_string(childExit));
            }
            if (context_.request.receive) {
                const auto receiveState = ReadTextIfPresent(context_.requestDir / tx10ub::receive_state::FileName);
                transferSucceeded = primaryFailure.empty() && tx10ub::receive_state::ReadPhase(receiveState) ==
                    tx10ub::receive_state::Phase::Completed;
            }
        }
        catch (const std::exception& error) {
            if (preparationCancelled) record("preparation_cancelled=1");
            else recordPrimary(error.what());
            if (childStarted && !childExited) {
                cancelled = true;
                setStatus(supervisor::Phase::Restoring);
                requestStop("operator_request");
                // A started probe is never terminated. Continue pumping until its
                // own send/USB owner reports process exit.
                while (probeStillRunning()) {
                    try {
                        ParseChildLines(events_, ReadAppended(context_.capture / events::LogFileName, logPosition));
                        PublishRadioLease(context_.capture);
                        if (WaitForSingleObject(context_.owner.get(), 0) != WAIT_TIMEOUT) requestStop("operator_request");
                    } catch (...) { }
                    Sleep(250);
                }
                childExited = true;
                DWORD childExit = 0;
                if (GetExitCodeProcess(child.get(), &childExit)) {
                    ParseChildLines(events_, ReadAppended(context_.capture / events::LogFileName, logPosition), true);
                    shutdownConfirmed = HasExactMarker(context_.capture / markers::ProbeShutdownFileName,
                                                        markers::ProbeShutdownContent);
                    if (childExit == STILL_ACTIVE) shutdownConfirmed = false;
                }
                safeToRestore = shutdownConfirmed;
                if (!shutdownConfirmed) {
                    restoreBlockReason = "active_probe_shutdown_unconfirmed";
                } else {
                    SetJournalFlag(journal, JournalProbeStarted, false);
                    SetJournalFlag(journal, JournalProbeStartPending, false);
                    SetJournalFlag(journal, JournalShutdownConfirmed, true);
                    persistJournal();
                }
            }
            if (!childStarted && HasJournalFlag(journal, JournalProbeStartPending)) {
                SetJournalFlag(journal, JournalProbeStartPending, false);
                persistJournal();
            }
        }

        if (ndiscapSession) {
            const bool sessionStopped = ndiscapSession->Stop();
            if (sessionStopped) {
                if (ndiscapSession->wasStarted()) record("ndiscap_session_removed=1");
                else record("ndiscap_session_helper_stopped=1");
            } else {
                record("ndiscap_session_cleanup_unconfirmed=1");
                recordPrimary("ndiscap_session_cleanup_unconfirmed");
                transferSucceeded = false;
            }
        }

        if (childStarted && !childExited) {
            recordPrimary("probe_exit_state_uncertain");
            safeToRestore = false;
        }
        if (!childStarted) shutdownConfirmed = true;
        if (childStarted && !shutdownConfirmed) {
            safeToRestore = false;
            if (restoreBlockReason.empty()) restoreBlockReason = "active_probe_shutdown_unconfirmed";
        }
        if (HasJournalFlag(journal, JournalVendorOperationPending) ||
            HasJournalFlag(journal, JournalRxReadPending) ||
            HasJournalFlag(journal, JournalMonitorPending) ||
            HasJournalFlag(journal, JournalChannelPending) ||
            (vendor && (vendor->poisoned() || vendor->undrained() || vendor->has_pending()))) {
            markVendorOperationUnconfirmed();
        }

        bool radioRestoreOk = true;
        if (safeToRestore && journalReady) {
            setStatus(supervisor::Phase::Restoring);
            record("send_state=restoring");
            // Child exit and its shutdown acknowledgement precede closing the
            // vendor channel. Never restart under an active transport.
            if (!closeVendorTransport()) {
                safeToRestore = false;
                radioRestoreOk = false;
            } else {
                radio.reset();
                try {
                    RequireAuxiliaryStopped();
                    if (HasJournalFlag(journal, JournalNetworkRestartPending)) {
                        persistJournal();
                        tx10ub::host::NetworkRestartTimings timings;
                        sessionAdapter = RestartTransferAdapter(sessionAdapter, savedWifi, &timings, true, journal);
                        record("shutdown_device_restart_ms=" + std::to_string(timings.deviceRestartMs));
                        record("shutdown_adapter_ready_ms=" + std::to_string(timings.adapterReadyMs));
                        record("shutdown_wifi_restore_ms=" + std::to_string(timings.wifiRestoreMs));
                        record("shutdown_scan_policy_status=" + std::to_string(timings.scanPolicyStatus));
                        rxReinitialized = true;
                        record("network_function_reinitialized=1; wps_memory_readback_verified=0");
                    } else {
                        sessionAdapter = tx10ub::host::RestoreWifiWithoutRestart(sessionAdapter, savedWifi);
                        vendorStateUnchanged = true;
                        record("network_function_restart_skipped=vendor_state_unchanged");
                    }
                    radio = std::make_unique<WifiRadio>(sessionAdapter);
                    const auto actual = radio->Capture();
                    if (!tx10ub::host::WifiStateRestored(savedWifi, actual))
                        Fail("original_wifi_connection_restore_mismatch");
                    RequireAuxiliaryStopped();
                    apRestored = auxiliaryRestored = true;
                    for (const auto flag : {JournalNetworkRestartPending, JournalRadioRestoreVerificationPending,
                        JournalMonitorOwned, JournalChannelOwned, JournalAutoconfChanged,
                        JournalDisconnectPending, JournalDisconnected}) SetJournalFlag(journal, flag, false);
                    persistJournal();
                    record("original_wifi_state_restored=1; auxiliary_started=0");
                } catch (const std::exception& error) {
                    radioRestoreOk = false;
                    record(std::string("restore_failure=network_reinitialization: ") + error.what());
                }
            }
        }
        // Close the vendor channel before releasing the process-wide radio
        // mutexes, even when a different lower-layer fence blocked restoration.
        if (vendor && (!childStarted || childExited)) {
            if (!closeVendorTransport()) {
                record("restore_failure=vendor_close_or_drain_unconfirmed");
                safeToRestore = false;
                if (restoreBlockReason.empty()) restoreBlockReason = "vendor_transport_drain_unconfirmed";
                SetJournalFlag(journal, JournalLowerFenceUnconfirmed, true);
                persistJournal();
            }
        }

        if (realtekCaptured) {
            try {
                if (Sha256(tx10ub::host::RealtekServiceDriverPath()) != realtekHash) Fail("stock_realtek_image_changed");
                record("realtek_driver_unchanged=1");
            } catch (const std::exception& error) { record(std::string("realtek_check_failure=") + error.what()); safeToRestore = false; }
        }
        bool journalRestored = false;
        if (journalReady) {
            if (safeToRestore && radioRestoreOk && apRestored && auxiliaryRestored && shutdownConfirmed &&
                !HasJournalFlag(journal, JournalVendorOperationPending) &&
                !HasJournalFlag(journal, JournalRadioRestoreVerificationPending) &&
                !HasJournalFlag(journal, JournalRxReadPending) &&
                !HasJournalFlag(journal, JournalMonitorPending) &&
                !HasJournalFlag(journal, JournalChannelPending) &&
                !HasJournalFlag(journal, JournalNetworkRestartPending) &&
                !HasJournalFlag(journal, JournalLowerFenceUnconfirmed)) {
                SetJournalFlag(journal, JournalRestoreComplete, true);
            }
            try {
                persistJournal();
                journalRestored = HasJournalFlag(journal, JournalRestoreComplete);
            }
            catch (const std::exception& error) {
                if (statusWarning.empty()) statusWarning = std::string("journal_write_failed: ") + error.what();
                safeToRestore = false;
            }
        }
        if (!safeToRestore || !radioRestoreOk) {
            if (restoreBlockReason.empty()) restoreBlockReason = "radio_or_service_restore_unconfirmed";
            record("restore_failure=restore_blocked: " + restoreBlockReason);
            try { WriteAtomic(context_.capture / markers::RestoreBlockedFileName, restoreBlockReason + "\n"); }
            catch (const std::exception& error) { record(std::string("restore_block_marker_failure=") + error.what()); }
        }
        const bool receiveCompleted = context_.request.receive && transferSucceeded;
        const bool restorationComplete = safeToRestore && radioRestoreOk && apRestored && auxiliaryRestored &&
            !HasJournalFlag(journal, JournalNetworkRestartPending);
        if (!context_.request.receive && transferSucceeded && events_.transportClosed && shutdownConfirmed && restorationComplete) {
            finalStatus = supervisor::Phase::Completed;
        } else if (cancelled && primaryFailure.empty() && !restorationRequired && !childStarted) {
            finalStatus = supervisor::Phase::Cancelled;
        } else if (cancelled && primaryFailure.empty() && shutdownConfirmed && restorationComplete) {
            finalStatus = supervisor::Phase::Cancelled;
        } else if (receiveCompleted && primaryFailure.empty() && shutdownConfirmed && restorationComplete) {
            finalStatus = supervisor::Phase::Completed;
        } else {
            finalStatus = supervisor::Phase::Failed;
            if (primaryFailure.empty()) primaryFailure = "transfer_or_restore_incomplete";
            if ((primaryFailure == supervisor::MissingAdapterReason ||
                primaryFailure == supervisor::MultipleAdaptersReason ||
                primaryFailure == supervisor::TransferHelperBusyReason ||
                primaryFailure == supervisor::UnsupportedDriverReason) &&
                events_.failureReason.empty())
                events_.failureReason = primaryFailure;
        }

        const bool restorationWasRequired = restorationRequired || childStarted;
        if (!primaryFailure.empty() || !statusWarning.empty()) {
            try {
                std::string errors;
                if (!primaryFailure.empty()) errors += primaryFailure + "\n";
                if (!statusWarning.empty()) errors += statusWarning + "\n";
                WriteAtomic(context_.requestDir / L"error.txt", errors);
            } catch (...) { }
        }
        std::ostringstream result;
        result << supervisor::StatusKey << '=' << supervisor::PhaseName(finalStatus)
            << '\n' << supervisor::TransferSucceededKey << '=' << ((transferSucceeded && (!context_.request.receive || receiveCompleted)) ? 1 : 0)
            << '\n' << supervisor::FailureStageKey << '=' << (events_.failureStage.empty() ? (context_.request.receive ? "receive" : events_.transferStage) : events_.failureStage)
            << '\n' << supervisor::FailureReasonKey << '=' << (events_.failureReason.empty() ? (finalStatus == supervisor::Phase::Failed ? "failed" : "") : events_.failureReason)
            << '\n' << supervisor::FailureHttpStatusKey << '=' << events_.failureHttpStatus
            << '\n' << supervisor::RestorationRequiredKey << '=' << (restorationWasRequired ? 1 : 0)
            << '\n' << supervisor::RecoveryRequiredKey << '=' << (journalReady && !journalRestored ? 1 : 0)
            << '\n' << supervisor::ApRestoredKey << '=' << (apRestored ? 1 : 0)
            << '\n' << supervisor::AuxiliaryRestoredKey << '=' << (auxiliaryRestored ? 1 : 0)
            << '\n' << supervisor::RxReinitializedKey << '=' << (rxReinitialized ? 1 : 0)
            << '\n' << supervisor::VendorStateUnchangedKey << '=' << (vendorStateUnchanged ? 1 : 0) << '\n';
        try { WriteAtomic(context_.resultPath, result.str()); }
        catch (const std::exception& error) { record(std::string("result_write_failure=") + error.what()); finalStatus = supervisor::Phase::Failed; }
        record(std::string("controller_exit=") + supervisor::PhaseName(finalStatus));
        setStatus(finalStatus, true);
        if (childLog) childLog.reset();
        return finalStatus == supervisor::Phase::Completed ? 0 : finalStatus == supervisor::Phase::Cancelled ? 2 : 1;
    }

private:
    EventState events_;
    Context context_;
};

int RecoverOwnedSession(Context context, RuntimeJournal& journal) {
    const auto journalPath = context.candidate / markers::RadioSnapshotFileName;
    std::unique_ptr<OwnedMutex> legacyRadioMutex;
    std::unique_ptr<VendorTransport> vendor;
    bool vendorOperationInProgress = false;
    auto beginVendorOperation = [&]() {
        SetJournalFlag(journal, JournalVendorOperationPending, true);
        vendorOperationInProgress = true;
        WriteRuntimeJournal(journalPath, journal);
    };
    auto completeVendorOperation = [&]() {
        SetJournalFlag(journal, JournalVendorOperationPending, false);
        try { WriteRuntimeJournal(journalPath, journal); }
        catch (...) {
            SetJournalFlag(journal, JournalVendorOperationPending, true);
            vendorOperationInProgress = true;
            throw;
        }
        vendorOperationInProgress = false;
    };
    try {
        if (!IsAdministrator()) Fail("administrator_token_required");
        if (HasJournalFlag(journal, JournalRestoreComplete)) return 0;
        LocateRuntimeFiles(context);
        const bool directSession = HasJournalFlag(journal, JournalDirectIhv);
        if (!directSession) {
            const auto savedRuntimePath = ReadJournalWide(journal.runtimeSysPath, "runtime_sys_path");
            if (!SamePath(context.sysPath, savedRuntimePath)) Fail("runtime_recovery_package_image_mismatch");
            tx10ub::security::VerifySignedDriver(context.sysPath);
        }
        const auto expectedImage = ReadJournalDriverImage(journal);

        legacyRadioMutex = std::make_unique<OwnedMutex>(L"Local\\AWDLWin-TX10UB-UnassociatedRx");
        if (FindActiveTransferHelper()) Fail(supervisor::TransferHelperBusyReason);

        if (HasJournalFlag(journal, JournalLowerFenceUnconfirmed) ||
            HasJournalFlag(journal, JournalWpsClearPending) ||
            HasJournalFlag(journal, JournalVendorOperationPending) ||
            HasJournalFlag(journal, JournalRxReadPending) ||
            HasJournalFlag(journal, JournalMonitorPending) ||
            HasJournalFlag(journal, JournalChannelPending)) {
            Fail(supervisor::RecoveryOperationUnsettledReason);
        }
        if (HasJournalFlag(journal, JournalProbeStarted) ||
            HasJournalFlag(journal, JournalProbeStartPending)) {
            if (!HasExactMarker(context.capture / markers::ProbeShutdownFileName, markers::ProbeShutdownContent)) {
                Fail("runtime_recovery_probe_shutdown_unconfirmed");
            }
            SetJournalFlag(journal, JournalProbeStarted, false);
            SetJournalFlag(journal, JournalProbeStartPending, false);
            SetJournalFlag(journal, JournalShutdownConfirmed, true);
            WriteRuntimeJournal(journalPath, journal);
        }

        const auto adapter = tx10ub::host::DiscoverAdapterByGuid(journal.adapterGuid);
        if (adapter.driverImage != expectedImage) Fail(supervisor::UnsupportedDriverReason);
        if (directSession) {
            if (adapter.instanceId != ReadJournalWide(journal.adapterInstanceId, "adapter_instance_id"))
                Fail("runtime_recovery_device_identity_changed");
        } else {
            if (adapter.luid.Value != journal.adapterLuid || adapter.index != journal.adapterIndex)
                Fail(supervisor::RecoveryAdapterChangedReason);
            if (journal.runtimeTargetNetLuid != adapter.luid.Value) Fail("runtime_recovery_target_luid_changed");
        }

        WifiSnapshot savedWifi{};
        if (journal.wifiState != wlan_interface_state_connected &&
            journal.wifiState != wlan_interface_state_disconnected) Fail("runtime_recovery_wifi_snapshot_invalid");
        if (journal.wifiAutoconf > 1) Fail("runtime_recovery_wifi_autoconf_snapshot_invalid");
        savedWifi.state = static_cast<WLAN_INTERFACE_STATE>(journal.wifiState);
        savedWifi.autoconfEnabled = journal.wifiAutoconf != 0;
        savedWifi.channel = journal.wifiChannel;
        std::copy(std::begin(journal.wifiBssid), std::end(journal.wifiBssid), savedWifi.bssid.begin());
        savedWifi.profileName = ReadJournalWide(journal.wifiProfile, "wifi_profile");
        savedWifi.ssid = journal.wifiSsid;
        if (savedWifi.state == wlan_interface_state_connected &&
            (savedWifi.profileName.empty() || savedWifi.channel == 0)) {
            Fail("runtime_recovery_wifi_connection_snapshot_incomplete");
        }

        if (directSession) {
            RequireAuxiliaryStopped();
            if (HasJournalFlag(journal, JournalNetworkRestartPending)) {
                RestartTransferAdapter(adapter, savedWifi, nullptr, context.request.ndiscap, journal);
            } else {
                tx10ub::host::RestoreWifiWithoutRestart(adapter, savedWifi);
                WifiRadio unchanged(adapter);
                const auto actual = unchanged.Capture();
                if (!tx10ub::host::WifiStateRestored(savedWifi, actual))
                    Fail("runtime_recovery_wifi_changed_outside_runtime");
            }
            RequireAuxiliaryStopped();
            journal.flags = static_cast<ULONG>(JournalWifiCaptured) | static_cast<ULONG>(JournalDirectIhv) |
                static_cast<ULONG>(JournalShutdownConfirmed) | static_cast<ULONG>(JournalRestoreComplete);
            WriteRuntimeJournal(journalPath, journal);
            if (!DeleteFileW((context.capture / markers::RestoreBlockedFileName).c_str()) &&
                GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND)
                std::cout << "radio_state_restored=1 restore_marker_removal_failed=" << GetLastError() << '\n';
            else std::cout << "radio_state_restored=1; auxiliary_started=0\n";
            return 0;
        }

        BbState originalBb{
            journal.originalBbEncoded, journal.originalBbWidth, journal.originalBbPrimaryIndex,
            journal.originalBbSmallBand, journal.originalBbIs24Ghz
        };
        Channel originalChannel{
            journal.originalChannelBand, journal.originalChannelPrimary,
            journal.originalChannelWidth, journal.originalChannelOffset
        };
        const bool baselineCaptured = HasJournalFlag(journal, JournalRadioBaselineCaptured);
        const bool monitorOwned = HasJournalFlag(journal, JournalMonitorOwned);
        const bool channelOwned = HasJournalFlag(journal, JournalChannelOwned);
        const bool radioVerificationPending = HasJournalFlag(journal, JournalRadioRestoreVerificationPending);
        const bool radioRestoreRequired = monitorOwned || channelOwned || radioVerificationPending;
        if (radioRestoreRequired && !baselineCaptured) {
            Fail("runtime_recovery_radio_baseline_missing");
        }
        if (baselineCaptured) {
            VendorTransport validationTransport(adapter);
            const Channel decoded = validationTransport.ChannelFromBb(originalBb);
            if (decoded.band != originalChannel.band || decoded.primary != originalChannel.primary ||
                decoded.width != originalChannel.width || decoded.offset != originalChannel.offset ||
                (journal.originalRxFilter == 0 && journal.originalRxDataFilter == 0)) {
                Fail("runtime_recovery_radio_baseline_invalid");
            }
        }

        WifiRadio radio(adapter);
        const auto currentState = radio.InterfaceState();
        if (currentState != wlan_interface_state_connected && currentState != wlan_interface_state_disconnected) {
            Fail("runtime_recovery_wifi_interface_not_stable");
        }
        if (radioRestoreRequired && currentState != wlan_interface_state_disconnected) {
            Fail("runtime_recovery_wifi_must_be_disconnected_for_radio_restore");
        }

        if (radioRestoreRequired) {
            if (!HasJournalFlag(journal, JournalRadioRestoreVerificationPending)) {
                SetJournalFlag(journal, JournalRadioRestoreVerificationPending, true);
                WriteRuntimeJournal(journalPath, journal);
            }
            vendor = std::make_unique<VendorTransport>(adapter);
            beginVendorOperation();
            vendor->Open();
            completeVendorOperation();
            if (monitorOwned) {
                SetJournalFlag(journal, JournalMonitorPending, true);
                WriteRuntimeJournal(journalPath, journal);
                beginVendorOperation();
                const auto reply = vendor->Command({"echo", "core", "mon_mode", "0", "0"});
                completeVendorOperation();
                if (reply.find("port 0 left mon mode successfully") == std::string::npos &&
                    reply.find("the port is not in monitor mode") == std::string::npos) {
                    Fail("runtime_recovery_monitor_exit_not_confirmed");
                }
                SetJournalFlag(journal, JournalMonitorOwned, false);
                SetJournalFlag(journal, JournalMonitorPending, false);
                WriteRuntimeJournal(journalPath, journal);
            }
            if (channelOwned) {
                SetJournalFlag(journal, JournalChannelPending, true);
                WriteRuntimeJournal(journalPath, journal);
                beginVendorOperation();
                vendor->SetChannel(originalChannel);
                if (!(vendor->ReadBb() == originalBb)) Fail("runtime_recovery_original_channel_readback_mismatch");
                completeVendorOperation();
                SetJournalFlag(journal, JournalChannelOwned, false);
                SetJournalFlag(journal, JournalChannelPending, false);
                WriteRuntimeJournal(journalPath, journal);
            }
            beginVendorOperation();
            if (!(vendor->ReadBb() == originalBb)) Fail("runtime_recovery_original_channel_readback_mismatch");
            completeVendorOperation();
            SetJournalFlag(journal, JournalRxReadPending, true);
            WriteRuntimeJournal(journalPath, journal);
            const auto currentRx = tx10ub::host::ReadRxSettings(context.probePath);
            SetJournalFlag(journal, JournalRxReadPending, false);
            WriteRuntimeJournal(journalPath, journal);
            if (currentRx != std::pair<ULONG, ULONG>{journal.originalRxFilter, journal.originalRxDataFilter}) {
                Fail("runtime_recovery_original_rx_readback_mismatch");
            }
            beginVendorOperation();
            vendor->Close();
            if (vendor->undrained() || vendor->has_pending() || vendor->poisoned()) {
                Fail("runtime_recovery_vendor_transport_not_drained");
            }
            completeVendorOperation();
            SetJournalFlag(journal, JournalRadioRestoreVerificationPending, false);
            WriteRuntimeJournal(journalPath, journal);
            vendor.reset();
        }

        const bool restoreAutoconf = HasJournalFlag(journal, JournalAutoconfPending) ||
            HasJournalFlag(journal, JournalAutoconfChanged);
        if (restoreAutoconf) {
            const bool currentAutoconf = radio.AutoconfEnabled();
            if (currentAutoconf != savedWifi.autoconfEnabled) {
                if (currentAutoconf) Fail("runtime_recovery_autoconf_changed_outside_runtime");
                radio.SetAutoconf(savedWifi.autoconfEnabled);
            }
            if (radio.AutoconfEnabled() != savedWifi.autoconfEnabled) Fail("runtime_recovery_autoconf_restore_failed");
            SetJournalFlag(journal, JournalAutoconfPending, false);
            SetJournalFlag(journal, JournalAutoconfChanged, false);
            WriteRuntimeJournal(journalPath, journal);
        }

        if (HasJournalFlag(journal, JournalServiceStartPending) ||
            HasJournalFlag(journal, JournalServiceStarted)) {
            AuxiliaryService::RestoreSaved(journal);
            SetJournalFlag(journal, JournalServiceStartPending, false);
            SetJournalFlag(journal, JournalServiceStarted, false);
            WriteRuntimeJournal(journalPath, journal);
        }

        const bool disconnectWasOwned = HasJournalFlag(journal, JournalDisconnectPending) ||
            HasJournalFlag(journal, JournalDisconnected);
        if (savedWifi.state == wlan_interface_state_connected) {
            auto actual = radio.Capture();
            if (disconnectWasOwned && actual.state == wlan_interface_state_disconnected) {
                radio.Connect(savedWifi);
            } else if (actual.state != wlan_interface_state_connected ||
                       !tx10ub::host::IsSavedWifiNetwork(savedWifi, actual.profileName.c_str(), actual.ssid,
                           actual.bssid.data())) {
                Fail("runtime_recovery_wifi_changed_outside_runtime");
            }
            actual = radio.Capture();
            if (!tx10ub::host::WifiStateRestored(savedWifi, actual)) {
                Fail("runtime_recovery_original_wifi_connection_not_restored");
            }
        } else if (radio.InterfaceState() != wlan_interface_state_disconnected ||
            radio.AutoconfEnabled() != savedWifi.autoconfEnabled) {
            Fail("runtime_recovery_original_disconnected_wifi_not_restored");
        }

        if (HasJournalFlag(journal, JournalVendorOperationPending) ||
            HasJournalFlag(journal, JournalRadioRestoreVerificationPending) ||
            HasJournalFlag(journal, JournalRxReadPending) ||
            HasJournalFlag(journal, JournalMonitorPending) ||
            HasJournalFlag(journal, JournalChannelPending) ||
            HasJournalFlag(journal, JournalLowerFenceUnconfirmed)) {
            Fail("runtime_recovery_completion_fence_not_clear");
        }
        SetJournalFlag(journal, JournalDisconnectPending, false);
        SetJournalFlag(journal, JournalDisconnected, false);
        SetJournalFlag(journal, JournalWpsClearPending, false);
        SetJournalFlag(journal, JournalRxReadPending, false);
        SetJournalFlag(journal, JournalMonitorPending, false);
        SetJournalFlag(journal, JournalChannelPending, false);
        SetJournalFlag(journal, JournalProbeStarted, false);
        SetJournalFlag(journal, JournalProbeStartPending, false);
        SetJournalFlag(journal, JournalShutdownConfirmed, true);
        SetJournalFlag(journal, JournalRestoreComplete, true);
        WriteRuntimeJournal(journalPath, journal);
        if (!DeleteFileW((context.capture / markers::RestoreBlockedFileName).c_str()) &&
            GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND) {
            std::cout << "radio_state_restored=1 restore_marker_removal_failed=" << GetLastError() << '\n';
            return 0;
        }
        std::cout << "radio_state_restored=1\n";
        return 0;
    } catch (const std::exception& error) {
        if (vendorOperationInProgress || HasJournalFlag(journal, JournalVendorOperationPending) ||
            HasJournalFlag(journal, JournalRxReadPending) ||
            (vendor && (vendor->poisoned() || vendor->undrained() || vendor->has_pending()))) {
            SetJournalFlag(journal, JournalLowerFenceUnconfirmed, true);
            try { WriteRuntimeJournal(journalPath, journal); }
            catch (...) { }
        }
        try {
            WriteAtomic(context.capture / markers::RestoreBlockedFileName,
                        std::string("recovery_failed=") + error.what() + "\n");
        }
        catch (...) { }
        std::cerr << "runtime_recovery_error=" << error.what() << '\n';
        return static_cast<int>(supervisor::ClassifyRecoveryFailure(error.what()));
    }
}

// Parses "--request <absolute ...\request.json>" exactly as the owner built it.
// The started runtime validates the request itself (owner, session folder, file access).
std::optional<fs::path> BrokerRequestPath(const std::wstring& parameters) {
    if (parameters.empty() || parameters.find(L'\0') != std::wstring::npos) return std::nullopt;
    const std::wstring commandLine = L"DropPorterRuntime.exe " + parameters;
    int count = 0;
    LPWSTR* arguments = CommandLineToArgvW(commandLine.c_str(), &count);
    if (!arguments) return std::nullopt;
    std::optional<fs::path> result;
    if (count == 3 && wcscmp(arguments[1], L"--request") == 0) {
        const fs::path path(arguments[2]);
        if (path.is_absolute() && path.filename() == request_file::FileName) result = path;
    }
    LocalFree(arguments);
    return result;
}

// Elevated launcher that lives for one app run: starts the runtime for requests from
// the owner process only, and hands the owner a wait/query handle to it.
int RunBroker(const std::wstring& ownerPidText, const std::wstring& token, const fs::path& executable) {
    namespace broker = dropporter::broker;
    if (!broker::IsToken(token)) Fail("broker_token_invalid");
    if (ownerPidText.empty() || ownerPidText.size() > 10 ||
        ownerPidText.find_first_not_of(L"0123456789") != std::wstring::npos) Fail("broker_owner_pid_invalid");
    const unsigned long long ownerPidValue = std::stoull(ownerPidText);
    if (ownerPidValue == 0 || ownerPidValue > MAXDWORD) Fail("broker_owner_pid_invalid");
    const DWORD ownerPid = static_cast<DWORD>(ownerPidValue);

    Handle owner(OpenProcess(SYNCHRONIZE | PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ownerPid));
    if (!owner) FailWin32("broker_owner_unavailable");
    if (WaitForSingleObject(owner.get(), 0) != WAIT_TIMEOUT) Fail("broker_owner_has_exited");
    HANDLE rawOwnerToken = nullptr;
    if (!OpenProcessToken(owner.get(), TOKEN_QUERY, &rawOwnerToken)) FailWin32("broker_owner_token_open_failed");
    Handle ownerToken(rawOwnerToken);

    // UAC grants activation to the elevated process. Hand that right back to
    // the requesting UI before publishing the ready pipe, even though this
    // background broker has no window of its own.
    (void)AllowSetForegroundWindow(ownerPid);

    // Only SYSTEM and the owner's user may open the pipe; the medium label lets the
    // unelevated owner write to it.
    const std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GRGW;;;" + TokenSidString(ownerToken.get()) + L")S:(ML;;NW;;;ME)";
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
        FailWin32("broker_pipe_security_failed");
    }
    SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
    constexpr DWORD inputBytes = sizeof(broker::RequestHeader) + broker::kMaxParameterChars * sizeof(wchar_t);
    const HANDLE rawPipe = CreateNamedPipeW(broker::PipeName(token).c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, sizeof(broker::Reply), inputBytes, 0, &security);
    const DWORD pipeError = GetLastError();
    LocalFree(descriptor);
    if (rawPipe == INVALID_HANDLE_VALUE) FailWin32("broker_pipe_create_failed", pipeError);
    Handle pipe(rawPipe);
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event) FailWin32("broker_event_create_failed");

    // Completes one overlapped pipe operation; false when the owner exits or time runs out.
    const auto complete = [&](BOOL started, OVERLAPPED& overlapped, DWORD timeout, DWORD& bytes, DWORD& error) {
        bytes = 0;
        error = started ? ERROR_SUCCESS : GetLastError();
        if (!started && error != ERROR_IO_PENDING) return true;
        const HANDLE waits[] = {event.get(), owner.get()};
        if (!started && WaitForMultipleObjects(2, waits, FALSE, timeout) != WAIT_OBJECT_0) {
            CancelIoEx(pipe.get(), &overlapped);
            (void)GetOverlappedResult(pipe.get(), &overlapped, &bytes, TRUE);
            return false;
        }
        error = GetOverlappedResult(pipe.get(), &overlapped, &bytes, FALSE) ? ERROR_SUCCESS : GetLastError();
        return true;
    };

    OVERLAPPED overlapped{};
    overlapped.hEvent = event.get();
    DWORD bytes = 0, error = ERROR_SUCCESS;
    if (!complete(ConnectNamedPipe(pipe.get(), &overlapped), overlapped, broker::kConnectTimeoutMs, bytes, error)) return 0;
    if (error != ERROR_SUCCESS && error != ERROR_PIPE_CONNECTED) FailWin32("broker_connect_failed", error);
    ULONG clientPid = 0;
    if (!GetNamedPipeClientProcessId(pipe.get(), &clientPid) || clientPid != ownerPid) Fail("broker_client_not_owner");

    std::vector<BYTE> message(inputBytes);
    for (;;) {
        ResetEvent(event.get());
        overlapped = {};
        overlapped.hEvent = event.get();
        if (!complete(ReadFile(pipe.get(), message.data(), inputBytes, nullptr, &overlapped), overlapped, INFINITE, bytes, error)) return 0;
        if (error == ERROR_BROKEN_PIPE) return 0;
        if (error != ERROR_SUCCESS) FailWin32("broker_read_failed", error);

        broker::RequestHeader header{};
        if (bytes < sizeof(header)) Fail("broker_request_invalid");
        std::memcpy(&header, message.data(), sizeof(header));
        if (header.magic != broker::kRequestMagic || header.parameterChars == 0 ||
            header.parameterChars > broker::kMaxParameterChars ||
            bytes != sizeof(header) + header.parameterChars * sizeof(wchar_t)) Fail("broker_request_invalid");
        std::wstring parameters(header.parameterChars, L'\0');
        std::memcpy(parameters.data(), message.data() + sizeof(header), header.parameterChars * sizeof(wchar_t));
        const auto requestPath = BrokerRequestPath(parameters);
        if (!requestPath) Fail("broker_request_invalid");

        broker::Reply reply{broker::kReplyMagic, ERROR_SUCCESS, 0};
        std::wstring commandLine = QuoteArgument(executable.wstring()) + L" --request " + QuoteArgument(requestPath->wstring());
        const std::wstring directory = executable.parent_path().wstring();
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        startup.dwFlags = STARTF_USESHOWWINDOW;
        startup.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION process{};
        if (!CreateProcessW(executable.c_str(), commandLine.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                nullptr, directory.c_str(), &startup, &process)) {
            reply.error = GetLastError();
        } else {
            Handle runtimeProcess(process.hProcess);
            Handle runtimeThread(process.hThread);
            HANDLE remote = nullptr;
            // The runtime is already running: without a handle the owner falls back to
            // requesting cancellation through the session folder, so report success.
            if (DuplicateHandle(GetCurrentProcess(), runtimeProcess.get(), owner.get(), &remote,
                    SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0)) {
                reply.process = static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(remote));
            }
        }
        ResetEvent(event.get());
        overlapped = {};
        overlapped.hEvent = event.get();
        if (!complete(WriteFile(pipe.get(), &reply, sizeof(reply), nullptr, &overlapped), overlapped, INFINITE, bytes, error)) return 0;
        if (error != ERROR_SUCCESS || bytes != sizeof(reply)) return 0;
    }
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    const bool brokerMode = argc == 4 && wcscmp(argv[1], L"--broker") == 0;
    const bool recoveryMode = argc == 3 && wcscmp(argv[1], L"--recover") == 0;
    if (!brokerMode && !recoveryMode && (argc != 3 || wcscmp(argv[1], L"--request") != 0)) {
        std::wcerr << L"usage: DropPorterRuntime.exe --request|--recover <absolute request.json>\n";
        return 2;
    }
    try {
        std::array<wchar_t, 32768> executable{};
        const DWORD length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
        if (!length || length >= executable.size()) FailWin32("runtime_executable_path_unavailable");
        if (brokerMode) return RunBroker(argv[2], argv[3], fs::path(std::wstring(executable.data(), length)));
        const fs::path requestPath(argv[2]);
        if (!requestPath.is_absolute()) Fail("request_path_must_be_absolute");
        const auto executableDir = fs::path(std::wstring(executable.data(), length)).parent_path();
        if (recoveryMode) {
            if (!IsAdministrator()) Fail("administrator_token_required");
            // Read the journal only after excluding a concurrent supervisor or recovery.
            OwnedMutex recoveryMutex(L"Global\\AWDLWinSend");
            auto journal = std::make_unique<RuntimeJournal>();
            auto context = ValidateRecoveryRequest(requestPath, executableDir, *journal);
            return RecoverOwnedSession(std::move(context), *journal);
        }
        auto context = ValidateRequest(requestPath, executableDir);
        Supervisor supervisor(std::move(context));
        return supervisor.Run();
    } catch (const std::exception& error) {
        std::cerr << "runtime_error=" << error.what() << '\n';
        return recoveryMode ? static_cast<int>(supervisor::ClassifyRecoveryFailure(error.what())) : 1;
    }
}

