#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shobjidl.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <charconv>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <iomanip>
#include <limits>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "DropPorterLifecycle.h"
#include "DropPorterDiscoveryTiming.h"
#include "DropPorterRequestFile.h"
#include "DropPorterSendSelection.h"
#include "DropPorterReceiveOffer.h"
#include "DropPorterTargetFiles.h"
#include "DropPorterSessionMarkers.h"
#include "../Tx10ub/Tx10ubSendFiles.h"
#include "DropPorterBridgeIds.h"
#include "DropPorterSupervisorState.h"
#include "../Tx10ub/Tx10ubReceiveState.h"
#include "../Tx10ub/Tx10ubProbeEvents.h"

namespace dropporter {
enum class TransferField { ChooseFile, PrimaryAction, Cancel, FilePath, Status, Details, Target, Files, OpenFile, OpenFolder };
class UniqueHandle {
public:
    explicit UniqueHandle(HANDLE handle = nullptr) noexcept : handle_(handle) {}
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    ~UniqueHandle() { reset(); }

    HANDLE get() const noexcept { return handle_; }
    explicit operator bool() const noexcept { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }
    HANDLE release() noexcept {
        HANDLE result = handle_;
        handle_ = nullptr;
        return result;
    }
    void reset(HANDLE replacement = nullptr) noexcept {
        if (*this) CloseHandle(handle_);
        handle_ = replacement;
    }

private:
    HANDLE handle_ = nullptr;
};

inline std::wstring GetModulePath() {
    std::vector<wchar_t> buffer(512);
    for (;;) {
        const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) return {};
        if (length < buffer.size() - 1) return std::wstring(buffer.data(), length);
        if (buffer.size() >= 32768) return {};
        buffer.resize((std::min)(buffer.size() * 2, static_cast<std::size_t>(32768)));
    }
}

inline std::optional<std::filesystem::path> FindRuntimeExecutable() {
    const auto module = GetModulePath();
    if (module.empty()) return std::nullopt;
    auto current = std::filesystem::path(module).parent_path();
    const auto packaged = current / L"runtime" / L"DropPorterRuntime.exe";
    if (const auto attributes = GetFileAttributesW(packaged.c_str());
        attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        return packaged;
    }
    while (!current.empty()) {
        for (const auto& candidate : {current / L"DropPorterRuntime.exe",
            current / L"artifacts" / L"DropPorter" / L"DropPorterRuntime.exe",
            current / L"tools" / L"x64" / L"DropPorterRuntime" / L"Release" / L"DropPorterRuntime.exe"}) {
            const auto attributes = GetFileAttributesW(candidate.c_str());
            if (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY)) return candidate;
        }
        const auto parent = current.parent_path();
        if (parent == current) break;
        current = parent;
    }
    return std::nullopt;
}

inline std::filesystem::path UserSessionDirectory() {
    PWSTR raw = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &raw)) || !raw) {
        if (raw) CoTaskMemFree(raw);
        return {};
    }
    const std::filesystem::path path(raw);
    CoTaskMemFree(raw);
    return path / L"DropPorter" / L"Sessions";
}

inline std::wstring QuoteWindowsArgument(std::wstring_view argument) {
    std::wstring quoted(1, L'"');
    std::size_t slashes = 0;
    for (const wchar_t ch : argument) {
        if (ch == L'\\') {
            ++slashes;
            continue;
        }
        if (ch == L'"') {
            quoted.append(slashes * 2 + 1, L'\\');
            quoted.push_back(L'"');
            slashes = 0;
            continue;
        }
        quoted.append(slashes, L'\\');
        slashes = 0;
        quoted.push_back(ch);
    }
    quoted.append(slashes * 2, L'\\');
    quoted.push_back(L'"');
    return quoted;
}

inline std::string Utf8(std::wstring_view value) {
    if (value.empty()) return {};
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string result(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), result.data(), required, nullptr, nullptr) != required) return {};
    return result;
}

inline std::string WideChannelRequestField() {
    wchar_t value[3]{};
    if (GetEnvironmentVariableW(L"DROPPORTER_WIDE_CHANNEL_MHZ", value, 3) == 2 &&
        std::wstring_view(value, 2) == L"80") {
        return request_file::Field(request_file::WideChannelMhz) + "80,\n  ";
    }
    return {};
}

inline std::string JsonEscape(std::string_view value) {
    std::string result;
    result.reserve(value.size() + 8);
    constexpr char hex[] = "0123456789abcdef";
    for (const unsigned char ch : value) {
        switch (ch) {
        case '"': result += "\\\""; break;
        case '\\': result += "\\\\"; break;
        case '\b': result += "\\b"; break;
        case '\f': result += "\\f"; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default:
            if (ch < 0x20) {
                result += "\\u00";
                result.push_back(hex[ch >> 4]);
                result.push_back(hex[ch & 0x0f]);
            } else result.push_back(static_cast<char>(ch));
        }
    }
    return result;
}

inline std::optional<std::wstring> NewToken() {
    GUID guid{};
    if (FAILED(CoCreateGuid(&guid))) return std::nullopt;
    wchar_t formatted[40]{};
    if (StringFromGUID2(guid, formatted, static_cast<int>(std::size(formatted))) == 0) return std::nullopt;
    std::wstring token;
    token.reserve(32);
    for (const wchar_t ch : std::wstring_view(formatted)) {
        if ((ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f')) token.push_back(ch);
        else if (ch >= L'A' && ch <= L'F') token.push_back(ch + (L'a' - L'A'));
    }
    if (token.size() != 32) return std::nullopt;
    return token;
}

inline bool WriteNewFile(const std::filesystem::path& path, std::string_view contents) {
    UniqueHandle file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                  FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file) return false;
    std::size_t offset = 0;
    while (offset < contents.size()) {
        const DWORD remaining = static_cast<DWORD>((std::min)(
            contents.size() - offset, static_cast<std::size_t>((std::numeric_limits<DWORD>::max)())));
        DWORD written = 0;
        if (!WriteFile(file.get(), contents.data() + offset, remaining, &written, nullptr) || written == 0) return false;
        offset += written;
    }
    return FlushFileBuffers(file.get()) != FALSE;
}

inline bool WriteCancelMarker(const std::filesystem::path& path) {
    UniqueHandle file(CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    return static_cast<bool>(file) && FlushFileBuffers(file.get()) != FALSE;
}

inline std::optional<std::string> ReadSmallTextFile(const std::filesystem::path& path) {
    // Status is replaced atomically by the supervisor. Permit that rename
    // while reading the old immutable file, and bound allocation before IO.
    UniqueHandle file(CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr));
    LARGE_INTEGER size{};
    if (!file || !GetFileSizeEx(file.get(), &size) || size.QuadPart < 0 || size.QuadPart > 64 * 1024)
        return std::nullopt;
    std::string result(static_cast<std::size_t>(size.QuadPart), '\0');
    std::size_t offset = 0;
    while (offset < result.size()) {
        DWORD read = 0;
        if (!ReadFile(file.get(), result.data() + offset,
            static_cast<DWORD>(result.size() - offset), &read, nullptr) || !read)
            return std::nullopt;
        offset += read;
    }
    if (result.size() >= 3 && static_cast<unsigned char>(result[0]) == 0xef &&
        static_cast<unsigned char>(result[1]) == 0xbb && static_cast<unsigned char>(result[2]) == 0xbf) {
        result.erase(0, 3);
    }
    return result;
}

inline std::map<std::string, std::string> ParseKeyValues(std::string_view text) {
    std::map<std::string, std::string> values;
    std::size_t start = 0;
    while (start < text.size()) {
        const auto end = text.find_first_of("\r\n", start);
        const auto line = text.substr(start, end == std::string_view::npos ? text.size() - start : end - start);
        const auto separator = line.find('=');
        if (separator != std::string_view::npos) {
            values[std::string(line.substr(0, separator))] = std::string(line.substr(separator + 1));
        }
        if (end == std::string_view::npos) break;
        start = end + 1;
        if (start < text.size() && text[end] == '\r' && text[start] == '\n') ++start;
    }
    return values;
}

inline const char* Value(const std::map<std::string, std::string>& values, const char* key) {
    const auto found = values.find(key);
    return found == values.end() ? "" : found->second.c_str();
}

inline bool IsOne(const std::map<std::string, std::string>& values, const char* key) {
    return std::string_view(Value(values, key)) == "1";
}

inline constexpr wchar_t MissingAdapterText[] =
    L"対応するWi-Fi子機が見つかりません。USBポートに接続して、もう一度お試しください。";
inline constexpr wchar_t SendStartFailure[] = L"送信を開始できませんでした。もう一度お試しください。";
inline constexpr wchar_t ReceiveStartFailure[] = L"受信を開始できませんでした。もう一度お試しください。";
inline constexpr wchar_t SendFileCountLimit[] = L"一度に送信できるファイルは100件までです。";

using supervisor::UnsupportedDriverReason;

inline const wchar_t* AdapterFailureText(std::string_view reason) {
    if (reason == tx10ub::probe_events::BluetoothUnavailable)
        return L"パソコンのBluetoothが使えません。Windowsの「設定」→「Bluetoothとデバイス」でBluetoothをオンにしてください。スイッチが表示されない場合は、デバイス マネージャーでBluetoothアダプターを有効にしてください。";
    if (reason == supervisor::MissingAdapterReason) return MissingAdapterText;
    if (reason == supervisor::MultipleAdaptersReason)
        return L"Wi-Fi子機を1台だけ接続してから、もう一度お試しください。";
    if (reason == supervisor::TransferHelperBusyReason)
        return L"別のDrop Porterの通信処理が実行中です。終了してから、もう一度お試しください。";
    if (reason == UnsupportedDriverReason) return L"このWi-Fi子機のドライバーは、現在のDrop Porterに対応していません。";
    return L"";
}

inline const wchar_t* RecoveryFailureText(std::string_view reason) noexcept {
    if (reason == UnsupportedDriverReason)
        return AdapterFailureText(reason);
    if (reason == supervisor::MissingAdapterReason)
        return L"Wi-Fi子機を接続してから、もう一度お試しください。";
    if (reason == supervisor::RecoveryAdapterChangedReason)
        return L"前に使っていたWi-Fi子機を同じUSBポートに接続してから、もう一度お試しください。";
    if (reason == supervisor::RecoveryOperationUnsettledReason)
        return L"Drop PorterからWi-Fiを元に戻せません。WindowsのWi-Fi設定から接続してください。";
    if (reason == supervisor::RecoverySnapshotMissingReason)
        return L"この回のWi-Fi接続はDrop Porterから元に戻せません。WindowsのWi-Fi設定で接続を確認し、「接続済み」を押してください。";
    return L"Wi-Fiを元に戻せませんでした。ほかのDrop Porterで送受信中なら終了を待ってください。Wi-Fiが切れている場合は、Windowsの設定から接続してください。";
}

inline std::wstring SendFailureText(const std::map<std::string, std::string>& result) {
    const auto stage = std::string_view(Value(result, supervisor::FailureStageKey));
    const auto reason = std::string_view(Value(result, supervisor::FailureReasonKey));
    const auto http = std::string_view(Value(result, supervisor::FailureHttpStatusKey));
    if (const auto* adapterFailure = AdapterFailureText(reason); *adapterFailure) return adapterFailure;
    if (reason == "not_found") return L"送信先が見つかりませんでした。";
    if (reason == "target_not_unique") return L"送信先を選び直してください。";
    if (reason == "timeout") {
        if (stage == tx10ub::probe_events::Select) return L"送信先を選ぶ時間が過ぎました。もう一度「送信先を探す」を押してください。";
        if (stage == tx10ub::probe_events::Discovery) return L"送信先を探す時間が過ぎました。もう一度お試しください。";
        if (stage == tx10ub::probe_events::Ask) return L"相手の受信許可を待っている間に時間切れになりました。";
        if (stage == tx10ub::probe_events::Upload) return L"転送が時間切れになりました。相手の端末でファイルを確認してください。";
        return L"相手の端末との接続が時間切れになりました。";
    }
    if (reason == "http_error" && stage == tx10ub::probe_events::Ask && http == "403") return L"相手が受信を許可しませんでした。";
    if (reason == "http_error" && stage == tx10ub::probe_events::Upload) return L"相手の端末がファイルを受け付けませんでした。";
    if (reason == "peer_expired" || reason == "connection_ended")
        return L"相手の端末との通信が途切れました。";
    if (reason == "send_failed" || reason == "receive_failed") return L"通信が途中で止まりました。";
    if (reason == send_selection::InvalidReason) return L"選択したファイルは送信できません。選び直してください。";
    if (reason == target_files::SelectionExpired) return L"選択した端末が一覧から外れました。もう一度送信先を探してください。";
    if (stage == tx10ub::probe_events::Select || stage == tx10ub::probe_events::Discovery) return L"送信先をもう一度探してください。";
    if (stage == tx10ub::probe_events::Connect || stage == tx10ub::probe_events::Tls || stage == tx10ub::probe_events::Discover || reason == "tls_error" || reason == "tls_init")
        return L"相手の端末に接続できませんでした。";
    if (stage == tx10ub::probe_events::Ask) return L"相手の受信許可が得られず、送信できませんでした。";
    if (stage == tx10ub::probe_events::Upload) return L"相手の端末でファイルを確認してください。";
    if (stage == tx10ub::probe_events::Preparing) return SendStartFailure;
    return {};
}

inline const wchar_t* ReceiveFailureText(std::optional<tx10ub::receive_state::FailureReason> reason) {
    using tx10ub::receive_state::FailureReason;
    if (!reason) return L"";
    switch (*reason) {
    case FailureReason::ConnectionClosed: return L"相手の端末との通信が途切れました。";
    case FailureReason::UploadTimedOut: return L"相手からのデータが届かず、受信を終了しました。";
    case FailureReason::SaveFailed: return L"保存先を確認してから、保存されていないファイルを送り直してもらってください。";
    default: return L"保存されていないファイルは、相手に送り直してもらってください。";
    }
}

// Wi-Fi restoration outcome after a send/receive, from the supervisor's result file.
enum class Restoration { NotNeeded, Restored, Kept, ReceiveUnverified, Unknown, Failed };
inline Restoration ClassifyRestoration(const std::map<std::string, std::string>& result) {
    // Left in the transfer state on purpose; the app restores it when it closes.
    if (IsOne(result, supervisor::RadioKeptKey)) return Restoration::Kept;
    const bool hasRestorationRequired = Value(result, supervisor::RestorationRequiredKey)[0] != '\0';
    const bool hasAp = Value(result, supervisor::ApRestoredKey)[0] != '\0';
    const bool hasAuxiliary = Value(result, supervisor::AuxiliaryRestoredKey)[0] != '\0';
    if (!hasRestorationRequired) return Restoration::Unknown;
    if (!IsOne(result, supervisor::RestorationRequiredKey)) return Restoration::NotNeeded;
    if ((hasAp && !IsOne(result, supervisor::ApRestoredKey)) || (hasAuxiliary && !IsOne(result, supervisor::AuxiliaryRestoredKey)))
        return Restoration::Failed;
    if (!hasAp || !hasAuxiliary) return Restoration::Unknown;
    if (!IsOne(result, supervisor::RxReinitializedKey) && !IsOne(result, supervisor::RxRestoreVerifiedKey) &&
        !IsOne(result, supervisor::VendorStateUnchangedKey)) return Restoration::ReceiveUnverified;
    return Restoration::Restored;
}
inline bool RestorationNeedsAttention(Restoration value) {
    return value != Restoration::NotNeeded && value != Restoration::Restored && value != Restoration::Kept;
}
// Short addition to the status line; empty when nothing needs the user's attention.
inline std::wstring RestorationStatus(Restoration value) {
    switch (value) {
    case Restoration::Failed: return L"Wi-Fiを元の接続に戻せませんでした。";
    case Restoration::Unknown:
    case Restoration::ReceiveUnverified: return L"Wi-Fiの接続を確認してください。";
    default: return {};
    }
}
// What the user can rely on or do about the Wi-Fi connection.
inline std::wstring RestorationDetail(Restoration value) {
    switch (value) {
    case Restoration::Restored: return L"Wi-Fiは元の接続に戻りました。";
    case Restoration::ReceiveUnverified:
        return L"Wi-Fiは元の接続に戻りました。通信が不安定な場合はWi-Fi子機を抜き差ししてください。";
    case Restoration::Unknown:
        return L"Wi-Fiにつながっていない場合は、WindowsのWi-Fi設定から接続し直してください。";
    case Restoration::Failed:
        return L"WindowsのWi-Fi設定から接続し直してください。つながらない場合はWi-Fi子機を抜き差ししてください。";
    default: return {};
    }
}
// "<outcome>" or "<outcome>。<restoration status>"
inline std::wstring ResultStatus(std::wstring outcome, Restoration value) {
    const auto restoration = RestorationStatus(value);
    if (restoration.empty()) return outcome;
    if (!outcome.ends_with(L"。")) outcome += L"。";
    return outcome + restoration;
}
inline void AppendLine(std::wstring& text, const std::wstring& line) {
    if (line.empty()) return;
    if (!text.empty()) text += L"\r\n";
    text += line;
}
struct TransferResultDisplay {std::wstring title, detail, restoration; bool showDriverHelp = false;};

inline bool HasFinalSupervisorResult(const std::filesystem::path& path) {
    const auto text = ReadSmallTextFile(path);
    if (!text) return false;
    const auto values = ParseKeyValues(*text);
    const auto status = supervisor::ParsePhase(Value(values, supervisor::StatusKey));
    const std::string_view restoration = Value(values, supervisor::RestorationRequiredKey);
    return supervisor::IsFinalPhase(status) &&
        (restoration == "0" || restoration == "1");
}

struct TransferProgress {std::uint64_t processed, total;};
inline TransferActivity ClassifyTransferActivity(bool running,bool stopping,supervisor::Phase phase,bool receiving=false) {
    if(!running) return TransferActivity::None;
    if(phase==supervisor::Phase::Restoring) return TransferActivity::Restoring;
    if(stopping) return TransferActivity::Stopping;
    if(phase==supervisor::Phase::Finalizing) return TransferActivity::AwaitingCompletion;
    if(phase==supervisor::Phase::Sending || receiving) return TransferActivity::Transferring;
    using supervisor::Phase;
    if (phase == Phase::Unknown || phase == Phase::Preparing || phase == Phase::PreparingAdapter ||
        phase == Phase::PreparingNetwork || phase == Phase::PreparingRadio ||
        phase == Phase::Connecting || phase == Phase::WaitingAccept)
        return TransferActivity::Working;
    return TransferActivity::None;
}
using SendProgress = tx10ub::probe_events::Progress;
inline std::optional<SendProgress> ParseSendProgress(const std::map<std::string, std::string>& values) {
    const auto number=[&](const char* key,std::uint64_t& value) {
        const auto text=std::string_view(Value(values,key));
        return tx10ub::probe_events::ParseUnsigned(text, value);
    };
    SendProgress progress{};
    using namespace tx10ub::probe_events;
    if (!number(ProcessedKey, progress.processed) || !number(TotalKey, progress.total) ||
        !number(ElapsedKey, progress.elapsedMs) || progress.processed > progress.total ||
        progress.total > tx10ub::send_files::MaxBytes) return std::nullopt;
    return progress;
}

inline std::wstring SendProgressText(const std::map<std::string, std::string>& values) {
    const auto progress=ParseSendProgress(values);
    if(!progress)return L"";
    const auto processed=progress->processed,total=progress->total,elapsed=progress->elapsedMs;
    const auto percent=total?(std::min)(std::uint64_t{99},processed*100/total):0;
    std::wostringstream text;
    text<<L"進捗（目安）"<<percent<<L"%\r\n"<<std::fixed<<std::setprecision(1)
        <<static_cast<double>(processed)/(1024*1024)<<L"/"<<static_cast<double>(total)/(1024*1024)
        <<L"MiB　経過"<<elapsed/1000<<L"秒";
    return text.str();
}

inline std::wstring SendPhaseText(supervisor::Phase phase,bool submitted) {
    if(phase==supervisor::Phase::Preparing)return L"送信の準備中です。";
    if(phase==supervisor::Phase::PreparingAdapter)return L"送信の準備中：デバイスを確認しています。";
    if(phase==supervisor::Phase::PreparingNetwork)return L"送信の準備中：Wi-Fiを切り替えています。";
    if(phase==supervisor::Phase::PreparingRadio)return L"送信の準備中：通信を準備しています。";
    if(phase==supervisor::Phase::Discovering)return L"送信先を探しています。";
    if(phase==supervisor::Phase::Connecting)return L"選択したデバイスに接続しています。";
    if(phase==supervisor::Phase::Selecting)return submitted?L"選択したデバイスに接続しています。":L"送信先を選んで送信を押してください。";
    if(phase==supervisor::Phase::WaitingAccept)return L"相手の受信許可を待っています。";
    if(phase==supervisor::Phase::Sending)return L"送信中です。";
    if(phase==supervisor::Phase::Finalizing)return L"相手の端末で受信が完了するのを待っています。";
    if(phase==supervisor::Phase::Restoring)return L"Wi-Fiを復旧しています。";
    return L"送信処理中です。";
}

struct TargetRow {
    unsigned id;
    std::wstring label;
    std::string peerMac;
    bool freshName = false;
};
struct TargetList {unsigned round;std::vector<TargetRow> rows;unsigned refresh=0;};
inline bool IsTargetPeerMac(std::string_view value) {
    return value.size() == 12 && value.find_first_not_of("0123456789abcdef") == std::string_view::npos;
}

inline std::wstring FormatTargetLabel(std::wstring label) {
    // The probe appends an address suffix. Strip only its separator, including
    // from previously saved labels that still contain it.
    const auto suffix = label.rfind(L" [");
    if (suffix != std::wstring::npos && label.size() - suffix == 11 &&
        label[suffix + 4] == L':' && label[suffix + 7] == L':' && label.back() == L']') {
        label.erase(suffix, 1);
        if (suffix == 0) label.insert(0, L"デバイス");
    }
    return label;
}

inline std::optional<TargetList> ParseTargetList(std::string_view text) {
    if(text.size()>32768||!text.starts_with(target_files::Round))return std::nullopt;
    const auto lineEnd=text.find('\n');if(lineEnd==std::string_view::npos)return std::nullopt;
    TargetList list{};
    auto round = text.substr(target_files::Round.size(), lineEnd - target_files::Round.size());
    if (round.ends_with('\r')) round.remove_suffix(1);
    const auto parsed = target_files::ParseNumber(round, target_files::MaxRound);
    if (!parsed) return std::nullopt;
    list.round = *parsed;
    auto pos=lineEnd+1;
    if(text.substr(pos).starts_with(target_files::Refresh)) {
        const auto end=text.find('\n',pos);if(end==std::string_view::npos)return std::nullopt;
        const auto valueAt = pos + target_files::Refresh.size();
        const auto value = text.substr(valueAt, end - valueAt);
        const auto generation = target_files::ParseNumber(value, list.round);
        if (!generation) return std::nullopt;
        list.refresh = *generation;
        pos=end+1;
    }
    for(;pos<text.size();) {
        const auto end=text.find('\n',pos);if(end==std::string_view::npos)return std::nullopt;
        auto line=text.substr(pos,end-pos);pos=end+1;if(line.ends_with('\r'))line.remove_suffix(1);
        const auto tab = line.find(target_files::RowSeparator);
        if (tab == std::string_view::npos || list.rows.size() >= target_files::MaxRows) return std::nullopt;
        const auto number = target_files::ParseNumber(line.substr(0, tab), target_files::MaxTargetId);
        if (!number) return std::nullopt;
        const auto id = *number;
        if (std::any_of(list.rows.begin(),list.rows.end(),[&](const auto& row){return row.id==id;}))return std::nullopt;
        auto hex=line.substr(tab+1);
        std::string peerMac;
        bool freshName=false;
        if(const auto metadata=hex.find(target_files::RowSeparator);metadata!=std::string_view::npos) {
            const auto fields=hex.substr(metadata+1);
            if(fields.size()!=14||fields[12] != target_files::RowSeparator ||
                (fields[13] != target_files::Unnamed && fields[13] != target_files::Named)||
                !IsTargetPeerMac(fields.substr(0,12)))return std::nullopt;
            peerMac=fields.substr(0,12);freshName = fields[13] == target_files::Named;
            hex=hex.substr(0,metadata);
        }
        if(hex.empty()||hex.size()%2||hex.size()>534)return std::nullopt;
        std::string bytes;
        for(std::size_t i=0;i<hex.size();i+=2) {
            unsigned value=0;const auto digit=std::from_chars(hex.data()+i,hex.data()+i+2,value,16);
            if(digit.ec!=std::errc{}||digit.ptr!=hex.data()+i+2)return std::nullopt;
            bytes+=static_cast<char>(value);
        }
        const auto length=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,bytes.data(),static_cast<int>(bytes.size()),nullptr,0);
        std::wstring label(length>0?length:0,L' ');
        if(length>0)MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,bytes.data(),static_cast<int>(bytes.size()),label.data(),length);
        for(auto& ch:label)if(ch<32||ch==127||(ch>=0x202a&&ch<=0x202e)||(ch>=0x2066&&ch<=0x2069))ch=L' ';
        if(label.empty()){label=L"デバイス"+std::to_wstring(id);freshName=false;}
        list.rows.push_back({id,FormatTargetLabel(std::move(label)),std::move(peerMac),freshName});
    }
    return list;
}

inline bool ValidateSelectedFile(const std::filesystem::path& path, std::wstring& reason, std::uint64_t* bytes = nullptr) {
    UniqueHandle file(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (!file) {
        reason = L"選択したファイルを開けません。ファイルを確認してください。";
        return false;
    }
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(file.get(), &info)) {
        reason = L"選択したファイルは送信できません。選び直してください。";
        return false;
    }
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        reason = L"フォルダーは送信できません。ファイルを選んでください。";
        return false;
    }
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 || GetFileType(file.get()) != FILE_TYPE_DISK) {
        reason = L"通常のファイルを選んでください。";
        return false;
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.get(), &size) || size.QuadPart < 0) {
        reason = L"選択したファイルは送信できません。選び直してください。";
        return false;
    }
    if (bytes) *bytes = static_cast<std::uint64_t>(size.QuadPart);
    return true;
}

inline bool ValidateSelectedFiles(const std::vector<std::filesystem::path>& paths, std::uint64_t& total, std::wstring& error) {
    using namespace tx10ub::send_files;
    total = 0;
    if (paths.empty()) return false;
    if (paths.size() > MaxFiles) {
        error = SendFileCountLimit;
        return false;
    }
    std::vector<std::wstring> names;
    for (const auto& path : paths) {
        std::uint64_t size = 0;
        if (!ValidateSelectedFile(path, error, &size)) return false;
        if (size > MaxBytes - total) {
            error = L"送信するファイルの合計サイズは8 GiB未満にしてください。";
            return false;
        }
        auto name = path.filename().wstring();
        if (std::any_of(names.begin(), names.end(), [&](const auto& existing) { return SameFileName(existing, name); })) {
            error = L"同じ名前のファイルが含まれています。片方を外すか、名前を変更してください。";
            return false;
        }
        names.push_back(std::move(name));
        total += size;
    }
    return true;
}

inline std::wstring WideFromUtf8(std::string_view value) {
    if (value.empty()) return {};
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0);
    if (length <= 0) return {};
    std::wstring result(static_cast<std::size_t>(length), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), result.data(), length) != length) return {};
    return result;
}

inline std::wstring SafeDisplayText(std::wstring value, std::size_t maxLength = 256) {
    for (auto& ch : value) {
        if (ch < 0x20 || ch == 0x7f || (ch >= 0x202a && ch <= 0x202e) ||
            (ch >= 0x2066 && ch <= 0x2069)) ch = L' ';
    }
    while (value.size() > maxLength) value.pop_back();
    if (!value.empty() && value.back() >= 0xd800 && value.back() <= 0xdbff) value.pop_back();
    return value;
}

// Owner process recorded in a session's request.json, or 0 when unreadable.
inline DWORD RequestOwnerPid(const std::filesystem::path& request) {
    const auto contents = ReadSmallTextFile(request);
    if (!contents) return 0;
    const auto key = request_file::Field(request_file::OwnerPid);
    const auto at = contents->find(key);
    if (at == std::string::npos) return 0;
    unsigned long long value = 0;
    std::size_t digits = 0;
    for (auto i = at + key.size(); i < contents->size() && digits < 11; ++i, ++digits) {
        const char ch = (*contents)[i];
        if (ch < '0' || ch > '9') break;
        value = value * 10 + static_cast<unsigned>(ch - '0');
    }
    return digits && value <= MAXDWORD ? static_cast<DWORD>(value) : 0;
}

inline bool HasMarker(const std::filesystem::path& file, std::string_view content) {
    return ReadSmallTextFile(file) == content;
}

// The newest session of this app run that left the Wi-Fi adapter in its transfer
// state and is still waiting to be taken over or restored.
inline std::optional<std::filesystem::path> FindKeptRadioSession(const std::filesystem::path& sessions, DWORD ownerPid) {
    if (sessions.empty() || !ownerPid) return std::nullopt;
    std::optional<std::filesystem::path> newest;
    std::filesystem::file_time_type newestTime{};
    std::error_code error;
    for (std::filesystem::directory_iterator it(sessions, error), end; it != end && !error; it.increment(error)) {
        const auto& directory = it->path();
        if (!request_file::ValidDirectory(directory.filename().native())) continue;
        const auto attributes = GetFileAttributesW(directory.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) continue;
        if (!HasMarker(directory / session_markers::RadioKeptFileName, session_markers::RadioKeptContent) ||
            HasMarker(directory / session_markers::RadioAdoptedFileName, session_markers::RadioAdoptedContent) ||
            HasMarker(directory / session_markers::RecoveryCompletedFileName, session_markers::RecoveryCompletedContent) ||
            HasMarker(directory / session_markers::RecoveryDismissedFileName, session_markers::RecoveryDismissedContent) ||
            ReadSmallTextFile(directory / supervisor::RecoveryResultFileName)) continue;
        const auto request = directory / request_file::FileName;
        if (RequestOwnerPid(request) != ownerPid) continue;
        std::error_code timeError;
        const auto time = std::filesystem::last_write_time(request, timeError);
        if (!timeError && (!newest || time > newestTime)) {
            newest = request;
            newestTime = time;
        }
    }
    return newest;
}

inline std::optional<std::filesystem::path> FindPendingWifiRecovery(const std::filesystem::path& sessions,
                                                                   DWORD runningOwnerPid = 0) {
    if (sessions.empty()) return std::nullopt;
    using supervisor::Phase;
    constexpr Phase activePhases[]{Phase::PreparingNetwork, Phase::PreparingRadio, Phase::Discovering,
        Phase::Selecting, Phase::Connecting, Phase::WaitingAccept, Phase::Sending, Phase::Finalizing,
        Phase::Listening, Phase::Restoring};
    std::optional<std::filesystem::path> newest;
    std::filesystem::file_time_type newestTime{};
    std::error_code error;
    for (std::filesystem::directory_iterator it(sessions, error), end; it != end && !error; it.increment(error)) {
        const auto& directory = it->path();
        const auto name = directory.filename().wstring();
        if (!request_file::ValidDirectory(name)) continue;
        const auto attributes = GetFileAttributesW(directory.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) continue;
        const auto request = directory / request_file::FileName;
        const auto requestAttributes = GetFileAttributesW(request.c_str());
        if (requestAttributes == INVALID_FILE_ATTRIBUTES || (requestAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) continue;
        if (ReadSmallTextFile(directory / session_markers::RecoveryCompletedFileName) ==
            session_markers::RecoveryCompletedContent) continue;
        if (ReadSmallTextFile(directory / session_markers::RecoveryDismissedFileName) ==
            session_markers::RecoveryDismissedContent) continue;
        // A later transfer took this state over, so that session owns its restoration.
        if (HasMarker(directory / session_markers::RadioAdoptedFileName, session_markers::RadioAdoptedContent)) continue;
        // The running app restores its own kept state when it closes. A kept state
        // left by an app that exited, or whose restoration failed, needs recovery.
        if (runningOwnerPid && HasMarker(directory / session_markers::RadioKeptFileName, session_markers::RadioKeptContent) &&
            !ReadSmallTextFile(directory / supervisor::RecoveryResultFileName) &&
            RequestOwnerPid(request) == runningOwnerPid) continue;

        const auto candidate = sessions / name.substr(0, name.size() - request_file::DirectorySuffix.size());
        const auto snapshotAttributes = GetFileAttributesW((candidate / session_markers::RadioSnapshotFileName).c_str());
        if (snapshotAttributes == INVALID_FILE_ATTRIBUTES) {
            const auto snapshotError = GetLastError();
            if (snapshotError == ERROR_FILE_NOT_FOUND || snapshotError == ERROR_PATH_NOT_FOUND) continue;
            // The snapshot directory is private to the elevated runtime.
            if (const auto recoveryResult = ReadSmallTextFile(directory / supervisor::RecoveryResultFileName)) {
                const auto values = ParseKeyValues(*recoveryResult);
                if (std::string_view(Value(values, supervisor::FailureReasonKey)) ==
                    supervisor::RecoverySnapshotMissingReason) continue;
            }
        } else if (snapshotAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) {
            continue;
        }

        bool pending = false;
        if (const auto result = ReadSmallTextFile(directory / supervisor::ResultFileName)) {
            const auto values = ParseKeyValues(*result);
            const auto recovery = std::string_view(Value(values, supervisor::RecoveryRequiredKey));
            pending = recovery == "1" ||
                (recovery.empty() && snapshotAttributes != INVALID_FILE_ATTRIBUTES &&
                 IsOne(values, supervisor::RestorationRequiredKey) && RestorationNeedsAttention(ClassifyRestoration(values)));
        } else if (const auto status = ReadSmallTextFile(directory / supervisor::StatusFileName)) {
            const auto last = status->find_last_not_of("\r\n");
            const auto phase = supervisor::ParsePhase(std::string_view(*status).substr(0, last + 1));
            pending = std::find(std::begin(activePhases), std::end(activePhases), phase) != std::end(activePhases);
        }
        if (!pending) continue;
        std::error_code timeError;
        const auto time = std::filesystem::last_write_time(request, timeError);
        if (!timeError && (!newest || time > newestTime)) {
            newest = request;
            newestTime = time;
        }
    }
    return newest;
}

struct ReceiveFile {
    std::wstring name;
    std::optional<std::uint64_t> size;
};

struct IncomingRequest {
    std::string token;
    std::wstring sender;
    std::vector<ReceiveFile> files;
    bool hasPreview = false;
};

inline std::optional<IncomingRequest> ParseIncomingRequest(std::string_view text) {
    JsonValue root;
    if (!JsonParser(text).Parse(root) || root.kind != JsonValue::Kind::Object) return std::nullopt;
    const auto token = JsonString(root, tx10ub::receive_state::TokenField);
    const auto sender = JsonString(root, tx10ub::receive_state::SenderField);
    const auto* files = JsonMember(root, tx10ub::receive_state::FilesField);
    if (!token || !receive_offer::ValidToken(*token) || !sender || !files || files->kind != JsonValue::Kind::Array ||
        files->array.empty() || files->array.size() > receive_offer::MaxFiles) return std::nullopt;
    IncomingRequest request;
    request.token = *token;
    if (const auto* preview = JsonMember(root, receive_offer::HasPreviewField))
        request.hasPreview = preview->kind == JsonValue::Kind::Boolean && preview->text == "true";
    request.sender = SafeDisplayText(WideFromUtf8(*sender));
    if (request.sender.empty()) request.sender = L"近くのデバイス";
    for (const auto& item : files->array) {
        const auto fileName = JsonString(item, tx10ub::receive_state::FileNameField);
        if (!fileName) return std::nullopt;
        ReceiveFile file;
        file.name = SafeDisplayText(WideFromUtf8(*fileName), 240);
        if (file.name.empty()) file.name = L"ファイル";
        if (JsonMember(item, tx10ub::receive_state::FileSizeField)) {
            const auto parsedSize = JsonUnsigned(item, tx10ub::receive_state::FileSizeField);
            if (!parsedSize) return std::nullopt;
            file.size = *parsedSize;
        }
        request.files.push_back(std::move(file));
    }
    return request;
}

struct ReceiveState {
    tx10ub::receive_state::Phase phase = tx10ub::receive_state::Phase::Unknown;
    std::string token;
    std::wstring sender;
    std::wstring receiverName;
    std::wstring expiresAtUtc;
    std::optional<std::uint64_t> receivedBytes;
    bool waitingForData = false;
    std::optional<std::uint64_t> totalBytes;
    std::optional<std::uint64_t> totalFiles;
    std::optional<std::uint64_t> idleDeadlineMs;
    std::optional<std::uint64_t> discoveredAtMs;
    std::string lastResult;
    std::optional<tx10ub::receive_state::FailureReason> failureReason;
    std::vector<std::wstring> savedPaths;
};

inline std::optional<ReceiveState> ParseReceiveState(std::string_view text) {
    JsonValue root;
    if (!JsonParser(text).Parse(root) || root.kind != JsonValue::Kind::Object) return std::nullopt;
    using namespace tx10ub::receive_state;
    const auto phase = ReadPhase(root);
    if (!phase) return std::nullopt;
    ReceiveState state;
    state.phase = *phase;
    if (const auto token = JsonString(root, TokenField); token && receive_offer::ValidToken(*token)) state.token = *token;
    if (const auto sender = JsonString(root, SenderField)) state.sender = SafeDisplayText(WideFromUtf8(*sender));
    if (const auto name = JsonString(root, ReceiverNameField)) state.receiverName = SafeDisplayText(WideFromUtf8(*name));
    if (const auto expires = JsonString(root, ExpiresAtUtcField)) state.expiresAtUtc = WideFromUtf8(*expires);
    state.receivedBytes = JsonUnsigned(root, ReceivedBytesField);
    if (const auto* waiting = JsonMember(root, WaitingForDataField))
        state.waitingForData = waiting->kind == JsonValue::Kind::Boolean && waiting->text == "true";
    state.totalBytes = JsonUnsigned(root, TotalBytesField);
    state.totalFiles = JsonUnsigned(root, TotalFilesField);
    state.idleDeadlineMs = JsonUnsigned(root, IdleDeadlineMsField);
    state.discoveredAtMs = JsonUnsigned(root, DiscoveredAtMsField);
    if (const auto lastResult = JsonString(root, LastResultField)) state.lastResult = *lastResult;
    if (const auto reason = JsonUnsigned(root, FailureReasonField)) {
        state.failureReason = static_cast<FailureReason>(*reason);
    } else if (const auto diagnostic = JsonString(root, ErrorField); !diagnostic.value_or("").empty()) {
        // Older workers report only a diagnostic. Keep the generic guidance.
        state.failureReason = FailureReason::Other;
    }
    if (const auto* paths = JsonMember(root, SavedPathsField)) {
        if (paths->kind != JsonValue::Kind::Array || paths->array.size() > 256) return std::nullopt;
        for (const auto& path : paths->array) {
            if (path.kind != JsonValue::Kind::String) return std::nullopt;
            const auto savedPath = WideFromUtf8(path.text);
            if (savedPath.empty() || savedPath.find(L'\0') != std::wstring::npos) return std::nullopt;
            state.savedPaths.push_back(savedPath);
        }
    }
    return state;
}

inline bool RecentlyDiscoveredForReceive(const ReceiveState& state, std::uint64_t now) noexcept {
    constexpr std::uint64_t noticeMs = std::chrono::milliseconds(std::chrono::minutes(1)).count();
    return state.idleDeadlineMs && now < *state.idleDeadlineMs && state.discoveredAtMs &&
        now >= *state.discoveredAtMs && now - *state.discoveredAtMs < noticeMs &&
        (state.phase == tx10ub::receive_state::Phase::Listening || state.phase == tx10ub::receive_state::Phase::Completed);
}

inline bool HasPublishedReceivePaths(const ReceiveState& state) noexcept {
    if (!state.savedPaths.empty()) return true;
    using tx10ub::receive_state::Phase;
    if (state.phase == Phase::Completed || state.phase == Phase::Failed) return true;
    return state.phase == Phase::Listening &&
        (state.lastResult == tx10ub::receive_state::FailedResult ||
         state.lastResult == tx10ub::receive_state::CancelledResult);
}

inline std::wstring FormatBytes(std::uint64_t bytes) {
    std::wostringstream text;
    if (bytes < 1024) text << bytes << L"B";
    else if (bytes < 1024ULL * 1024) text << std::fixed << std::setprecision(1) <<
        static_cast<double>(bytes) / 1024.0 << L"KiB";
    else text << std::fixed << std::setprecision(1) <<
        static_cast<double>(bytes) / (1024.0 * 1024.0) << L"MiB";
    return text.str();
}

inline std::wstring IncomingFilesText(const IncomingRequest& request) {
    std::wstring result;
    constexpr std::size_t maxRows = 100;
    const auto rows = (std::min)(request.files.size(), maxRows);
    for (std::size_t index = 0; index < rows; ++index) {
        if (!result.empty()) result += L"\r\n";
        result += request.files[index].name;
        if (request.files[index].size) result += L"（" + FormatBytes(*request.files[index].size) + L"）";
    }
    if (request.files.size() > rows) result += L"\r\nほか" + std::to_wstring(request.files.size() - rows) + L"件";
    return result;
}
inline std::wstring IncomingSizeText(const IncomingRequest& request) {
    std::uint64_t total=0;
    bool known=true;
    for(const auto& file:request.files) {
        if(!file.size || *file.size>(std::numeric_limits<std::uint64_t>::max)()-total) {known=false;break;}
        total+=*file.size;
    }
    return known ? L"合計 " + FormatBytes(total) : L"合計サイズ不明";
}

inline std::wstring SavedPathsText(const ReceiveState& state) {
    std::wstring result;
    for (std::size_t index = 0; index < state.savedPaths.size(); ++index) {
        if (!result.empty()) result += L"\r\n";
        result += SafeDisplayText(state.savedPaths[index], 1024);
        if (result.size() > 7000) {
            result += L"\r\nほかの保存先があります。";
            break;
        }
    }
    return result;
}

inline std::wstring ReceiveProgressText(const ReceiveState& state) {
    if (!state.receivedBytes) return {};
    if (!state.totalBytes || *state.receivedBytes > *state.totalBytes) {
        auto result = L"受信済み：" + FormatBytes(*state.receivedBytes);
        if (state.totalFiles) result += L"\r\nファイル数：" + std::to_wstring(*state.totalFiles);
        return result;
    }
    const auto estimatedPercent = *state.totalBytes ? static_cast<std::uint64_t>(
        static_cast<long double>(*state.receivedBytes) * 100.0L / static_cast<long double>(*state.totalBytes)) : 0;
    const auto percent = (std::min)(std::uint64_t{99}, estimatedPercent);
    std::wstring result = L"受信中（目安）" + std::to_wstring(percent) + L"%　" +
        FormatBytes(*state.receivedBytes) + L"/" + FormatBytes(*state.totalBytes);
    if (state.totalFiles) result += L"\r\nファイル数：" + std::to_wstring(*state.totalFiles);
    return result;
}

inline std::wstring DownloadsPath() {
    PWSTR rawPath = nullptr;
    const HRESULT result = SHGetKnownFolderPath(FOLDERID_Downloads, KF_FLAG_DEFAULT, nullptr, &rawPath);
    if (FAILED(result) || rawPath == nullptr) {
        if (rawPath) CoTaskMemFree(rawPath);
        return {};
    }
    std::filesystem::path path(rawPath);
    CoTaskMemFree(rawPath);
    const auto attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) return {};
    return path.lexically_normal().wstring();
}

inline std::filesystem::path ReceiveFolderPreferencePath(const std::filesystem::path& localAppData) {
    return localAppData / L"DropPorter" / L"receive-folder.txt";
}

inline std::filesystem::path KeepRadioPreferencePath(const std::filesystem::path& localAppData) {
    return localAppData / L"DropPorter" / L"keep-radio.txt";
}

inline std::optional<std::filesystem::path> ParseReceiveFolderPreference(std::string_view value) {
    if (value.size() > 32768) return std::nullopt;
    while (!value.empty() && (value.back() == '\r' || value.back() == '\n')) value.remove_suffix(1);
    if (value.empty() || value.find_first_of("\r\n") != std::string_view::npos) return std::nullopt;
    const auto wide = WideFromUtf8(value);
    if (wide.empty() || wide.find(L'\0') != std::wstring::npos) return std::nullopt;
    const std::filesystem::path path(wide);
    if (!path.is_absolute()) return std::nullopt;
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) return std::nullopt;
    return path.lexically_normal();
}

inline std::optional<std::filesystem::path> ReadReceiveFolderPreference(const std::filesystem::path& file) {
    const auto contents = ReadSmallTextFile(file);
    return contents ? ParseReceiveFolderPreference(*contents) : std::nullopt;
}

inline bool PublishLocalFile(const std::filesystem::path& file, std::string_view contents, bool replaceExisting) {
    const auto token = NewToken();
    if (!token) return false;
    const auto temporary = file.parent_path() / (file.filename().wstring() + L"-" + *token + L".tmp");
    const DWORD flags = MOVEFILE_WRITE_THROUGH | (replaceExisting ? MOVEFILE_REPLACE_EXISTING : 0);
    if (WriteNewFile(temporary, contents) && MoveFileExW(temporary.c_str(), file.c_str(), flags)) return true;
    DeleteFileW(temporary.c_str());
    return false;
}

inline bool WriteLocalPreference(const std::filesystem::path& file, std::string_view contents) {
    std::error_code error;
    std::filesystem::create_directories(file.parent_path(), error);
    return !error && PublishLocalFile(file, contents, true);
}

inline bool PersistReceiveFolderPreference(const std::filesystem::path& file,
                                    const std::filesystem::path& folder) {
    if (!folder.is_absolute() || folder.native().find(L'\0') != std::wstring::npos) return false;
    const DWORD attributes = GetFileAttributesW(folder.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) return false;
    const auto utf8 = Utf8(folder.lexically_normal().wstring());
    if (utf8.empty() || utf8.size() > 32768) return false;
    return WriteLocalPreference(file, utf8);
}

inline void ApplyRememberedTargetNames(const std::filesystem::path& file, std::vector<TargetRow>& rows) {
    if (file.empty() || std::none_of(rows.begin(), rows.end(), [](const TargetRow& row) {
        return !row.peerMac.empty();
    })) return;
    constexpr std::size_t limit = 64;
    std::vector<std::pair<std::string, std::wstring>> names;
    if (const auto saved = ReadSmallTextFile(file)) {
        std::istringstream input(*saved);
        std::string line;
        while (names.size() < limit && std::getline(input, line)) {
            const auto tab = line.find('\t');
            if (tab == std::string::npos || !IsTargetPeerMac(std::string_view(line).substr(0, tab)) ||
                line.size() - tab - 1 > 267) continue;
            auto label = SafeDisplayText(WideFromUtf8(std::string_view(line).substr(tab + 1)), 267);
            if (!label.empty()) names.emplace_back(line.substr(0, tab), FormatTargetLabel(std::move(label)));
        }
    }
    bool changed = false;
    for (auto& row : rows) {
        if (row.peerMac.empty()) continue;
        const auto known = std::find_if(names.begin(), names.end(), [&](const auto& name) {
            return name.first == row.peerMac;
        });
        if (!row.freshName) {
            if (known != names.end()) row.label = known->second;
            continue;
        }
        if (known != names.end()) {
            if (known->second == row.label) continue;
            names.erase(known);
        }
        names.emplace_back(row.peerMac, row.label);
        if (names.size() > limit) names.erase(names.begin());
        changed = true;
    }
    if (changed) {
        std::string contents;
        for (const auto& [mac, label] : names) contents += mac + '\t' + Utf8(label) + '\n';
        WriteLocalPreference(file, contents);
    }
}

inline std::optional<std::filesystem::path> LoadReceiveFolderPreference(
    const std::filesystem::path& localAppData) {
    const auto settings = ReceiveFolderPreferencePath(localAppData);
    if (const auto saved = ReadReceiveFolderPreference(settings)) return saved;
    std::error_code error;
    // A present but invalid new preference must not resurrect an old selection.
    if (std::filesystem::exists(settings, error) || error) return std::nullopt;
    const auto legacy = ReadReceiveFolderPreference(localAppData / L"AWDLWin" / L"receive-folder.txt");
    if (legacy) {
        // Keep the old file, and keep using its value if saving the new copy fails.
        PersistReceiveFolderPreference(settings, *legacy);
    }
    return legacy;
}

inline std::filesystem::path ReceiveFolderSettingsFile() {
    PWSTR rawPath = nullptr;
    const HRESULT result = SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &rawPath);
    if (FAILED(result) || rawPath == nullptr) {
        if (rawPath) CoTaskMemFree(rawPath);
        return {};
    }
    const std::filesystem::path localAppData(rawPath);
    CoTaskMemFree(rawPath);
    return ReceiveFolderPreferencePath(localAppData);
}

// Off unless the user turned it on; an unreadable setting keeps the default.
inline bool KeepRadioPreference() {
    const auto settings = ReceiveFolderSettingsFile();
    if (settings.empty()) return false;
    const auto value = ReadSmallTextFile(KeepRadioPreferencePath(settings.parent_path().parent_path()));
    return value && (*value == "1" || *value == "1\n");
}

inline bool PersistKeepRadioPreference(bool enabled) {
    const auto settings = ReceiveFolderSettingsFile();
    if (settings.empty()) return false;
    return WriteLocalPreference(KeepRadioPreferencePath(settings.parent_path().parent_path()), enabled ? "1\n" : "0\n");
}

inline std::string KeepRadioRequestField() {
    return KeepRadioPreference() ? request_file::Field(request_file::KeepRadio) + "1,\n  " : std::string{};
}

inline std::wstring PreferredReceiveFolder() {
    const auto settings = ReceiveFolderSettingsFile();
    if (!settings.empty()) {
        if (const auto saved = LoadReceiveFolderPreference(settings.parent_path().parent_path())) return saved->wstring();
    }
    return DownloadsPath();
}

inline std::optional<std::filesystem::path> ResolveOpenableSavedFile(
    const std::filesystem::path& savedPath, const std::filesystem::path& sessionDestination) {
    if (!savedPath.is_absolute() || !sessionDestination.is_absolute()) return std::nullopt;
    std::error_code error;
    const auto destination = std::filesystem::canonical(sessionDestination, error);
    if (error || !std::filesystem::is_directory(destination, error) || error) return std::nullopt;
    error.clear();
    const auto resolved = std::filesystem::canonical(savedPath, error);
    if (error || !std::filesystem::is_regular_file(resolved, error) || error) return std::nullopt;
    std::wstring root = destination.wstring();
    if (root.empty()) return std::nullopt;
    if (root.back() != L'\\' && root.back() != L'/') root.push_back(L'\\');
    const std::wstring candidate = resolved.wstring();
    if (candidate.size() < root.size() || root.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()) ||
        CompareStringOrdinal(root.c_str(), static_cast<int>(root.size()), candidate.c_str(),
            static_cast<int>(root.size()), TRUE) != CSTR_EQUAL) return std::nullopt;
    return resolved;
}

struct TransferView {
    virtual ~TransferView() = default;
    virtual void SetControlText(TransferField, const std::wstring&) = 0;
    virtual void EnableControl(TransferField, bool) = 0;
    virtual int SelectedTarget() const = 0;
    virtual bool ShowTargets(const std::vector<TargetRow>&, int selected) = 0;
    virtual int SelectedSavedFile() const = 0;
    virtual void ShowSavedFiles(const std::vector<std::filesystem::path>&, int selected) = 0;
    virtual bool StartPolling() = 0;
    virtual void StopPolling() = 0;
    // An empty result means the view will deliver the outcome on a later poll.
    virtual std::optional<bool> LaunchRuntime(const std::filesystem::path&, const std::wstring&, HANDLE&, DWORD&) = 0;
    virtual void OperationStarted() = 0;
    virtual void OperationFinished(Operation, bool) = 0;
};
class SenderController {
public:
    SenderController(ShareLifecycle& lifecycle, TransferView& view);
private:
    ShareLifecycle& lifecycle_;
    TransferView& view_;
    std::vector<std::filesystem::path> selectedFiles_;
    std::optional<std::uint64_t> selectedBytes_;
    std::filesystem::path requestDirectory_;
    std::filesystem::path requestFile_;
    std::filesystem::path statusFile_;
    std::filesystem::path progressFile_;
    std::string targetSnapshot_;
    std::vector<TargetRow> targets_;
    unsigned targetRound_=0;
    unsigned refreshGeneration_=0,refreshSelection_=0;
    bool refreshingTargets_=false;
    bool selectingTarget_=false,targetSubmitted_=false;
    bool targetConfirmed_=false;
    bool sendCompleted_=false;
    bool initialTargetSelected_=false;
    std::optional<std::chrono::steady_clock::time_point> searchStarted_;
    bool showSearchHelpAfterResult_=false;
    std::filesystem::path resultFile_;
    std::filesystem::path cancelFile_;
    std::wstring currentStatus_;
    std::wstring currentDetails_;
    std::optional<TransferProgress> progress_;
    TransferResultDisplay result_;
    supervisor::Phase phase_ = supervisor::Phase::Unknown;
    UniqueHandle childProcess_;
    bool running_ = false;
    bool cancellationRequested_ = false;
    bool otherModeBusy_ = false;
    bool starting_ = false;
    bool cancelAfterStart_ = false;
public:
    void StartSend();
    bool SendCompleted() const noexcept { return sendCompleted_; }
    void SubmitTarget();
    bool CanRefreshTargets() const;
    bool CanChooseFiles() const noexcept;
    void RefreshTargets();
    void UpdateTargets();
    void RequestCancel();
    void PollChild();
    void FinishChild(DWORD exitCode);
    void SetOtherModeBusy(bool busy);
    // Start is queued until the waiting receive has stopped.
    void WaitForReceiveStop();
    void RequestHostClose();

    bool IsRunning() const noexcept;
    bool IsStarting() const noexcept;
    void CompleteLaunch(bool launched, HANDLE process, DWORD error);
    void LogDiscoveryTiming(std::string_view stage,std::int64_t at = discovery_timing::NowUs()) const noexcept;
    std::optional<TransferProgress> Progress() const;
    TransferActivity Activity() const;
    const TransferResultDisplay& Result() const;
    bool ShowsSearchHelp(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) const noexcept;
    const std::wstring& Status() const noexcept;
    void ReportUiError(std::wstring message);

    void SelectFile(const std::filesystem::path& path);
    const std::vector<std::filesystem::path>& SelectedFiles() const noexcept;
    std::wstring SelectionSizeText() const;
    void SelectFiles(std::vector<std::filesystem::path> paths);
    void TargetSelectionChanged();
};

class ReceiverController {
public:
    ReceiverController(ShareLifecycle& lifecycle, TransferView& view);
private:
    ShareLifecycle& lifecycle_;
    TransferView& view_;
    std::wstring downloadsPath_;
    std::filesystem::path sessionDestination_;
    std::vector<std::filesystem::path> completedFiles_;
    std::filesystem::path requestDirectory_;
    std::filesystem::path requestFile_;
    std::filesystem::path statusFile_;
    std::filesystem::path resultFile_;
    std::filesystem::path cancelFile_;
    std::filesystem::path incomingFile_;
    std::filesystem::path receiveStateFile_;
    std::optional<IncomingRequest> incoming_;
    std::optional<ReceiveState> receiveState_;
    bool WaitingForOffer() const noexcept;
    TransferResultDisplay result_;
    bool liveResultVisible_=true;
    supervisor::Phase supervisorPhase_ = supervisor::Phase::Unknown;
    std::wstring currentSender_;
    std::wstring currentFiles_;
    std::wstring currentStatus_ = L"受信を開始するとWi-Fi接続が切断されます。";
    std::wstring currentDetails_;
    UniqueHandle childProcess_;
    bool running_ = false;
    bool cancellationRequested_ = false;
    bool decisionSubmitted_ = false;
    bool otherModeBusy_ = false;
    bool starting_ = false;
    bool cancelAfterStart_ = false;
public:
    void StartReceive();
    void SubmitDecision(bool accept);
    void SubmitNotificationDecision(std::wstring_view token, bool accept);
    void RequestCancel();
    void RefreshFromFiles();
    void RefreshControls();
    void SetOtherModeBusy(bool busy);
    void RequestHostClose();
    void PollChild();
    void FinishChild(DWORD exitCode);

    bool IsRunning() const noexcept;
    bool IsStarting() const noexcept;
    void CompleteLaunch(bool launched, HANDLE process, DWORD error);
    const std::wstring& Status() const noexcept;
    void ReportUiError(std::wstring message);

    const std::wstring& ReceiveFolder() const noexcept;
    // Stop only a receive that is still waiting for a sender. Returns whether it was asked to stop.
    bool StopWaitingForSend();
    bool HasIncoming() const noexcept;
    bool IsReceiving() const noexcept;
    // Only waiting for a sender: stopping it loses nothing the user started.
    bool CanYieldToSend() const noexcept;
    TransferActivity Activity() const;
    std::size_t OfferFileCount() const noexcept;
    std::wstring OfferSizeText() const;
    const IncomingRequest* PendingOffer() const noexcept;
    std::wstring OfferPreviewPath() const;
    std::wstring OfferExpiration() const;
    TransferResultDisplay Result() const;
    std::optional<TransferProgress> Progress() const;
    void SelectReceiveFolder(const std::filesystem::path& selected);
    void RefreshSavedFiles(const std::vector<std::wstring>& paths);
    std::optional<std::filesystem::path> SelectedFileToOpen();
    std::optional<std::filesystem::path> SavedFilesFolder() const;
};

}
