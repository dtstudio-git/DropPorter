#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <wlanapi.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace tx10ub::host {

enum class DriverImage { Stock, Shared, Tx20u1281, Tx20u1132 };
struct Adapter {
    GUID guid{};
    NET_LUID luid{};
    NET_IFINDEX index{};
    std::wstring alias;
    std::wstring instanceId;
    DriverImage driverImage{};
    bool mediaDisconnected{};
};

enum class AdapterModel { Tx10ubNano, Tx20uNano };

// Model-specific diagnostics and recovery of historical USB capture sessions.
struct AdapterProfile {
    AdapterModel model;
    const wchar_t* instancePrefix;          // PnP instance ID of the USB device, upper case
    USHORT usbVendorId;
    USHORT usbProductId;
    bool usbDeviceIsNetworkFunction;        // single-function device: no composite parent
    DriverImage diagnosticImage;
    bool usbCaptureRestartCyclesPort;
    bool verifiesRxSettingsAfterRestart;
};

inline constexpr AdapterProfile kAdapterProfiles[] = {
    {AdapterModel::Tx20uNano, L"USB\\VID_35BC&PID_0108\\", 0x35bc, 0x0108, true, DriverImage::Shared, true, true},
    {AdapterModel::Tx10ubNano, L"USB\\VID_3625&PID_010B&MI_02\\", 0x3625, 0x010b, false, DriverImage::Stock, false, false},
};

constexpr const AdapterProfile& ProfileFor(AdapterModel model) {
    for (const auto& profile : kAdapterProfiles)
        if (profile.model == model) return profile;
    throw std::logic_error("adapter_profile_missing");
}

// nullptr when the instance ID is not a supported adapter.
const AdapterProfile* FindProfile(const std::wstring& instanceId);
// Throws adapter_model_unknown when the adapter is not a supported model.
const AdapterProfile& ProfileOf(const Adapter& adapter);

Adapter DiscoverAdapter();
Adapter DiscoverAdapter(AdapterModel model);
// Prefer a disconnected WLAN interface. Break ties by interface GUID.
Adapter DiscoverTransferAdapter();
std::filesystem::path RealtekServiceDriverPath();
// The connected supported adapter with this GUID; throws adapter_not_present.
Adapter DiscoverAdapterByGuid(const GUID& guid);
std::array<UCHAR, 32> FileSha256(const std::filesystem::path& path);
bool MatchesStockRealtekDigest(const std::array<UCHAR, 32>& digest);
bool MatchesSharedRealtekDigest(const std::array<UCHAR, 32>& digest);
std::optional<DriverImage> ClassifyDriverImage(const std::array<UCHAR, 32>& digest);
void RequireStockRealtekDriver();
void RequireApCoexistenceDriver();

struct UsbCaptureTarget {
    std::wstring filterPath;
    ULONG address{};
};

UsbCaptureTarget DiscoverUsbCaptureTarget(const Adapter& adapter);
// Only for profiles with usbCaptureRestartCyclesPort.
void CycleUsbPort(const Adapter& adapter);
// Only for profiles with usbDeviceIsNetworkFunction.
bool HasUsbPcapFilter(const Adapter& adapter);

struct Channel {
    ULONG band{};
    ULONG primary{};
    ULONG width{};
    ULONG offset{};
};

struct BbState {
    ULONG encoded{};
    ULONG width{};
    ULONG primaryIndex{};
    ULONG smallBand{};
    ULONG is24Ghz{};
    friend bool operator==(const BbState&, const BbState&) = default;
};

struct WifiSnapshot {
    bool autoconfEnabled{};
    WLAN_INTERFACE_STATE state{wlan_interface_state_not_ready};
    std::wstring profileName;
    std::array<UCHAR, 6> bssid{};
    ULONG channel{};
    DOT11_SSID ssid{}; // Optional for older recovery journals; live captures retain exact SSID bytes.
};

inline bool IsSavedWifiNetwork(const WifiSnapshot& saved, const wchar_t* profileName,
                               const DOT11_SSID& ssid, const UCHAR* bssid) {
    if (saved.profileName.empty() || saved.profileName != profileName) return false;
    // Version 1 and 2 recovery journals only recorded the access point.
    if (!saved.ssid.uSSIDLength)
        return std::memcmp(saved.bssid.data(), bssid, saved.bssid.size()) == 0;
    return ssid.uSSIDLength <= DOT11_SSID_MAX_LENGTH && saved.ssid.uSSIDLength == ssid.uSSIDLength &&
        std::memcmp(saved.ssid.ucSSID, ssid.ucSSID, ssid.uSSIDLength) == 0;
}

inline bool WifiStateRestored(const WifiSnapshot& saved, const WifiSnapshot& actual) {
    return saved.state == actual.state && saved.autoconfEnabled == actual.autoconfEnabled &&
        (saved.state != wlan_interface_state_connected ||
         IsSavedWifiNetwork(saved, actual.profileName.c_str(), actual.ssid, actual.bssid.data()));
}

class RxReadbackError final : public std::runtime_error {
public:
    RxReadbackError(std::string message, bool lowerCompletionUnconfirmed)
        : std::runtime_error(std::move(message)), lowerCompletionUnconfirmed_(lowerCompletionUnconfirmed) {}
    bool lowerCompletionUnconfirmed() const noexcept { return lowerCompletionUnconfirmed_; }
private:
    bool lowerCompletionUnconfirmed_{};
};

class WifiRadio {
public:
    explicit WifiRadio(Adapter adapter);
    ~WifiRadio();
    WifiRadio(const WifiRadio&) = delete;
    WifiRadio& operator=(const WifiRadio&) = delete;

    WifiSnapshot Capture() const;
    WLAN_INTERFACE_STATE InterfaceState() const;
    bool AutoconfEnabled() const;
    void SetAutoconf(bool enabled) const;
    void Disconnect() const;
    void Connect(const WifiSnapshot& snapshot, DWORD timeoutMs = 30000) const;

private:
    DWORD Query(DWORD opcode, std::vector<std::byte>& data) const;
    Adapter adapter_;
    HANDLE client_{};
};

class VendorTransport {
public:
    explicit VendorTransport(Adapter adapter);
    ~VendorTransport();
    VendorTransport(const VendorTransport&) = delete;
    VendorTransport& operator=(const VendorTransport&) = delete;

    void Open(DriverImage image = DriverImage::Stock);
    void Close();
    bool undrained() const noexcept { return undrained_; }
    bool has_pending() const noexcept { return !requests_.empty(); }
    bool poisoned() const noexcept { return poisoned_; }
    std::string Command(const std::vector<std::string>& tokens);
    BbState ReadBb();
    Channel ChannelFromBb(const BbState& state) const;
    void SetChannel(const Channel& channel);
    void SetMonitorMode(bool enabled);
    // Fixed read-only diagnostic, also usable while connected. Caller owns
    // the session mutex and has required the auxiliary driver to be stopped.
    // If undrained is set, retain that mutex until process exit; no more I/O.
    static std::string ReadScanHistory(Adapter adapter, bool& undrained);

private:
    void OpenDevice(bool requireDisconnected, DriverImage image = DriverImage::Stock);
    struct Pending;
    Pending* Issue(DWORD code, const void* input, DWORD inputBytes,
        DWORD outputBytes);
    std::vector<std::byte> Finish(Pending& request);
    void Cancel(Pending& request);
    ULONG ReadRegister(ULONG address);
    Adapter adapter_;
    HANDLE device_{INVALID_HANDLE_VALUE};
    HANDLE mutex_{};
    bool ownsMutex_{};
    bool poisoned_{};
    bool undrained_{};
    ULONG job_{0x41574450};
    std::vector<std::unique_ptr<Pending>> requests_;
};

std::pair<ULONG, ULONG> ReadRxSettings(const std::filesystem::path& probePath);

} // namespace tx10ub::host
