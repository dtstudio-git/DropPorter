#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "Tx10ubHost.h"

#include <bcrypt.h>
#include <cfgmgr32.h>
#include <devguid.h>
#include <iphlpapi.h>
#include <netcfgx.h>
#include <setupapi.h>
#include <usbioctl.h>
#include <winioctl.h>
#include <initguid.h>
#include <devpkey.h>

#include <algorithm>
#include <atomic>
#include <charconv>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <exception>
#include <iomanip>
#include <limits>
#include <memory>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <unordered_set>
#include <optional>

namespace tx10ub::host {
namespace {

constexpr ULONG kVendorDriverIdentityIoctl = 0x122428;
constexpr ULONG kVendorReadJobIoctl = 0x122418;
constexpr ULONG kVendorExecuteIoctl = 0x122414;
// The JP V1 package and TP-Link's US 20240621 package ship this same x64 driver image.
constexpr char kRealtekDriverSha256[] =
    "57A7C804A35FE76BA8A80FF12A8D24BF27426DEEFCB1285CC28D4B2D7CB20200";

[[noreturn]] void ThrowWin32(const char* action, DWORD error = GetLastError()) {
    throw std::system_error(static_cast<int>(error), std::system_category(), action);
}

[[noreturn]] void ThrowHresult(const char* action, HRESULT hr) {
    std::ostringstream message;
    message << action << "_hr_0x" << std::hex << std::uppercase
        << std::setw(8) << std::setfill('0') << static_cast<ULONG>(hr);
    throw std::runtime_error(message.str());
}

template<class T>
class ComPtr {
public:
    ComPtr() = default;
    ~ComPtr() { reset(); }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    T* get() const { return value_; }
    T** put() { reset(); return &value_; }
    T* operator->() const { return value_; }
    explicit operator bool() const { return value_ != nullptr; }
    void reset() {
        if (value_) value_->Release();
        value_ = nullptr;
    }
private:
    T* value_{};
};

class Handle {
public:
    explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return value_; }
    bool valid() const { return value_ && value_ != INVALID_HANDLE_VALUE; }
    HANDLE release() { const auto value = value_; value_ = INVALID_HANDLE_VALUE; return value; }
    void reset(HANDLE value = INVALID_HANDLE_VALUE) {
        if (valid()) CloseHandle(value_);
        value_ = value;
    }
private:
    HANDLE value_;
};

class NetCfgSession {
public:
    explicit NetCfgSession(INetCfg* netCfg) : netCfg_(netCfg) {}
    ~NetCfgSession() { if (initialized_) (void)netCfg_->Uninitialize(); }
    void Initialized() { initialized_ = true; }
    HRESULT Close() {
        if (!initialized_) return S_OK;
        initialized_ = false;
        return netCfg_->Uninitialize();
    }
private:
    INetCfg* netCfg_{};
    bool initialized_{};
};

std::wstring Upper(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towupper(ch));
    });
    return value;
}

std::wstring DeviceIdFromComponent(INetCfgComponent* component) {
    LPWSTR allocated = nullptr;
    const HRESULT hr = component->GetPnpDevNodeId(&allocated);
    if (FAILED(hr)) {
        if (allocated) CoTaskMemFree(allocated);
        return {};
    }
    std::wstring result = allocated ? allocated : L"";
    if (allocated) CoTaskMemFree(allocated);
    return result;
}



std::vector<std::wstring> DeviceInstanceAncestors(const std::wstring& deviceId) {
    DEVINST node{};
    const CONFIGRET located = CM_Locate_DevNodeW(&node,
        const_cast<DEVINSTID_W>(deviceId.c_str()), CM_LOCATE_DEVNODE_NORMAL);
    if (located != CR_SUCCESS) return {};

    std::vector<std::wstring> result;
    for (unsigned depth = 0; depth < 16; ++depth) {
        ULONG required = 0;
        CONFIGRET status = CM_Get_Device_ID_Size(&required, node, 0);
        if (status != CR_SUCCESS || required > 32767) break;
        std::vector<wchar_t> buffer(static_cast<size_t>(required) + 1, L'\0');
        status = CM_Get_Device_IDW(node, buffer.data(), static_cast<ULONG>(buffer.size()), 0);
        if (status != CR_SUCCESS) break;
        result.emplace_back(buffer.data());
        DEVINST parent{};
        status = CM_Get_Parent(&parent, node, 0);
        if (status != CR_SUCCESS) break;
        node = parent;
    }
    return result;
}

bool IsStartedRealtekNetworkDevice(const std::wstring& instanceId) {
    if (instanceId.empty()) return false;
    DEVINST node{};
    const CONFIGRET located = CM_Locate_DevNodeW(&node,
        const_cast<DEVINSTID_W>(instanceId.c_str()), CM_LOCATE_DEVNODE_NORMAL);
    if (located != CR_SUCCESS) return false;
    ULONG status = 0, problem = 0;
    if (CM_Get_DevNode_Status(&status, &problem, node, 0) != CR_SUCCESS) return false;
    if ((status & DN_STARTED) == 0 || problem) return false;
    wchar_t service[256]{};
    ULONG bytes = sizeof(service);
    DEVPROPTYPE type{};
    return CM_Get_DevNode_PropertyW(node, &DEVPKEY_Device_Service, &type,
        reinterpret_cast<PBYTE>(service), &bytes, 0) == CR_SUCCESS &&
        type == DEVPROP_TYPE_STRING && bytes == sizeof(L"rtwlanu6") &&
        _wcsnicmp(service, L"rtwlanu6", std::size(L"rtwlanu6")) == 0;
}

Adapter MakeAdapter(const GUID& guid, const std::wstring& instanceId) {
    NET_LUID luid{};
    if (ConvertInterfaceGuidToLuid(&guid, &luid) != NO_ERROR) {
        throw std::runtime_error("tx10ub_present_adapter_has_no_network_luid");
    }
    NET_IFINDEX index{};
    if (ConvertInterfaceLuidToIndex(&luid, &index) != NO_ERROR || index == 0) {
        throw std::runtime_error("tx10ub_present_adapter_has_no_network_index");
    }
    MIB_IF_ROW2 row{};
    row.InterfaceLuid = luid;
    const DWORD ifError = GetIfEntry2(&row);
    if (ifError != NO_ERROR || row.InterfaceIndex != index ||
        row.Type != IF_TYPE_IEEE80211 || row.PhysicalAddressLength != 6 ||
        (row.PhysicalAddress[0] & 1) != 0) {
        throw std::runtime_error("tx10ub_network_interface_identity_invalid");
    }
    std::array<wchar_t, IF_MAX_STRING_SIZE + 1> alias{};
    if (ConvertInterfaceLuidToAlias(&luid, alias.data(), static_cast<ULONG>(alias.size())) != NO_ERROR) {
        throw std::runtime_error("tx10ub_network_interface_alias_unavailable");
    }
    Adapter adapter{};
    adapter.guid = guid;
    adapter.luid = luid;
    adapter.index = index;
    adapter.alias = alias.data();
    adapter.instanceId = instanceId;
    adapter.mediaDisconnected = row.MediaConnectState == MediaConnectStateDisconnected;
    return adapter;
}

std::vector<std::wstring> EnumerateUsbPcapFilters() {
    DWORD capacity = 32768;
    std::vector<wchar_t> buffer(capacity);
    for (;;) {
        const DWORD count = QueryDosDeviceW(nullptr, buffer.data(), capacity);
        if (count != 0) {
            std::vector<std::wstring> result;
            const wchar_t* current = buffer.data();
            const wchar_t* end = buffer.data() + count;
            while (current < end && *current) {
                const std::wstring name(current);
                const auto upper = Upper(name);
                if (upper.rfind(L"USBPCAP", 0) == 0 && upper.size() > 7 &&
                    std::all_of(upper.begin() + 7, upper.end(), [](wchar_t ch) {
                        return ch >= L'0' && ch <= L'9';
                    })) {
                    result.push_back(name);
                }
                current += name.size() + 1;
            }
            return result;
        }
        const DWORD error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER || capacity >= 1024 * 1024) {
            ThrowWin32("usbpcap_filter_enumeration_failed", error);
        }
        capacity *= 2;
        buffer.resize(capacity);
    }
}

std::wstring UsbPcapRootHubPath(const std::wstring& filterName) {
    const std::wstring filterPath = L"\\\\.\\" + filterName;
    // USBPcap exposes the hub link through a FILE_ANY_ACCESS IOCTL.
    Handle filter(CreateFileW(filterPath.c_str(), 0, 0, nullptr, OPEN_EXISTING, 0, nullptr));
    if (!filter.valid()) return {};

    constexpr DWORD kGetHubLink = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803,
        METHOD_BUFFERED, FILE_ANY_ACCESS);
    std::vector<wchar_t> buffer(32768, L'\0');
    DWORD returned = 0;
    if (!DeviceIoControl(filter.get(), kGetHubLink, nullptr, 0, buffer.data(),
        static_cast<DWORD>((buffer.size() - 1) * sizeof(wchar_t)), &returned, nullptr)) {
        return {};
    }
    std::wstring path(buffer.data());
    if (path.rfind(L"\\??\\", 0) == 0) path.replace(0, 4, L"\\\\?\\");
    return path;
}

std::wstring ConnectionDriverKey(HANDLE hub, ULONG port) {
    std::vector<std::byte> storage(sizeof(USB_NODE_CONNECTION_DRIVERKEY_NAME) + 65536);
    auto* request = reinterpret_cast<PUSB_NODE_CONNECTION_DRIVERKEY_NAME>(storage.data());
    request->ConnectionIndex = port;
    DWORD returned = 0;
    if (!DeviceIoControl(hub, IOCTL_USB_GET_NODE_CONNECTION_DRIVERKEY_NAME,
        request, static_cast<DWORD>(storage.size()), request,
        static_cast<DWORD>(storage.size()), &returned, nullptr)) {
        return {};
    }
    if (request->ActualLength < sizeof(USB_NODE_CONNECTION_DRIVERKEY_NAME) ||
        request->ActualLength > storage.size()) return {};
    const size_t textOffset = FIELD_OFFSET(USB_NODE_CONNECTION_DRIVERKEY_NAME, DriverKeyName);
    const size_t characters = (request->ActualLength - textOffset) / sizeof(wchar_t);
    const auto end = std::find(request->DriverKeyName, request->DriverKeyName + characters, L'\0');
    if (end == request->DriverKeyName + characters) return {};
    return std::wstring(request->DriverKeyName, end);
}

std::wstring ConnectionHubName(HANDLE hub, ULONG port) {
    std::vector<std::byte> storage(sizeof(USB_NODE_CONNECTION_NAME) + 65536);
    auto* request = reinterpret_cast<PUSB_NODE_CONNECTION_NAME>(storage.data());
    request->ConnectionIndex = port;
    DWORD returned = 0;
    if (!DeviceIoControl(hub, IOCTL_USB_GET_NODE_CONNECTION_NAME,
        request, static_cast<DWORD>(storage.size()), request,
        static_cast<DWORD>(storage.size()), &returned, nullptr)) {
        return {};
    }
    if (request->ActualLength < sizeof(USB_NODE_CONNECTION_NAME) ||
        request->ActualLength > storage.size() || request->NodeName[0] == L'\0') return {};
    const size_t textOffset = FIELD_OFFSET(USB_NODE_CONNECTION_NAME, NodeName);
    const size_t characters = (request->ActualLength - textOffset) / sizeof(wchar_t);
    const auto end = std::find(request->NodeName, request->NodeName + characters, L'\0');
    if (end == request->NodeName + characters) return {};
    std::wstring path(request->NodeName, end);
    if (path.rfind(L"\\??\\", 0) == 0) path.replace(0, 4, L"\\\\?\\");
    else if (!path.empty() && path.front() != L'\\') path.insert(0, L"\\\\.\\");
    return path;
}

bool DriverKeyMatchesInstance(const std::wstring& driverKey,
    const std::vector<std::wstring>& driverKeys) {
    auto key = Upper(driverKey);
    std::replace(key.begin(), key.end(), L'/', L'\\');
    const auto classOffset = key.find(L"\\CONTROL\\CLASS\\");
    if (classOffset != std::wstring::npos) key = key.substr(classOffset + 15);
    for (const auto& value : driverKeys) {
        if (key == Upper(value)) return true;
    }
    return false;
}

std::vector<std::wstring> DeviceDriverKeys(const std::vector<std::wstring>& instanceIds) {
    std::vector<std::wstring> result;
    HDEVINFO devices = SetupDiGetClassDevsW(nullptr, nullptr, nullptr,
        DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (devices == INVALID_HANDLE_VALUE) ThrowWin32("usb_target_device_list_failed");
    struct DeviceListCleanup {
        HDEVINFO value;
        ~DeviceListCleanup() { if (value != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(value); }
    } cleanup{devices};
    for (const auto& instanceId : instanceIds) {
        SP_DEVINFO_DATA data{};
        data.cbSize = sizeof(data);
        if (!SetupDiOpenDeviceInfoW(devices, instanceId.c_str(), nullptr, 0, &data)) continue;
        DWORD type = 0, required = 0;
        (void)SetupDiGetDeviceRegistryPropertyW(devices, &data, SPDRP_DRIVER,
            &type, nullptr, 0, &required);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required < sizeof(wchar_t)) continue;
        std::vector<BYTE> buffer(static_cast<size_t>(required) + sizeof(wchar_t), 0);
        if (!SetupDiGetDeviceRegistryPropertyW(devices, &data, SPDRP_DRIVER,
            &type, buffer.data(), required, &required) || type != REG_SZ) continue;
        const auto* value = reinterpret_cast<const wchar_t*>(buffer.data());
        const size_t chars = required / sizeof(wchar_t);
        const auto end = std::find(value, value + chars, L'\0');
        if (end != value + chars && end != value) result.emplace_back(value, end);
    }
    if (result.empty()) throw std::runtime_error("tx10ub_driver_registry_key_unavailable");
    return result;
}

std::array<UCHAR, 32> Sha256File(const std::filesystem::path& path) {
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!file.valid()) ThrowWin32("stock_realtek_driver_open_failed");

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
        nullptr, 0);
    if (status < 0) throw std::runtime_error("sha256_provider_unavailable");
    struct AlgCleanup {
        BCRYPT_ALG_HANDLE value;
        ~AlgCleanup() { if (value) BCryptCloseAlgorithmProvider(value, 0); }
    } algorithmCleanup{algorithm};

    DWORD objectBytes = 0, resultBytes = 0, returned = 0;
    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&objectBytes), sizeof(objectBytes), &returned, 0);
    if (status < 0 || returned != sizeof(objectBytes)) {
        throw std::runtime_error("sha256_object_size_unavailable");
    }
    status = BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&resultBytes), sizeof(resultBytes), &returned, 0);
    if (status < 0 || returned != sizeof(resultBytes) || resultBytes != 32) {
        throw std::runtime_error("sha256_digest_size_invalid");
    }
    std::vector<UCHAR> object(objectBytes);
    BCRYPT_HASH_HANDLE hash = nullptr;
    status = BCryptCreateHash(algorithm, &hash, object.data(), objectBytes, nullptr, 0, 0);
    if (status < 0) throw std::runtime_error("sha256_hash_create_failed");
    struct HashCleanup {
        BCRYPT_HASH_HANDLE value;
        ~HashCleanup() { if (value) BCryptDestroyHash(value); }
    } hashCleanup{hash};

    std::array<UCHAR, 65536> buffer{};
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(file.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) {
            ThrowWin32("stock_realtek_driver_read_failed");
        }
        if (!read) break;
        status = BCryptHashData(hash, buffer.data(), read, 0);
        if (status < 0) throw std::runtime_error("sha256_hash_data_failed");
    }
    std::array<UCHAR, 32> digest{};
    status = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
    if (status < 0) throw std::runtime_error("sha256_hash_finish_failed");
    return digest;
}

std::wstring Hex(ULONG value) {
    std::wostringstream out;
    out << std::hex << std::nouppercase << value;
    return out.str();
}

std::string HexAscii(ULONG value) {
    std::ostringstream out;
    out << std::hex << std::nouppercase << value;
    return out.str();
}

struct UsbMatch {
    UsbCaptureTarget target;
    ULONG port{};
    std::wstring driverKey;
    std::wstring hubPath;
};

void EnumerateUsbHub(const std::wstring& hubPath, const std::wstring& filterPath,
    const std::vector<std::wstring>& driverKeys, USHORT vendorId, USHORT productId,
    std::unordered_set<std::wstring>& visited, std::vector<UsbMatch>& matches, unsigned depth) {
    if (depth > 16) return;
    const auto normalizedPath = Upper(hubPath);
    if (!visited.insert(normalizedPath).second) return;
    Handle hub(CreateFileW(hubPath.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
    if (!hub.valid()) return;
    USB_NODE_INFORMATION node{};
    node.NodeType = UsbHub;
    DWORD returned = 0;
    if (!DeviceIoControl(hub.get(), IOCTL_USB_GET_NODE_INFORMATION,
        &node, sizeof(node), &node, sizeof(node), &returned, nullptr)) return;
    const ULONG ports = node.u.HubInformation.HubDescriptor.bNumberOfPorts;
    for (ULONG port = 1; port <= ports; ++port) {
        std::vector<std::byte> storage(sizeof(USB_NODE_CONNECTION_INFORMATION_EX) +
            32 * sizeof(USB_PIPE_INFO));
        auto* info = reinterpret_cast<PUSB_NODE_CONNECTION_INFORMATION_EX>(storage.data());
        info->ConnectionIndex = port;
        if (!DeviceIoControl(hub.get(), IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX,
            info, static_cast<DWORD>(storage.size()), info,
            static_cast<DWORD>(storage.size()), &returned, nullptr)) continue;
        if (info->ConnectionStatus != DeviceConnected) continue;

        if (info->DeviceDescriptor.idVendor == vendorId &&
            info->DeviceDescriptor.idProduct == productId) {
            const auto driverKey = ConnectionDriverKey(hub.get(), port);
            if (DriverKeyMatchesInstance(driverKey, driverKeys)) {
                UsbMatch found{};
                found.target.filterPath = filterPath;
                found.target.address = info->DeviceAddress;
                found.port = port;
                found.driverKey = driverKey;
                found.hubPath = hubPath;
                matches.push_back(std::move(found));
            }
        }

        const auto childHub = ConnectionHubName(hub.get(), port);
        if (!childHub.empty()) {
            EnumerateUsbHub(childHub, filterPath, driverKeys, vendorId, productId, visited, matches, depth + 1);
        }
    }
}

} // namespace

std::filesystem::path RealtekServiceDriverPath() {
    // Read the image configured for the same function service as the started PnP node.
    std::array<wchar_t, 32768> value{};
    DWORD bytes = sizeof(value);
    const auto error = RegGetValueW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\rtwlanu6", L"ImagePath",
        RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND, nullptr, value.data(), &bytes);
    if (error != ERROR_SUCCESS) ThrowWin32("realtek_service_image_query_failed", error);
    std::wstring path(value.data());
    if (path.size() >= 2 && path.front() == L'"' && path.back() == L'"')
        path = path.substr(1, path.size() - 2);
    std::array<wchar_t, 32768> windows{};
    const UINT count = GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size()));
    if (!count || count >= windows.size()) ThrowWin32("windows_directory_unavailable");
    for (const std::wstring_view prefix : {L"\\SystemRoot\\", L"%SystemRoot%\\", L"%windir%\\"}) {
        if (_wcsnicmp(path.c_str(), prefix.data(), prefix.size()) == 0)
            return std::filesystem::path(windows.data()) / path.substr(prefix.size());
    }
    if (_wcsnicmp(path.c_str(), L"System32\\", 9) == 0)
        return std::filesystem::path(windows.data()) / path;
    if (path.starts_with(L"\\??\\")) path.erase(0, 4);
    if (path.size() > 3 && iswalpha(path[0]) && path[1] == L':' && path[2] == L'\\') return path;
    throw std::runtime_error("unsupported_driver_image");
}

const AdapterProfile* FindProfile(const std::wstring& instanceId) {
    const auto upper = Upper(instanceId);
    for (const auto& profile : kAdapterProfiles)
        if (upper.rfind(profile.instancePrefix, 0) == 0) return &profile;
    return nullptr;
}

const AdapterProfile& ProfileOf(const Adapter& adapter) {
    const auto* profile = FindProfile(adapter.instanceId);
    if (!profile) throw std::runtime_error("adapter_model_unknown");
    return *profile;
}

std::array<UCHAR, 32> FileSha256(const std::filesystem::path& path) {
    return Sha256File(path);
}

bool MatchesStockRealtekDigest(const std::array<UCHAR, 32>& digest) {
    std::ostringstream text;
    text << std::hex << std::uppercase << std::setfill('0');
    for (UCHAR byte : digest) text << std::setw(2) << static_cast<unsigned>(byte);
    return text.str() == kRealtekDriverSha256;
}

// TP-Link's Archer TX20U Nano 5001.19.128.4 image.
bool MatchesSharedRealtekDigest(const std::array<UCHAR, 32>& digest) {
    constexpr std::array<UCHAR, 32> expected{
        0xCF,0xA4,0xF1,0x4A,0xE9,0x0B,0x02,0x8A,0x77,0xB2,0x7F,0x90,0x6C,0x32,0xDB,0x2C,
        0xBC,0x50,0x54,0x99,0x9F,0x7A,0xD8,0x2F,0x90,0xB5,0x5B,0x0A,0x4F,0x26,0x69,0x39};
    return digest == expected;
}

std::optional<DriverImage> ClassifyDriverImage(const std::array<UCHAR, 32>& digest) {
    if (MatchesStockRealtekDigest(digest)) return DriverImage::Stock;
    if (MatchesSharedRealtekDigest(digest)) return DriverImage::Shared;
    // Archer TX20U Nano's built-in CD-ROM driver, 5001.19.128.1.
    constexpr std::array<UCHAR, 32> tx20u1281{
        0x47,0x07,0x5F,0x09,0xF9,0x85,0xEE,0x30,0x28,0xF1,0x26,0x1F,0x4C,0xE4,0x82,0x99,
        0x50,0xFC,0x26,0x1E,0x39,0x12,0xCC,0xC6,0x80,0x34,0x36,0x73,0x04,0x5B,0x7A,0x16};
    if (digest == tx20u1281) return DriverImage::Tx20u1281;
    // TP-Link Japan's Archer TX20U Nano 5001.19.113.2 x64 image.
    constexpr std::array<UCHAR, 32> tx20u1132{
        0x55,0x93,0xCA,0xF4,0x29,0xA4,0x5F,0xEB,0x3A,0x00,0xDE,0x5F,0xEE,0x4D,0x62,0xB6,
        0x01,0x68,0x3C,0xA4,0xFD,0xBD,0xE8,0x02,0xEF,0xB3,0x6B,0x36,0xB6,0x8E,0xF1,0x80};
    if (digest == tx20u1132) return DriverImage::Tx20u1132;
    return std::nullopt;
}

void RequireStockRealtekDriver() {
    if (!MatchesStockRealtekDigest(Sha256File(RealtekServiceDriverPath())))
        throw std::runtime_error("unsupported_driver_image");
}

void RequireApCoexistenceDriver() {
    const auto digest = Sha256File(RealtekServiceDriverPath());
    if (!MatchesStockRealtekDigest(digest) && !MatchesSharedRealtekDigest(digest))
        throw std::runtime_error("unsupported_ap_coexistence_driver_image");
}

static std::vector<Adapter> FindConnectedAdapters(const GUID* expectedGuid = nullptr,
    const AdapterProfile* diagnosticProfile = nullptr) {
    const HRESULT comResult = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool uninitializeCom = SUCCEEDED(comResult);
    if (FAILED(comResult) && comResult != RPC_E_CHANGED_MODE) {
        ThrowHresult("netcfg_com_initialization_failed", comResult);
    }
    struct ComCleanup {
        bool owned;
        ~ComCleanup() { if (owned) CoUninitialize(); }
    } comCleanup{uninitializeCom};

    ComPtr<INetCfg> netCfg;
    HRESULT hr = CoCreateInstance(CLSID_CNetCfg, nullptr, CLSCTX_INPROC_SERVER,
        IID_INetCfg, reinterpret_cast<void**>(netCfg.put()));
    if (FAILED(hr)) ThrowHresult("netcfg_creation_failed", hr);
    hr = netCfg->Initialize(nullptr);
    if (FAILED(hr)) ThrowHresult("netcfg_initialize_failed", hr);
    NetCfgSession session(netCfg.get());
    session.Initialized();

    std::vector<Adapter> candidates;
    std::optional<DriverImage> image;
    {
        ComPtr<INetCfgClass> networkClass;
        hr = netCfg->QueryNetCfgClass(&GUID_DEVCLASS_NET, IID_INetCfgClass,
            reinterpret_cast<void**>(networkClass.put()));
        if (FAILED(hr)) ThrowHresult("netcfg_network_class_query_failed", hr);
        ComPtr<IEnumNetCfgComponent> components;
        hr = networkClass->EnumComponents(components.put());
        if (FAILED(hr)) ThrowHresult("netcfg_component_enumeration_failed", hr);
        for (;;) {
            ComPtr<INetCfgComponent> component;
            ULONG fetched = 0;
            hr = components->Next(1, component.put(), &fetched);
            if (FAILED(hr)) ThrowHresult("netcfg_component_read_failed", hr);
            if (hr == S_FALSE || fetched == 0) break;
            auto instanceId = DeviceIdFromComponent(component.get());
            if ((diagnosticProfile && FindProfile(instanceId) != diagnosticProfile) ||
                !IsStartedRealtekNetworkDevice(instanceId)) continue;
            GUID guid{};
            hr = component->GetInstanceGuid(&guid);
            if (FAILED(hr)) ThrowHresult("netcfg_adapter_guid_unavailable", hr);
            if (expectedGuid && !IsEqualGUID(guid, *expectedGuid)) continue;
            if (!image) {
                image = ClassifyDriverImage(Sha256File(RealtekServiceDriverPath()));
                if (!image) throw std::runtime_error("unsupported_driver_image");
            }
            auto adapter = MakeAdapter(guid, instanceId);
            adapter.driverImage = *image;
            candidates.push_back(std::move(adapter));
        }
    }
    const HRESULT uninitResult = session.Close();
    if (FAILED(uninitResult)) ThrowHresult("netcfg_uninitialize_failed", uninitResult);
    return candidates;
}

Adapter DiscoverAdapter(AdapterModel model) {
    const auto adapters = FindConnectedAdapters(nullptr, &ProfileFor(model));
    if (adapters.empty()) throw std::runtime_error("adapter_not_present");
    if (adapters.size() != 1) throw std::runtime_error("multiple_adapters_present");
    return adapters.front();
}

Adapter DiscoverAdapter() {
    return DiscoverAdapter(AdapterModel::Tx10ubNano);
}

static Adapter SelectTransferAdapter(const std::vector<Adapter>& adapters) {
    if (adapters.empty()) throw std::runtime_error("adapter_not_present");
    return *std::min_element(adapters.begin(), adapters.end(), [](const Adapter& a, const Adapter& b) {
        if (a.mediaDisconnected != b.mediaDisconnected) return a.mediaDisconnected;
        return std::memcmp(&a.guid, &b.guid, sizeof(GUID)) < 0;
    });
}

Adapter DiscoverTransferAdapter() {
    return SelectTransferAdapter(FindConnectedAdapters());
}

Adapter DiscoverAdapterByGuid(const GUID& guid) {
    const auto adapters = FindConnectedAdapters(&guid);
    if (adapters.empty()) throw std::runtime_error("adapter_not_present");
    if (adapters.size() != 1) throw std::runtime_error("multiple_adapters_present");
    return adapters.front();
}

static UsbMatch FindUsbCaptureTarget(const Adapter& adapter) {
    const auto& profile = ProfileOf(adapter);
    const auto ancestorIds = DeviceInstanceAncestors(adapter.instanceId);
    if (ancestorIds.empty()) throw std::runtime_error("adapter_pnp_ancestry_unavailable");
    const auto driverKeys = DeviceDriverKeys(profile.usbDeviceIsNetworkFunction ? std::vector{adapter.instanceId} : ancestorIds);
    std::vector<UsbMatch> matches;
    for (const auto& filterName : EnumerateUsbPcapFilters()) {
        const auto rootHubPath = UsbPcapRootHubPath(filterName);
        if (rootHubPath.empty()) continue;
        const auto filterPath = L"\\\\.\\" + filterName;
        std::unordered_set<std::wstring> visited;
        EnumerateUsbHub(rootHubPath, filterPath, driverKeys,
            profile.usbVendorId, profile.usbProductId, visited, matches, 0);
    }
    if (matches.size() != 1) {
        throw std::runtime_error(matches.empty() ?
            "usb_capture_device_not_found" : "multiple_usb_capture_devices_match_adapter");
    }
    if (matches.front().target.address == 0 || matches.front().target.address > 127) {
        throw std::runtime_error("usb_capture_address_invalid");
    }
    return matches.front();
}

UsbCaptureTarget DiscoverUsbCaptureTarget(const Adapter& adapter) {
    return FindUsbCaptureTarget(adapter).target;
}

void CycleUsbPort(const Adapter& adapter) {
    if (!ProfileOf(adapter).usbCaptureRestartCyclesPort) throw std::runtime_error("usb_cycle_not_supported_for_adapter");
    const auto match = FindUsbCaptureTarget(adapter);
    Handle hub(CreateFileW(match.hubPath.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
    if (!hub.valid()) ThrowWin32("usb_cycle_hub_open_failed");
    if (!DriverKeyMatchesInstance(ConnectionDriverKey(hub.get(), match.port), {match.driverKey}))
        throw std::runtime_error("usb_cycle_target_changed");
    USB_CYCLE_PORT_PARAMS request{match.port, 0};
    DWORD bytes = 0;
    if (!DeviceIoControl(hub.get(), IOCTL_USB_HUB_CYCLE_PORT, &request, sizeof(request),
        &request, sizeof(request), &bytes, nullptr)) ThrowWin32("usb_cycle_port_failed");
    if (bytes >= sizeof(request) && request.StatusReturned != 0)
        throw std::runtime_error("usb_cycle_port_status_" + std::to_string(request.StatusReturned));
}

bool HasUsbPcapFilter(const Adapter& adapter) {
    if (!ProfileOf(adapter).usbDeviceIsNetworkFunction) throw std::runtime_error("usb_filter_check_not_supported_for_adapter");
    auto instance = adapter.instanceId;
    DEVINST node{};
    if (CM_Locate_DevNodeW(&node, instance.data(), CM_LOCATE_DEVNODE_NORMAL) != CR_SUCCESS)
        throw std::runtime_error("usb_filter_devnode_unavailable");
    std::array<wchar_t, 4096> stack{};
    ULONG bytes = static_cast<ULONG>(sizeof(stack));
    DEVPROPTYPE type{};
    const auto result = CM_Get_DevNode_PropertyW(node, &DEVPKEY_Device_Stack, &type,
        reinterpret_cast<PBYTE>(stack.data()), &bytes, 0);
    if (result != CR_SUCCESS || type != DEVPROP_TYPE_STRING_LIST || bytes > sizeof(stack) ||
        bytes % sizeof(wchar_t) != 0) throw std::runtime_error("usb_filter_device_stack_unavailable");
    auto entry = stack.begin();
    const auto end = entry + bytes / sizeof(wchar_t);
    while (entry != end && *entry) {
        const auto next = std::find(entry, end, L'\0');
        if (next == end) throw std::runtime_error("usb_filter_device_stack_invalid");
        const auto name = Upper(std::wstring(entry, next));
        if (name == L"USBPCAP" || name == L"\\DRIVER\\USBPCAP") return true;
        entry = next + 1;
    }
    return false;
}

WifiRadio::WifiRadio(Adapter adapter) : adapter_(std::move(adapter)) {
    DWORD version = 0;
    const DWORD error = WlanOpenHandle(2, nullptr, &version, &client_);
    if (error != ERROR_SUCCESS) ThrowWin32("wlan_open_failed", error);
}

WifiRadio::~WifiRadio() {
    if (client_) WlanCloseHandle(client_, nullptr);
}

DWORD WifiRadio::Query(DWORD opcode, std::vector<std::byte>& data) const {
    DWORD size = 0;
    PVOID value = nullptr;
    const DWORD error = WlanQueryInterface(client_, &adapter_.guid,
        static_cast<WLAN_INTF_OPCODE>(opcode), nullptr, &size, &value, nullptr);
    if (error != ERROR_SUCCESS) {
        if (value) WlanFreeMemory(value);
        return error;
    }
    if (!value || size == 0) {
        if (value) WlanFreeMemory(value);
        return ERROR_INVALID_DATA;
    }
    try {
        data.resize(size);
        std::memcpy(data.data(), value, size);
    }
    catch (...) {
        WlanFreeMemory(value);
        throw;
    }
    WlanFreeMemory(value);
    return ERROR_SUCCESS;
}

WLAN_INTERFACE_STATE WifiRadio::InterfaceState() const {
    std::vector<std::byte> data;
    const DWORD error = Query(wlan_intf_opcode_interface_state, data);
    if (error != ERROR_SUCCESS) ThrowWin32("wlan_interface_state_query_failed", error);
    if (data.size() != sizeof(WLAN_INTERFACE_STATE)) {
        throw std::runtime_error("wlan_interface_state_invalid_length");
    }
    WLAN_INTERFACE_STATE state{};
    std::memcpy(&state, data.data(), sizeof(state));
    return state;
}

bool WifiRadio::AutoconfEnabled() const {
    std::vector<std::byte> data;
    const DWORD error = Query(wlan_intf_opcode_autoconf_enabled, data);
    if (error != ERROR_SUCCESS) ThrowWin32("wlan_autoconf_query_failed", error);
    if (data.size() != sizeof(BOOL)) {
        throw std::runtime_error("wlan_autoconf_invalid_length");
    }
    BOOL enabled = FALSE;
    std::memcpy(&enabled, data.data(), sizeof(enabled));
    return enabled != FALSE;
}

WifiSnapshot WifiRadio::Capture() const {
    WifiSnapshot snapshot{};
    snapshot.autoconfEnabled = AutoconfEnabled();
    snapshot.state = InterfaceState();
    if (snapshot.state == wlan_interface_state_disconnected) return snapshot;
    if (snapshot.state != wlan_interface_state_connected) {
        throw std::runtime_error("target_wifi_interface_is_not_stable");
    }

    std::vector<std::byte> connectionData;
    DWORD error = Query(wlan_intf_opcode_current_connection, connectionData);
    if (error != ERROR_SUCCESS) ThrowWin32("wlan_connection_query_failed", error);
    if (connectionData.size() < sizeof(WLAN_CONNECTION_ATTRIBUTES)) {
        throw std::runtime_error("wlan_connection_invalid_length");
    }
    WLAN_CONNECTION_ATTRIBUTES attributes{};
    std::memcpy(&attributes, connectionData.data(), sizeof(attributes));
    // Windows can establish a saved profile automatically. Reconnecting by
    // that profile name works for both manual and automatic connections.
    const bool savedProfileMode = attributes.wlanConnectionMode == wlan_connection_mode_profile ||
        attributes.wlanConnectionMode == wlan_connection_mode_auto;
    if (attributes.isState != wlan_interface_state_connected ||
        !savedProfileMode ||
        attributes.strProfileName[0] == L'\0' ||
        wcsnlen_s(attributes.strProfileName, WLAN_MAX_NAME_LENGTH) == WLAN_MAX_NAME_LENGTH) {
        throw std::runtime_error("target_wifi_connection_cannot_be_restored_by_profile");
    }
    snapshot.profileName = attributes.strProfileName;
    snapshot.ssid = attributes.wlanAssociationAttributes.dot11Ssid;
    if (snapshot.ssid.uSSIDLength > DOT11_SSID_MAX_LENGTH)
        throw std::runtime_error("saved_wifi_ssid_invalid_length");
    std::copy_n(attributes.wlanAssociationAttributes.dot11Bssid,
        snapshot.bssid.size(), snapshot.bssid.begin());

    std::vector<std::byte> channelData;
    error = Query(wlan_intf_opcode_channel_number, channelData);
    if (error != ERROR_SUCCESS) ThrowWin32("wlan_channel_query_failed", error);
    if (channelData.size() != sizeof(ULONG)) {
        throw std::runtime_error("wlan_channel_invalid_length");
    }
    std::memcpy(&snapshot.channel, channelData.data(), sizeof(snapshot.channel));
    return snapshot;
}

void WifiRadio::SetAutoconf(bool enabled) const {
    const BOOL value = enabled ? TRUE : FALSE;
    const DWORD error = WlanSetInterface(client_, &adapter_.guid,
        wlan_intf_opcode_autoconf_enabled, sizeof(value), const_cast<BOOL*>(&value), nullptr);
    if (error != ERROR_SUCCESS) ThrowWin32("wlan_autoconf_set_failed", error);
}

void WifiRadio::Disconnect() const {
    const auto state = InterfaceState();
    if (state == wlan_interface_state_disconnected) return;
    if (state != wlan_interface_state_connected) {
        throw std::runtime_error("target_wifi_interface_state_changed_before_disconnect");
    }
    const DWORD error = WlanDisconnect(client_, &adapter_.guid, nullptr);
    if (error != ERROR_SUCCESS) ThrowWin32("wlan_disconnect_failed", error);
    const ULONGLONG deadline = GetTickCount64() + 15000;
    while (GetTickCount64() < deadline) {
        if (InterfaceState() == wlan_interface_state_disconnected) return;
        Sleep(100);
    }
    throw std::runtime_error("wlan_disconnect_timeout");
}

void WifiRadio::Connect(const WifiSnapshot& snapshot, DWORD timeoutMs) const {
    if (snapshot.state != wlan_interface_state_connected) return;
    if (snapshot.profileName.empty() || snapshot.channel == 0) {
        throw std::runtime_error("saved_wifi_connection_is_incomplete");
    }
    WLAN_CONNECTION_PARAMETERS parameters{};
    parameters.wlanConnectionMode = wlan_connection_mode_profile;
    parameters.strProfile = snapshot.profileName.c_str();
    auto ssid = snapshot.ssid;
    if (ssid.uSSIDLength > DOT11_SSID_MAX_LENGTH) throw std::runtime_error("saved_wifi_ssid_invalid_length");
    parameters.pDot11Ssid = ssid.uSSIDLength ? &ssid : nullptr;
    DOT11_BSSID_LIST legacyBssid{};
    if (!parameters.pDot11Ssid) {
        legacyBssid.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
        legacyBssid.Header.Revision = DOT11_BSSID_LIST_REVISION_1;
        legacyBssid.Header.Size = sizeof(legacyBssid);
        legacyBssid.uNumOfEntries = legacyBssid.uTotalNumOfEntries = 1;
        std::copy(snapshot.bssid.begin(), snapshot.bssid.end(), legacyBssid.BSSIDs[0]);
        parameters.pDesiredBssidList = &legacyBssid;
    }
    parameters.dot11BssType = dot11_BSS_type_infrastructure;

    const auto connectedToSavedNetwork = [&] {
        std::vector<std::byte> currentData;
        const DWORD queryError = Query(wlan_intf_opcode_current_connection, currentData);
        if (queryError == ERROR_SUCCESS && currentData.size() >= sizeof(WLAN_CONNECTION_ATTRIBUTES)) {
            WLAN_CONNECTION_ATTRIBUTES current{};
            std::memcpy(&current, currentData.data(), sizeof(current));
            return current.isState == wlan_interface_state_connected &&
                (current.wlanConnectionMode == wlan_connection_mode_profile ||
                 current.wlanConnectionMode == wlan_connection_mode_auto) &&
                wcsnlen_s(current.strProfileName, WLAN_MAX_NAME_LENGTH) < WLAN_MAX_NAME_LENGTH &&
                IsSavedWifiNetwork(snapshot, current.strProfileName, current.wlanAssociationAttributes.dot11Ssid,
                    current.wlanAssociationAttributes.dot11Bssid);
        }
        return false;
    };
    if (InterfaceState() == wlan_interface_state_connected) {
        if (connectedToSavedNetwork()) return;
        Disconnect();
    }

    struct ConnectionWatch {
        struct Context {
            GUID guid{};
            std::wstring profile;
            DOT11_SSID ssid{};
            std::atomic<bool> armed{};
            std::atomic<bool> failed{};
        };
        std::unique_ptr<Context> context = std::make_unique<Context>();
        HANDLE client{};
        static void WINAPI Notify(PWLAN_NOTIFICATION_DATA event, PVOID opaque) {
            auto& target = *static_cast<Context*>(opaque);
            if (!target.armed.load(std::memory_order_acquire) || !event ||
                event->NotificationSource != WLAN_NOTIFICATION_SOURCE_ACM ||
                event->NotificationCode != wlan_notification_acm_connection_complete ||
                !IsEqualGUID(event->InterfaceGuid, target.guid) || !event->pData ||
                event->dwDataSize < offsetof(WLAN_CONNECTION_NOTIFICATION_DATA, strProfileXml)) return;
            const auto& data = *static_cast<const WLAN_CONNECTION_NOTIFICATION_DATA*>(event->pData);
            if (data.wlanConnectionMode != wlan_connection_mode_profile ||
                wcsnlen_s(data.strProfileName, WLAN_MAX_NAME_LENGTH) == WLAN_MAX_NAME_LENGTH ||
                target.profile != data.strProfileName || data.wlanReasonCode == WLAN_REASON_CODE_SUCCESS ||
                data.dot11Ssid.uSSIDLength > DOT11_SSID_MAX_LENGTH) return;
            if (target.ssid.uSSIDLength && (target.ssid.uSSIDLength != data.dot11Ssid.uSSIDLength ||
                !std::equal(target.ssid.ucSSID, target.ssid.ucSSID + target.ssid.uSSIDLength,
                    data.dot11Ssid.ucSSID))) return;
            target.failed.store(true, std::memory_order_relaxed);
        }
        DWORD Close() noexcept {
            if (!client) return ERROR_SUCCESS;
            const auto handle = client; client = nullptr;
            const auto status = WlanCloseHandle(handle, nullptr);
            // Close waits for callbacks. If it fails, retain their heap context.
            if (status != ERROR_SUCCESS) (void)context.release();
            return status;
        }
        ~ConnectionWatch() { (void)Close(); }
    } watch;
    watch.context->guid = adapter_.guid;
    watch.context->profile = snapshot.profileName;
    watch.context->ssid = snapshot.ssid;
    DWORD version{};
    HANDLE observerClient{};
    DWORD status = WlanOpenHandle(2, nullptr, &version, &observerClient);
    bool notificationReady = false;
    DWORD observerCloseFailure = ERROR_SUCCESS;
    if (status == ERROR_SUCCESS) {
        watch.client = observerClient;
        status = WlanRegisterNotification(watch.client, WLAN_NOTIFICATION_SOURCE_ACM, FALSE,
            ConnectionWatch::Notify, watch.context.get(), nullptr, nullptr);
        notificationReady = status == ERROR_SUCCESS;
        if (!notificationReady) observerCloseFailure = watch.Close();
    }

    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    const auto requestConnection = [&] {
        for (;;) {
            if (notificationReady) {
                watch.context->failed.store(false, std::memory_order_relaxed);
                watch.context->armed.store(true, std::memory_order_release);
            }
            const DWORD error = WlanConnect(client_, &adapter_.guid, &parameters, nullptr);
            if (error == ERROR_SUCCESS) break;
            if (notificationReady) watch.context->armed.store(false, std::memory_order_release);
            // A rejected request has not started a connection. Re-enabling
            // autoconfiguration can briefly expose this state after restart.
            if (error != ERROR_INVALID_STATE || !AutoconfEnabled() || GetTickCount64() >= deadline)
                ThrowWin32("wlan_saved_profile_connect_failed", error);
            Sleep(100);
        }
    };
    bool restored = false, retried = false, connectionProgressed = false;
    std::exception_ptr primary;
    try {
        requestConnection();
        while (GetTickCount64() < deadline) {
            const auto state = InterfaceState();
            if (state == wlan_interface_state_associating || state == wlan_interface_state_discovering ||
                state == wlan_interface_state_authenticating) connectionProgressed = true;
            if (state == wlan_interface_state_disconnected && !retried &&
                (notificationReady ? watch.context->failed.load(std::memory_order_relaxed) : connectionProgressed)) {
                // Country discovery can cancel a queued SYS scan before it finds
                // the saved AP. Retry the same target once, after the attempt has
                // returned to disconnected, within the original timeout budget.
                retried = true;
                connectionProgressed = false;
                requestConnection();
            }
            if (state == wlan_interface_state_connected && connectedToSavedNetwork()) {
                restored = true;
                break;
            }
            Sleep(200);
        }
    } catch (...) { primary = std::current_exception(); }
    const auto closed = watch.Close();
    const auto closeStatus = closed != ERROR_SUCCESS ? closed : observerCloseFailure;
    if (closeStatus != ERROR_SUCCESS) {
        if (primary) {
            try { std::rethrow_exception(primary); }
            catch (const std::exception& error) { throw std::runtime_error(std::string(error.what()) +
                "; wlan_connect_observer_close=" + std::to_string(closeStatus)); }
        }
        ThrowWin32("wlan_connect_observer_close_failed", closeStatus);
    }
    if (primary) std::rethrow_exception(primary);
    if (restored) return;
    throw std::runtime_error("wlan_saved_profile_restore_timeout");
}

struct VendorTransport::Pending {
    OVERLAPPED overlapped{};
    HANDLE event{};
    std::vector<std::byte> input;
    std::vector<std::byte> output;

    ~Pending() { if (event) CloseHandle(event); }
    Pending() = default;
    Pending(const Pending&) = delete;
    Pending& operator=(const Pending&) = delete;
};

VendorTransport::VendorTransport(Adapter adapter) : adapter_(std::move(adapter)) {}

VendorTransport::~VendorTransport() {
    try { Close(); } catch (...) { }
}

void VendorTransport::Open(DriverImage image) {
    OpenDevice(true, image);
}

std::string VendorTransport::ReadScanHistory(Adapter adapter, bool& undrained) {
    undrained = false;
    VendorTransport query(std::move(adapter));
    std::string result;
    std::exception_ptr primary;
    try {
        query.OpenDevice(false);
        result = query.Command({"echo", "core", "scan_info"});
    } catch (...) { primary = std::current_exception(); }
    try { query.Close(); }
    catch (const std::exception& error) {
        undrained = query.undrained();
        if (primary) {
            try { std::rethrow_exception(primary); }
            catch (const std::exception& first) {
                throw std::runtime_error(std::string("scan_history_failed; primary=") +
                    first.what() + "; close=" + error.what());
            }
        }
        throw;
    }
    undrained = query.undrained();
    if (primary) std::rethrow_exception(primary);
    return result;
}

void VendorTransport::OpenDevice(bool requireDisconnected, DriverImage image) {
    if (device_ != INVALID_HANDLE_VALUE) throw std::runtime_error("vendor_transport_already_open");
    mutex_ = CreateMutexW(nullptr, FALSE, L"Local\\AWDLWin-TX10UB-UnassociatedRx");
    if (!mutex_) ThrowWin32("vendor_mutex_create_failed");
    const DWORD acquired = WaitForSingleObject(mutex_, 0);
    if (acquired == WAIT_ABANDONED) ownsMutex_ = true;
    else if (acquired == WAIT_OBJECT_0) ownsMutex_ = true;
    else {
        CloseHandle(mutex_);
        mutex_ = nullptr;
        throw std::runtime_error("another_unassociated_trial_is_running");
    }

    const auto current = DiscoverAdapterByGuid(adapter_.guid);
    if (current.instanceId != adapter_.instanceId || current.driverImage != image)
        throw std::runtime_error("unsupported_driver_image");

    WifiRadio radio(adapter_);
    const auto state = radio.InterfaceState();
    if (state != wlan_interface_state_disconnected &&
        (requireDisconnected || state != wlan_interface_state_connected)) {
        throw std::runtime_error("target_must_already_be_disconnected; no_automatic_disconnect");
    }

    std::array<wchar_t, 39> guidText{};
    if (!StringFromGUID2(adapter_.guid, guidText.data(), static_cast<int>(guidText.size()))) {
        throw std::runtime_error("target_guid_format_failed");
    }
    const std::wstring devicePath = L"\\\\.\\Realtek_Wifi_Device" + std::wstring(guidText.data());
    device_ = CreateFileW(devicePath.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (device_ == INVALID_HANDLE_VALUE) ThrowWin32("vendor_device_open_failed");

    std::array<std::byte, 32> input{};
    const auto identity = Finish(*Issue(kVendorDriverIdentityIoctl,
        input.data(), static_cast<DWORD>(input.size()), 32));
    if (identity.size() != 32 ||
        std::memcmp(identity.data() + 16, &adapter_.guid, sizeof(adapter_.guid)) != 0) {
        throw std::runtime_error("vendor_device_identity_mismatch");
    }
}

void VendorTransport::Close() {
    if (requests_.empty()) {
        if (device_ != INVALID_HANDLE_VALUE) {
            CloseHandle(device_);
            device_ = INVALID_HANDLE_VALUE;
        }
        if (ownsMutex_ && mutex_) ReleaseMutex(mutex_);
        ownsMutex_ = false;
        if (mutex_) CloseHandle(mutex_);
        mutex_ = nullptr;
        return;
    }

    while (!requests_.empty()) {
        auto* request = requests_.front().get();
        try { Cancel(*request); }
        catch (...) {
            poisoned_ = true;
            const auto stillOwned = std::find_if(requests_.begin(), requests_.end(),
                [request](const auto& entry) { return entry.get() == request; });
            if (stillOwned != requests_.end()) break;
        }
    }
    if (!requests_.empty()) {
        // Keep OVERLAPPED buffers and their device/mutex handles alive until
        // process exit if the kernel has not confirmed cancellation.
        for (auto& request : requests_) (void)request.release();
        requests_.clear();
        device_ = INVALID_HANDLE_VALUE;
        mutex_ = nullptr;
        ownsMutex_ = false;
        undrained_ = true;
        throw std::runtime_error("vendor_transport_undrained; process_exit_required");
    }
    if (device_ != INVALID_HANDLE_VALUE) {
        CloseHandle(device_);
        device_ = INVALID_HANDLE_VALUE;
    }
    if (ownsMutex_ && mutex_) ReleaseMutex(mutex_);
    ownsMutex_ = false;
    if (mutex_) CloseHandle(mutex_);
    mutex_ = nullptr;
}

VendorTransport::Pending* VendorTransport::Issue(DWORD code, const void* input,
    DWORD inputBytes, DWORD outputBytes) {
    if (poisoned_) throw std::runtime_error("vendor_transport_undrained_no_further_commands");
    if (device_ == INVALID_HANDLE_VALUE) throw std::runtime_error("vendor_transport_not_open");
    auto request = std::make_unique<Pending>();
    request->event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!request->event) ThrowWin32("vendor_event_create_failed");
    request->overlapped.hEvent = request->event;
    if (inputBytes) {
        request->input.resize(inputBytes);
        std::memcpy(request->input.data(), input, inputBytes);
    }
    request->output.resize(outputBytes);
    auto* result = request.get();
    requests_.push_back(std::move(request));
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(device_, code,
        inputBytes ? result->input.data() : nullptr, inputBytes,
        outputBytes ? result->output.data() : nullptr, outputBytes,
        &returned, &result->overlapped);
    if (!ok && GetLastError() != ERROR_IO_PENDING) {
        const DWORD error = GetLastError();
        requests_.erase(std::remove_if(requests_.begin(), requests_.end(),
            [result](const auto& entry) { return entry.get() == result; }), requests_.end());
        ThrowWin32("vendor_device_io_failed", error);
    }
    return result;
}

std::vector<std::byte> VendorTransport::Finish(Pending& request) {
    const DWORD waited = WaitForSingleObject(request.event, 1000);
    const bool timedOut = waited == WAIT_TIMEOUT;
    if (waited == WAIT_FAILED) {
        const DWORD error = GetLastError();
        poisoned_ = true;
        try { Cancel(request); } catch (...) {}
        ThrowWin32("vendor_completion_wait_failed", error);
    }
    if (timedOut) {
        poisoned_ = true;
        (void)CancelIoEx(device_, &request.overlapped);
        const DWORD drained = WaitForSingleObject(request.event, 1000);
        if (drained != WAIT_OBJECT_0) {
            throw std::runtime_error("vendor_timeout_cancel_undrained");
        }
    } else if (waited != WAIT_OBJECT_0) {
        poisoned_ = true;
        throw std::runtime_error("vendor_completion_wait_invalid");
    }

    DWORD returned = 0;
    const size_t outputCapacity = request.output.size();
    const BOOL ok = GetOverlappedResult(device_, &request.overlapped, &returned, FALSE);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok && error == ERROR_IO_INCOMPLETE) {
        poisoned_ = true;
        throw std::runtime_error("vendor_completion_not_terminal");
    }
    if (ok && returned > outputCapacity) {
        poisoned_ = true;
        throw std::runtime_error("vendor_response_oversized");
    }
    std::vector<std::byte> output;
    if (ok) {
        output.assign(request.output.begin(), request.output.begin() + returned);
    }
    const auto* record = &request;
    requests_.erase(std::remove_if(requests_.begin(), requests_.end(),
        [record](const auto& entry) { return entry.get() == record; }), requests_.end());
    if (timedOut) throw std::runtime_error("vendor_command_timeout");
    if (!ok) ThrowWin32("vendor_completion_failed", error);
    return output;
}

void VendorTransport::Cancel(Pending& request) {
    if (device_ == INVALID_HANDLE_VALUE) {
        poisoned_ = true;
        throw std::runtime_error("vendor_cancel_device_unavailable");
    }
    if (!CancelIoEx(device_, &request.overlapped)) {
        const DWORD error = GetLastError();
        if (error != ERROR_NOT_FOUND) ThrowWin32("vendor_cancel_failed", error);
    }
    if (WaitForSingleObject(request.event, 1000) != WAIT_OBJECT_0) {
        poisoned_ = true;
        throw std::runtime_error("vendor_cancel_undrained");
    }
    DWORD returned = 0;
    const BOOL ok = GetOverlappedResult(device_, &request.overlapped, &returned, FALSE);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok && error == ERROR_IO_INCOMPLETE) {
        poisoned_ = true;
        throw std::runtime_error("vendor_cancel_completion_not_terminal");
    }
    if (!ok && error != ERROR_OPERATION_ABORTED) ThrowWin32("vendor_cancel_completion_failed", error);
    const auto* record = &request;
    requests_.erase(std::remove_if(requests_.begin(), requests_.end(),
        [record](const auto& entry) { return entry.get() == record; }), requests_.end());
}

std::string VendorTransport::Command(const std::vector<std::string>& tokens) {
    if (tokens.size() > 20) throw std::runtime_error("invalid_fixed_vendor_tokens");
    for (const auto& token : tokens) {
        if (token.size() >= 16 || !std::all_of(token.begin(), token.end(),
            [](unsigned char value) { return value < 0x80; })) {
            throw std::runtime_error("invalid_fixed_vendor_tokens");
        }
    }
    ++job_;
    Pending* read = Issue(kVendorReadJobIoctl, &job_, sizeof(job_), 65536);
    try {
        std::array<std::byte, 346> packet{};
        std::memcpy(packet.data(), &job_, sizeof(job_));
        const USHORT command = 1, flags = 0, length = 336;
        std::memcpy(packet.data() + 4, &command, sizeof(command));
        std::memcpy(packet.data() + 6, &flags, sizeof(flags));
        std::memcpy(packet.data() + 8, &length, sizeof(length));
        const ULONG count = static_cast<ULONG>(tokens.size());
        std::memcpy(packet.data() + 22, &count, sizeof(count));
        for (size_t i = 0; i < tokens.size(); ++i) {
            std::memcpy(packet.data() + 26 + i * 16, tokens[i].data(), tokens[i].size());
        }
        Pending* execute = Issue(kVendorExecuteIoctl,
            packet.data(), static_cast<DWORD>(packet.size()), 64);
        (void)Finish(*execute);
        auto result = Finish(*read);
        const auto end = std::find(result.begin(), result.end(), std::byte{0});
        return std::string(reinterpret_cast<const char*>(result.data()),
            static_cast<size_t>(end - result.begin()));
    }
    catch (...) {
        const auto found = std::find_if(requests_.begin(), requests_.end(),
            [read](const auto& entry) { return entry.get() == read; });
        if (found != requests_.end()) {
            try { Cancel(**found); } catch (...) { poisoned_ = true; }
        }
        throw;
    }
}

ULONG VendorTransport::ReadRegister(ULONG address) {
    const auto response = Command({"echo", "bb", "cr", "r", "dw", HexAscii(address)});
    std::ostringstream patternText;
    patternText << R"(\[R\]\s+Reg0x)" << std::hex << std::nouppercase << address
        << R"(\[31:0{1,2}\]\s*=\s*0x([0-9a-f]+))";
    const std::regex pattern(patternText.str(), std::regex_constants::icase);
    std::sregex_iterator item(response.begin(), response.end(), pattern), end;
    if (item == end) throw std::runtime_error("bb_readback_invalid_" + std::to_string(address));
    const std::string valueText = (*item)[1].str();
    if (++item != end) throw std::runtime_error("bb_readback_duplicate_" + std::to_string(address));
    ULONG value = 0;
    const auto parsed = std::from_chars(valueText.data(), valueText.data() + valueText.size(), value, 16);
    if (parsed.ec != std::errc{} || parsed.ptr != valueText.data() + valueText.size() ||
        value == std::numeric_limits<ULONG>::max()) {
        throw std::runtime_error("bb_readback_unavailable_" + std::to_string(address));
    }
    return value;
}

BbState VendorTransport::ReadBb() {
    const ULONG channel = ReadRegister(0x734);
    const ULONG bandwidth = ReadRegister(0x49c0);
    const ULONG primary = ReadRegister(0x49c4);
    const ULONG band = ReadRegister(0x4738);
    return BbState{(channel >> 16) & 0xff, bandwidth >> 30,
        (primary >> 8) & 0x0f, (primary >> 12) & 0x03, (band >> 17) & 1};
}

Channel VendorTransport::ChannelFromBb(const BbState& state) const {
    const ULONG sequence = state.encoded >> 4;
    const ULONG delta = state.encoded & 15;
    ULONG band = 0, center = 0;
    if (sequence == 0 && delta >= 1 && delta <= 14) {
        band = 0;
        center = delta;
    } else {
        const std::array<std::pair<ULONG, ULONG>, 4> bases{{
            {2, 36}, {3, 100}, {4, 132}, {5, 149}
        }};
        const auto found = std::find_if(bases.begin(), bases.end(),
            [sequence](const auto& entry) { return entry.first == sequence; });
        if (found == bases.end()) throw std::runtime_error("unsupported_original_channel_index");
        band = 1;
        center = found->second + delta * 2;
    }
    if (state.is24Ghz != static_cast<ULONG>(band == 0) || state.smallBand != 0 || state.width > 2) {
        throw std::runtime_error("unsupported_original_bandwidth_or_band");
    }
    ULONG primary = 0, offset = 0;
    if (state.width == 0) {
        if (state.primaryIndex != 0) throw std::runtime_error("invalid_original_primary_index");
        primary = center;
    } else {
        const ULONG maxIndex = state.width == 1 ? 2 : 4;
        if (state.primaryIndex < 1 || state.primaryIndex > maxIndex) {
            throw std::runtime_error("invalid_original_primary_index");
        }
        const LONG adjustment = (state.primaryIndex & 1)
            ? static_cast<LONG>(state.primaryIndex) : 1 - static_cast<LONG>(state.primaryIndex);
        primary = static_cast<ULONG>(static_cast<LONG>(center) + adjustment * 2);
        if (state.width == 1) {
            offset = state.primaryIndex == 1 ? 3 : 1;
            const std::array<ULONG, 14> validCenters{
                38,46,54,62,102,110,118,126,134,142,151,159,167,175
            };
            const bool validCenter = std::find(validCenters.begin(), validCenters.end(), center) != validCenters.end();
            if ((band == 0 && (center < 3 || center > 11)) || (band == 1 && !validCenter)) {
                throw std::runtime_error("invalid_original_40mhz_center");
            }
        } else {
            const std::array<ULONG, 7> validCenters{42,58,106,122,138,155,171};
            if (band != 1 || std::find(validCenters.begin(), validCenters.end(), center) == validCenters.end()) {
                throw std::runtime_error("invalid_original_80mhz_center");
            }
            offset = (((primary - (center - 6)) / 4) % 2) == 0 ? 1 : 3;
        }
    }
    const bool valid24 = band == 0 && primary >= 1 && primary <= 14;
    const bool valid5 = band == 1 &&
        ((primary >= 36 && primary <= 64 && ((primary - 36) % 4) == 0) ||
         (primary >= 100 && primary <= 144 && ((primary - 100) % 4) == 0) ||
         (primary >= 149 && primary <= 177 && ((primary - 149) % 4) == 0));
    if (!valid24 && !valid5) throw std::runtime_error("invalid_original_primary_channel");
    return Channel{band, primary, state.width, offset};
}

void VendorTransport::SetChannel(const Channel& channel) {
    (void)Command({"echo", "phl", "set_ch", "0", HexAscii(channel.band), HexAscii(channel.primary),
        HexAscii(channel.width), HexAscii(channel.offset)});
}

void VendorTransport::SetMonitorMode(bool enabled) {
    (void)Command({"echo", "core", "mon_mode", "0", enabled ? "1" : "0"});
}

static ULONG ReadRxRegister(const std::filesystem::path& probePath,const wchar_t* command,const char* label) {
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    HANDLE rawRead = nullptr, rawWrite = nullptr;
    if (!CreatePipe(&rawRead, &rawWrite, &security, 0)) {
        throw RxReadbackError("rx_readback_pipe_create_failed_" + std::to_string(GetLastError()), false);
    }
    Handle read(rawRead), write(rawWrite);
    if (!SetHandleInformation(read.get(), HANDLE_FLAG_INHERIT, 0)) {
        throw RxReadbackError("rx_readback_pipe_inherit_clear_failed_" + std::to_string(GetLastError()), false);
    }

    std::wstring commandLine = L"\"" + probePath.wstring() + L"\" " + command;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = write.get();
    startup.hStdError = write.get();
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(probePath.c_str(), commandLine.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, probePath.parent_path().c_str(), &startup, &process)) {
        throw RxReadbackError("rx_readback_probe_start_failed_" + std::to_string(GetLastError()), false);
    }
    Handle processHandle(process.hProcess), threadHandle(process.hThread);
    write.reset();
    std::string output;
    std::array<char, 4096> buffer{};
    constexpr size_t kOutputLimit = 1024 * 1024;
    bool outputExceeded = false;
    bool timedOut = false;
    const ULONGLONG deadline = GetTickCount64() + 15000;
    std::string captureError;
    auto drain = [&]() {
        for (;;) {
            DWORD available = 0;
            if (!PeekNamedPipe(read.get(), nullptr, 0, nullptr, &available, nullptr)) {
                const DWORD error = GetLastError();
                if (error == ERROR_BROKEN_PIPE) return;
                if (captureError.empty()) captureError = "rx_readback_pipe_query_failed_" + std::to_string(error);
                return;
            }
            if (!available) return;
            DWORD count = 0;
            const DWORD requested = std::min<DWORD>(available, static_cast<DWORD>(buffer.size()));
            if (!ReadFile(read.get(), buffer.data(), requested, &count, nullptr)) {
                const DWORD error = GetLastError();
                if (error == ERROR_BROKEN_PIPE) return;
                if (captureError.empty()) captureError = "rx_readback_pipe_read_failed_" + std::to_string(error);
                return;
            }
            const size_t remaining = kOutputLimit - std::min(kOutputLimit, output.size());
            const size_t keep = std::min<size_t>(remaining, count);
            output.append(buffer.data(), keep);
            if (keep != count) outputExceeded = true;
        }
    };
    for (;;) {
        drain();
        const DWORD state = WaitForSingleObject(processHandle.get(), 50);
        if (state == WAIT_OBJECT_0) break;
        if (state == WAIT_FAILED) {
            const DWORD error = GetLastError();
            DWORD currentExit = STILL_ACTIVE;
            if (GetExitCodeProcess(processHandle.get(), &currentExit) && currentExit != STILL_ACTIVE) break;
            if (captureError.empty()) captureError = "rx_readback_probe_wait_unconfirmed_" + std::to_string(error);
            Sleep(50);
        }
        if (GetTickCount64() >= deadline) timedOut = true;
    }
    // The final write can race the previous PeekNamedPipe call. Drain only
    // after the owned read-only process has reached a terminal state.
    drain();
    if (!captureError.empty()) throw RxReadbackError(captureError, true);
    if (timedOut) throw RxReadbackError("rx_readback_probe_timeout_completion_unconfirmed", true);
    if (outputExceeded) throw RxReadbackError("rx_readback_probe_output_limit_exceeded", true);
    DWORD exitCode = 0;
    if (!GetExitCodeProcess(processHandle.get(), &exitCode)) {
        throw RxReadbackError("rx_readback_probe_exit_query_failed_" + std::to_string(GetLastError()), true);
    }
    const bool lowerCompletionUnconfirmed =
        output.find("classification=6") != std::string::npos ||
        output.find("completion_mode=4") != std::string::npos;
    if (lowerCompletionUnconfirmed) {
        throw RxReadbackError("mac_rx_readback_completion_unconfirmed", true);
    }
    if (exitCode != 0) {
        throw RxReadbackError("mac_rx_readback_failed", true);
    }
    const std::regex pattern(std::string(R"((?:^|\r?\n))")+label+R"(=0x([0-9a-fA-F]{8})(?=\r?\n|$))");
    auto match=std::sregex_iterator(output.begin(),output.end(),pattern);
    const auto end=std::sregex_iterator();
    if (match==end) {
        throw RxReadbackError("mac_rx_readback_labels_missing", true);
    }
    const auto value=(*match)[1].str();
    if(++match!=end)throw RxReadbackError("mac_rx_readback_labels_ambiguous",true);
    const auto parse = [](const std::string& text) {
        ULONG result = 0;
        const auto converted = std::from_chars(text.data(), text.data() + text.size(), result, 16);
        if (converted.ec != std::errc{} || converted.ptr != text.data() + text.size() ||
            result == std::numeric_limits<ULONG>::max()) {
            throw RxReadbackError("mac_rx_readback_invalid", true);
        }
        return result;
    };
    return parse(value);
}

std::pair<ULONG,ULONG> ReadRxSettings(const std::filesystem::path& probePath) {
    const ULONG filter=ReadRxRegister(probePath,L"rx-filter-readback","rx_filter_ce20");
    const ULONG data=ReadRxRegister(probePath,L"rx-data-filter-readback","rx_data_filter_ce2c");
    if (filter == 0 && data == 0) throw RxReadbackError("mac_rx_readback_unavailable", true);
    return {filter, data};
}

} // namespace tx10ub::host
