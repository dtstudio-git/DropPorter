#include "Tx10ubNetworkRestart.h"

#include "Tx10ubDirectIhv.h"

#include <cfgmgr32.h>
#include <setupapi.h>
#include <winsvc.h>

#include <array>
#include <exception>
#include <sstream>
#include <system_error>
#include <vector>

namespace tx10ub::host {
namespace {

constexpr wchar_t kAuxiliaryServiceName[] = L"AWDLWinTx10ubProbe";

class Service final {
public:
    explicit Service(SC_HANDLE value = nullptr) noexcept : value_(value) {}
    ~Service() noexcept
    {
        if (value_ != nullptr) CloseServiceHandle(value_);
    }
    Service(const Service&) = delete;
    Service& operator=(const Service&) = delete;
    SC_HANDLE get() const noexcept { return value_; }

private:
    SC_HANDLE value_{};
};

[[noreturn]] void ThrowWin32(const char* operation, DWORD error = GetLastError())
{
    throw std::system_error(static_cast<int>(error), std::system_category(), operation);
}

void Require(bool condition, const char* operation)
{
    if (!condition) ThrowWin32(operation);
}

Adapter RediscoverNetworkFunction(const Adapter& expected)
{
    return DiscoverAdapterByGuid(expected.guid);
}

void RequireSameIdentity(const Adapter& expected, const Adapter& actual)
{
    if (actual.instanceId != expected.instanceId || !IsEqualGUID(actual.guid, expected.guid) ||
        actual.driverImage != expected.driverImage) {
        throw std::runtime_error("target_identity_changed_during_restart");
    }
}

void RequireAuxiliaryStoppedOrAbsent()
{
    Service manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (manager.get() == nullptr) ThrowWin32("auxiliary_manager_open_failed");

    Service service{OpenServiceW(manager.get(), kAuxiliaryServiceName, SERVICE_QUERY_STATUS)};
    if (service.get() == nullptr) {
        const DWORD error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) return;
        ThrowWin32("auxiliary_status_open_failed", error);
    }

    SERVICE_STATUS_PROCESS state{};
    DWORD bytes{};
    Require(QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO,
        reinterpret_cast<BYTE*>(&state), sizeof(state), &bytes) != FALSE,
        "auxiliary_status_read_failed");
    if (bytes != sizeof(state)) throw std::runtime_error("auxiliary_status_invalid_length");
    if (state.dwCurrentState != SERVICE_STOPPED) {
        throw std::runtime_error("auxiliary_must_be_stopped_or_absent_no_state_changed");
    }
}

void ValidateOriginalWifi(const WifiSnapshot& snapshot)
{
    if (snapshot.state != wlan_interface_state_connected &&
        snapshot.state != wlan_interface_state_disconnected) {
        throw std::invalid_argument("original_wifi_snapshot_state_invalid");
    }
    if (snapshot.state == wlan_interface_state_connected &&
        (snapshot.profileName.empty() || snapshot.channel == 0)) {
        throw std::invalid_argument("original_wifi_snapshot_incomplete");
    }
}

DWORD ConfigureScanPolicy(HDEVINFO devices, SP_DEVINFO_DATA& device) noexcept
{
    // The fixed driver can finish country discovery and cancel redundant SYS
    // scans using its own task callbacks. Keep its regulatory scan unchanged.
    try { RequireStockRealtekDriver(); }
    catch (...) { return ERROR_REVISION_MISMATCH; }
    struct Key {
        HKEY value;
        ~Key() { if (value != INVALID_HANDLE_VALUE) RegCloseKey(value); }
    } key{SetupDiOpenDevRegKey(devices, &device, DICS_FLAG_GLOBAL, 0, DIREG_DRV,
        KEY_QUERY_VALUE | KEY_SET_VALUE)};
    if (key.value == INVALID_HANDLE_VALUE) return GetLastError();
    constexpr wchar_t setting[] = L"scan_policy_ww_plus_sys";
    const std::array<BYTE, 4> dwordZero{}, dwordOne{1, 0, 0, 0};
    const std::array<BYTE, 4> stringZero{'0', 0, 0, 0}, stringOne{'1', 0, 0, 0};
    DWORD type{}, size = 4;
    std::array<BYTE, 4> value{};
    const auto queried = RegQueryValueExW(key.value, setting, nullptr, &type, value.data(), &size);
    if (queried == ERROR_SUCCESS) {
        if (size != 4) return ERROR_INVALID_DATA;
        if ((type == REG_DWORD && value == dwordZero) || (type == REG_SZ && value == stringZero))
            return ERROR_SUCCESS;
        if (!((type == REG_DWORD && value == dwordOne) || (type == REG_SZ && value == stringOne)))
            return ERROR_INVALID_DATA;
    } else if (queried == ERROR_FILE_NOT_FOUND) {
        type = REG_SZ;
    } else {
        return queried;
    }
    const auto& zero = type == REG_SZ ? stringZero : dwordZero;
    const auto written = RegSetValueExW(key.value, setting, 0, type, zero.data(), 4);
    if (written != ERROR_SUCCESS) return written;
    DWORD checkedType{}, checkedSize = 4;
    const auto checked = RegQueryValueExW(key.value, setting, nullptr, &checkedType, value.data(), &checkedSize);
    if (checked != ERROR_SUCCESS) return checked;
    return checkedType == type && checkedSize == 4 && value == zero ? ERROR_SUCCESS : ERROR_WRITE_FAULT;
}

DWORD RestartNetworkFunction(const Adapter& adapter, bool& restartIssued, DWORD* scanPolicyStatus = nullptr,
                            bool configureScanPolicy = true)
{
    struct DeviceSet {
        HDEVINFO value;
        ~DeviceSet() { if (value != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(value); }
    } devices{SetupDiCreateDeviceInfoList(nullptr, nullptr)};
    Require(devices.value != INVALID_HANDLE_VALUE, "restart_device_set_failed");
    SP_DEVINFO_DATA device{};
    device.cbSize = sizeof(device);
    Require(SetupDiOpenDeviceInfoW(devices.value, adapter.instanceId.c_str(), nullptr, 0, &device),
        "restart_device_open_failed");
    SP_PROPCHANGE_PARAMS change{};
    change.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
    change.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
    change.StateChange = DICS_PROPCHANGE;
    change.Scope = DICS_FLAG_CONFIGSPECIFIC;
    Require(SetupDiSetClassInstallParamsW(devices.value, &device,
        &change.ClassInstallHeader, sizeof(change)), "restart_device_parameters_failed");
    // A performance-setting failure must not suppress required WPS cleanup.
    if (configureScanPolicy) {
        const DWORD policyStatus = ConfigureScanPolicy(devices.value, device);
        if (scanPolicyStatus) *scanPolicyStatus = policyStatus;
    }
    // A failed class-installer call may already have changed device state.
    // Complete recovery before reporting its failure; never race this request.
    restartIssued = true;
    Require(SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, devices.value, &device),
        "restart_device_failed");
    SP_DEVINSTALL_PARAMS_W installed{};
    installed.cbSize = sizeof(installed);
    Require(SetupDiGetDeviceInstallParamsW(devices.value, &device, &installed),
        "restart_device_result_failed");
    return installed.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART) ? ERROR_SUCCESS_REBOOT_REQUIRED : ERROR_SUCCESS;
}

Adapter WaitForAdapter(const Adapter& expected, bool portCycled)
{
    const ULONGLONG deadline = GetTickCount64() + 45000;
    constexpr ULONGLONG usbStabilityMs = 2000;
    std::string lastFailure;
    ULONGLONG stableSince = 0;
    NET_LUID stableLuid{};
    while (GetTickCount64() < deadline) {
        try {
            auto current = RediscoverNetworkFunction(expected);
            RequireSameIdentity(expected, current);
            WifiRadio radio(current);
            const auto state = radio.InterfaceState();
            if (state == wlan_interface_state_connected || state == wlan_interface_state_disconnected) {
                if (!portCycled) return current;
                if (!HasUsbPcapFilter(current)) throw std::runtime_error("usb_filter_not_reattached");
                (void)radio.AutoconfEnabled();
                const auto now = GetTickCount64();
                // The WLAN binding can disappear again during USB re-enumeration.
                if (!stableSince || stableLuid.Value != current.luid.Value) {
                    stableSince = now;
                    stableLuid = current.luid;
                }
                if (now - stableSince >= usbStabilityMs) return current;
                lastFailure = "wifi_interface_rebinding";
            } else {
                stableSince = 0;
                lastFailure = "wifi_interface_not_ready";
            }
        }
        catch (const std::exception& error) {
            stableSince = 0;
            lastFailure = error.what();
        }
        // Notice the rebound interface promptly; this bounds shutdown latency.
        Sleep(50);
    }
    throw std::runtime_error("restart_adapter_reappearance_timeout_" + lastFailure);
}

void RestoreDisconnectedWifi(WifiRadio& radio, bool watchAutoConnect)
{
    // After a PnP restart WLAN can report disconnected before AutoConfig starts
    // associating. Let that initial attempt settle, then disconnect it.
    constexpr ULONGLONG quietMs = 5000;
    const auto deadline = GetTickCount64() + 20000;
    std::optional<ULONGLONG> disconnectedSince;
    do {
        const auto state = radio.InterfaceState();
        if (state == wlan_interface_state_disconnected) {
            const auto now = GetTickCount64();
            if (!disconnectedSince) disconnectedSince = now;
            if (!watchAutoConnect || now - *disconnectedSince >= quietMs) return;
        } else {
            disconnectedSince.reset();
            if (state == wlan_interface_state_connected) radio.Disconnect();
        }
        Sleep(200);
    } while (GetTickCount64() < deadline);
    throw std::runtime_error("wifi_disconnection_did_not_settle");
}

bool Accepted(const direct_ihv::OperationResult& result)
{
    return result.win32Status == ERROR_SUCCESS &&
        result.responseValidation == direct_ihv::ResponseValidation::Valid &&
        result.acceptance == direct_ihv::RequestAcceptance::Accepted && result.value.has_value();
}

void VerifyDirectControl(const Adapter& adapter)
{
    direct_ihv::DirectIhv direct(adapter);
    if (!Accepted(direct.VendorId()) ||
        !Accepted(direct.ReadMac(direct_ihv::MacRegister::Ce20)) ||
        !Accepted(direct.ReadMac(direct_ihv::MacRegister::Ce2c))) {
        throw std::runtime_error("direct_control_after_restart_failed");
    }
}

std::string ExceptionMessage(const std::exception_ptr& error)
{
    if (!error) return {};
    try {
        std::rethrow_exception(error);
    }
    catch (const std::exception& value) {
        return value.what();
    }
    catch (...) {
        return "unknown_exception";
    }
}

} // namespace

static Adapter RestoreNetworkAndWifi(const Adapter& adapter,
                                    const WifiSnapshot& originalWifi,
                                    bool restart,
                                    NetworkRestartTimings* timings, RestartPurpose purpose = RestartPurpose::DirectIhvSession)
{
    if (timings) *timings = {};
    ValidateOriginalWifi(originalWifi);
    const bool portCycle = purpose == RestartPurpose::UsbCaptureSession && ProfileOf(adapter).usbCaptureRestartCyclesPort;
    auto current = RediscoverNetworkFunction(adapter);
    RequireSameIdentity(adapter, current);
    RequireAuxiliaryStoppedOrAbsent();

    std::exception_ptr primary;
    std::vector<std::string> recoveryFailures;
    bool restartIssued = false;
    const auto restartStarted = GetTickCount64();
    try {
        if (restart && portCycle) {
            // A port cycle may remove the devnode before reporting an error.
            restartIssued = true;
            CycleUsbPort(current);
        } else if (restart) {
            const DWORD exitCode = RestartNetworkFunction(current, restartIssued,
                timings ? &timings->scanPolicyStatus : nullptr,
                purpose != RestartPurpose::PassiveCapture && current.driverImage == DriverImage::Stock);
            if (exitCode != ERROR_SUCCESS) {
                throw std::runtime_error("device_restart_failed_or_reboot_required_" +
                    std::to_string(exitCode));
            }
        }
    }
    catch (...) {
        primary = std::current_exception();
    }
    if (timings) timings->deviceRestartMs = GetTickCount64() - restartStarted;

    if (restart && !restartIssued) {
        if (primary) std::rethrow_exception(primary);
        throw std::runtime_error("device_restart_not_started");
    }

    Adapter recovered{};
    const auto adapterWaitStarted = GetTickCount64();
    bool adapterAvailable = false;
    try {
        recovered = restart ? WaitForAdapter(adapter, portCycle) : current;
        adapterAvailable = true;
    }
    catch (const std::exception& error) {
        recoveryFailures.emplace_back(std::string("adapter_reappearance=") + error.what());
        if (!primary) primary = std::current_exception();
        if (portCycle) {
            try {
                recovered = WaitForAdapter(adapter, false);
                adapterAvailable = true;
            } catch (const std::exception& wifiError) {
                recoveryFailures.emplace_back(std::string("wifi_reappearance=") + wifiError.what());
            }
        }
    }

    if (timings) timings->adapterReadyMs = GetTickCount64() - adapterWaitStarted;
    const auto wifiRestoreStarted = GetTickCount64();

    try {
        RequireAuxiliaryStoppedOrAbsent();
    }
    catch (const std::exception& error) {
        recoveryFailures.emplace_back(std::string("auxiliary_state=") + error.what());
        if (!primary) primary = std::current_exception();
    }

    if (adapterAvailable) {
        try {
            WifiRadio radio(recovered);
            try {
                if (radio.AutoconfEnabled() != originalWifi.autoconfEnabled) {
                    radio.SetAutoconf(originalWifi.autoconfEnabled);
                }
            }
            catch (const std::exception& error) {
                recoveryFailures.emplace_back(std::string("autoconf_restore=") + error.what());
                if (!primary) primary = std::current_exception();
            }

            // Keep connection recovery independent from autoconfiguration recovery.
            try {
                if (originalWifi.state == wlan_interface_state_connected) {
                    radio.Connect(originalWifi);
                }
                else {
                    RestoreDisconnectedWifi(radio, restart && originalWifi.autoconfEnabled);
                }
            }
            catch (const std::exception& error) {
                recoveryFailures.emplace_back(std::string("connection_restore=") + error.what());
                if (!primary) primary = std::current_exception();
            }

            try {
                if (!WifiStateRestored(originalWifi, radio.Capture())) {
                    throw std::runtime_error("wifi_state_after_restart_mismatch");
                }
            }
            catch (const std::exception& error) {
                recoveryFailures.emplace_back(std::string("wifi_verification=") + error.what());
                if (!primary) primary = std::current_exception();
            }
        }
        catch (const std::exception& error) {
            recoveryFailures.emplace_back(std::string("wifi_restore_open=") + error.what());
            if (!primary) primary = std::current_exception();
        }

        try {
            RequireAuxiliaryStoppedOrAbsent();
            if (restart && purpose != RestartPurpose::PassiveCapture) VerifyDirectControl(recovered);
            if (portCycle && !HasUsbPcapFilter(recovered))
                throw std::runtime_error("usb_filter_not_reattached");
        }
        catch (const std::exception& error) {
            recoveryFailures.emplace_back(std::string("direct_control_verification=") + error.what());
            if (!primary) primary = std::current_exception();
        }
    }

    try {
        RequireAuxiliaryStoppedOrAbsent();
    }
    catch (const std::exception& error) {
        recoveryFailures.emplace_back(std::string("auxiliary_final_state=") + error.what());
        if (!primary) primary = std::current_exception();
    }

    if (timings) timings->wifiRestoreMs = GetTickCount64() - wifiRestoreStarted;
    if (primary || !recoveryFailures.empty()) {
        std::ostringstream message;
        message << "network_restart_recovery_failed; primary=" << ExceptionMessage(primary)
            << "; recovery_pending=" << (!recoveryFailures.empty() ? 1 : 0);
        for (const auto& failure : recoveryFailures) message << "; " << failure;
        throw std::runtime_error(message.str());
    }
    return recovered;
}

Adapter RestartNetworkAndRestoreWifi(const Adapter& adapter, const WifiSnapshot& originalWifi,
                                    NetworkRestartTimings* timings, RestartPurpose purpose)
{
    return RestoreNetworkAndWifi(adapter, originalWifi, true, timings, purpose);
}

Adapter RestoreWifiWithoutRestart(const Adapter& adapter, const WifiSnapshot& originalWifi)
{
    return RestoreNetworkAndWifi(adapter, originalWifi, false, nullptr);
}

} // namespace tx10ub::host
