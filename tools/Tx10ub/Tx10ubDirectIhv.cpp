#include "Tx10ubDirectIhv.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <system_error>

namespace tx10ub::direct_ihv {
namespace {

constexpr std::size_t kSerializerCapacity = 2048;
constexpr std::size_t kWdiHeaderAndTlvSize = 20;
constexpr DWORD kKnownWpsClearInvalidLength = 0xC0010014u;
constexpr std::uint32_t kVendorIdOid = 0x0001010Cu;
constexpr std::uint32_t kVendorExtensionSignature = 0xFF4CE000u;
constexpr std::uint32_t kRxRegisterOid = 0xFF0111C2u;

std::uint32_t NextSerializationTransactionId() noexcept
{
    static std::atomic<std::uint32_t> next{1};
    auto value = next.fetch_add(1, std::memory_order_relaxed);
    if (value == 0) value = next.fetch_add(1, std::memory_order_relaxed);
    return value;
}

std::uint32_t RegisterAddress(MacRegister address)
{
    switch (address) {
    case MacRegister::Ce20: return 0xCE20u;
    case MacRegister::Ce2c: return 0xCE2Cu;
    case MacRegister::Ce34: return 0xCE34u;
    case MacRegister::Ce38: return 0xCE38u;
    case MacRegister::ManagementFilter: return 0xCE28u;
    }
    throw std::invalid_argument("unsupported_mac_register");
}

std::array<std::uint8_t, 6> ReadAdapterMac(NET_LUID luid)
{
    MIB_IF_ROW2 row{};
    row.InterfaceLuid = luid;
    const DWORD status = GetIfEntry2Ex(MibIfEntryNormalWithoutStatistics, &row);
    if (status != NO_ERROR) {
        throw std::system_error(static_cast<int>(status), std::system_category(),
                                "adapter_mac_read_failed");
    }
    if (row.PhysicalAddressLength != 6 || (row.PhysicalAddress[0] & 1u) != 0) {
        throw std::runtime_error("adapter_mac_invalid");
    }
    std::array<std::uint8_t, 6> mac{};
    std::copy_n(row.PhysicalAddress, mac.size(), mac.begin());
    if (std::all_of(mac.begin(), mac.end(), [](std::uint8_t byte) { return byte == 0; })) {
        throw std::runtime_error("adapter_mac_invalid");
    }
    return mac;
}

void SetValidated(OperationResult& result, ResponseValidation validation)
{
    result.responseValidation = validation;
    result.acceptance = validation == ResponseValidation::Valid
        ? RequestAcceptance::Accepted
        : RequestAcceptance::Unknown;
}

bool IsOutcomeUncertainTransportFailure(DWORD status) noexcept
{
    return status == ERROR_TIMEOUT ||
           status == RPC_S_SERVER_UNAVAILABLE ||
           status == RPC_S_CALL_FAILED ||
           status == RPC_S_CALL_FAILED_DNE ||
           status == RPC_S_CALL_CANCELLED;
}

} // namespace

std::span<const std::uint8_t> detail::ExtractIhvBlob(
    std::span<const std::uint8_t> serializedRequest,
    std::size_t written) noexcept
{
    if (written <= kWdiHeaderAndTlvSize || written > serializedRequest.size()) return {};
    return serializedRequest.subspan(kWdiHeaderAndTlvSize, written - kWdiHeaderAndTlvSize);
}

ResponseValidation detail::ValidateEchoResponse(
    std::span<const std::uint8_t> expected,
    std::span<const std::uint8_t> response) noexcept
{
    if (expected.size() < 24) return ResponseValidation::InvalidContents;
    if (response.size() != expected.size()) return ResponseValidation::InvalidLength;
    for (std::size_t i = 0; i < expected.size(); ++i) {
        // The vendor handler owns the two output words corresponding to the
        // existing LWF parser's bytes-read and bytes-needed fields.
        if (i >= 16 && i < 24) continue;
        if (response[i] != expected[i]) return ResponseValidation::InvalidContents;
    }
    return ResponseValidation::Valid;
}

DirectIhv::DirectIhv(const tx10ub::host::Adapter& adapter)
    : adapterGuid_(adapter.guid), adapterLuid_(adapter.luid)
{
    const GUID zeroGuid{};
    if (std::memcmp(&adapterGuid_, &zeroGuid, sizeof(GUID)) == 0 ||
        adapterLuid_.Value == 0) {
        throw std::invalid_argument("adapter_identity_invalid");
    }

    NET_LUID resolvedLuid{};
    NET_IFINDEX resolvedIndex{};
    MIB_IF_ROW2 row{};
    row.InterfaceLuid = adapterLuid_;
    if (ConvertInterfaceGuidToLuid(&adapterGuid_, &resolvedLuid) != NO_ERROR ||
        resolvedLuid.Value != adapterLuid_.Value ||
        ConvertInterfaceLuidToIndex(&adapterLuid_, &resolvedIndex) != NO_ERROR ||
        resolvedIndex == 0 || resolvedIndex != adapter.index ||
        GetIfEntry2(&row) != NO_ERROR || row.InterfaceIndex != resolvedIndex ||
        row.Type != IF_TYPE_IEEE80211 || row.PhysicalAddressLength != 6 ||
        (row.PhysicalAddress[0] & 1u) != 0) {
        throw std::invalid_argument("adapter_identity_invalid");
    }

    DWORD negotiatedVersion{};
    HANDLE client{};
    const DWORD status = WlanOpenHandle(2, nullptr, &negotiatedVersion, &client);
    if (status != ERROR_SUCCESS) {
        throw std::system_error(static_cast<int>(status), std::system_category(),
                                "wlan_open_failed");
    }
    client_ = client;
}

DirectIhv::~DirectIhv()
{
    (void)Close();
}

DWORD DirectIhv::Close() noexcept
{
    if (client_ == nullptr) return ERROR_SUCCESS;
    const HANDLE client = client_;
    client_ = nullptr;
    return WlanCloseHandle(client, nullptr);
}

OperationResult DirectIhv::Call(std::span<const std::uint8_t> ihvRequest,
                                std::size_t responseCapacity)
{
    if (client_ == nullptr || ihvRequest.empty() ||
        ihvRequest.size() > std::numeric_limits<DWORD>::max() ||
        responseCapacity == 0 || responseCapacity > std::numeric_limits<DWORD>::max()) {
        throw std::invalid_argument("ihv_request_size_invalid");
    }

    OperationResult result{};
    if (transportQuarantined_) {
        result.win32Status = ERROR_TIMEOUT;
        result.transportQuarantined = true;
        return result;
    }

    result.response.resize(responseCapacity);
    DWORD bytesReturned{};
    result.callIssued = true;
    const auto callStart = std::chrono::steady_clock::now();
    result.win32Status = WlanIhvControl(
        client_, &adapterGuid_, wlan_ihv_control_type_driver,
        static_cast<DWORD>(ihvRequest.size()),
        const_cast<std::uint8_t*>(ihvRequest.data()),
        static_cast<DWORD>(responseCapacity), result.response.data(), &bytesReturned);
    result.ihvCallTime = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - callStart);
    if (IsOutcomeUncertainTransportFailure(result.win32Status)) {
        transportQuarantined_ = true;
        result.transportQuarantined = true;
    }

    if (bytesReturned > responseCapacity) {
        result.response.clear();
        if (result.win32Status == ERROR_SUCCESS) {
            result.responseValidation = ResponseValidation::InvalidLength;
        }
        return result;
    }
    result.response.resize(bytesReturned);
    return result;
}

OperationResult DirectIhv::CallSerialized(
    std::span<const std::uint8_t> serializedRequest,
    std::size_t written)
{
    const auto ihvRequest = detail::ExtractIhvBlob(serializedRequest, written);
    if (ihvRequest.empty()) {
        throw std::invalid_argument("serialized_ihv_request_invalid");
    }
    auto result = Call(ihvRequest, ihvRequest.size());
    if (result.win32Status == ERROR_SUCCESS &&
        result.responseValidation != ResponseValidation::InvalidLength) {
        SetValidated(result, detail::ValidateEchoResponse(ihvRequest, result.response));
    }
    return result;
}

OperationResult DirectIhv::VendorId()
{
    return QueryFixedDword(kVendorIdOid);
}

OperationResult DirectIhv::QueryEncryptionStatus()
{
    return QueryFixedDword(AWDLWIN_AF_ENCRYPTION_STATUS_INNER_OID);
}

OperationResult DirectIhv::QueryFixedDword(std::uint32_t oid)
{
    const std::array<std::uint32_t, 8> request{
        28u, kVendorExtensionSignature, 0u, oid, 0u, 0u, 4u, 0u};
    auto result = Call(
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(request.data()),
                                      sizeof(request)),
        256);
    if (result.win32Status != ERROR_SUCCESS) return result;
    if (result.response.size() != 32) {
        result.responseValidation = ResponseValidation::InvalidLength;
        return result;
    }

    std::array<std::uint32_t, 8> response{};
    std::memcpy(response.data(), result.response.data(), sizeof(response));
    if (response[0] != request[0] || response[1] != request[1] ||
        response[2] != request[2] || response[3] != request[3] ||
        response[4] != 4u || response[6] != 4u) {
        result.responseValidation = ResponseValidation::InvalidContents;
        return result;
    }

    result.responseValidation = ResponseValidation::Valid;
    result.acceptance = RequestAcceptance::Accepted;
    result.value = response[7];
    return result;
}

OperationResult DirectIhv::ReadMac(MacRegister address)
{
    const std::uint32_t registerAddress = RegisterAddress(address);
    const std::array<std::uint32_t, 12> request{
        44u, 0x814CE000u, 4u, 1u, 7u, 24u, kRxRegisterOid, 0u, 0u, 8u,
        registerAddress, 4u};
    auto result = Call(
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(request.data()),
                                      sizeof(request)),
        64);
    if (result.win32Status != ERROR_SUCCESS) return result;
    if (result.response.size() != 48) {
        result.responseValidation = ResponseValidation::InvalidLength;
        return result;
    }

    std::array<std::uint32_t, 12> response{};
    std::memcpy(response.data(), result.response.data(), sizeof(response));
    if (response[0] != request[0] || response[1] != request[1] ||
        response[2] != request[2] || response[3] != request[3] ||
        response[4] != request[4] || response[5] != request[5] ||
        response[6] != request[6] || response[7] != 4u ||
        response[8] != request[8] || response[9] != request[9] ||
        response[11] != request[11]) {
        result.responseValidation = ResponseValidation::InvalidContents;
        return result;
    }

    result.responseValidation = ResponseValidation::Valid;
    result.acceptance = RequestAcceptance::Accepted;
    result.value = response[10];
    return result;
}

OperationResult DirectIhv::SendAction(const AWDLWIN_AF_PARAMETERS& parameters,
                                     std::span<const std::uint8_t> serviceBody)
{
    std::array<std::uint8_t, kSerializerCapacity> serialized{};
    std::size_t written{};
    const auto source = ReadAdapterMac(adapterLuid_);
    if (parameters.BodyLength > sizeof(parameters.Body))
        throw std::invalid_argument("raw_action_parameters_invalid");
    const auto body = serviceBody.empty() ? std::span(parameters.Body,parameters.BodyLength) : serviceBody;
    if (!AwdlWinAfSerializeRawBodyRequest(&parameters, body.data(), body.size(),
            source.data(), serialized.data(), serialized.size(), &written)) {
        throw std::invalid_argument("raw_action_parameters_invalid");
    }
    return CallSerialized(serialized, written);
}

OperationResult DirectIhv::SendData(std::span<const std::uint8_t, 6> source,
                                    std::span<const std::uint8_t> frame, DataRate rate)
{
    if (rate != DataRate::Mbps12 && rate != DataRate::Mbps24 &&
        rate != DataRate::Mbps36 && rate != DataRate::Mbps54) {
        throw std::invalid_argument("raw_data_rate_invalid");
    }
    const auto macStart = std::chrono::steady_clock::now();
    const auto adapterSource = ReadAdapterMac(adapterLuid_);
    const auto macTime = std::chrono::steady_clock::now() - macStart;
    if (!std::equal(source.begin(), source.end(), adapterSource.begin())) {
        throw std::invalid_argument("raw_data_source_does_not_match_adapter");
    }
    std::array<std::uint8_t, kSerializerCapacity> serialized{};
    std::size_t written{};
    if (!AwdlWinAfSerializeRawDataRequest(
            NextSerializationTransactionId(), source.data(), frame.data(), frame.size(),
            serialized.data(), serialized.size(), &written)) {
        throw std::invalid_argument("raw_data_frame_invalid");
    }
    if (rate != DataRate::Mbps12 && (frame[4] & 1u) != 0) {
        throw std::invalid_argument("raw_data_multicast_rate_invalid");
    }
    serialized[50] = static_cast<std::uint8_t>(rate);
    auto result = CallSerialized(serialized, written);
    result.macReadTime = std::chrono::duration_cast<std::chrono::microseconds>(macTime);
    return result;
}

OperationResult DirectIhv::SetWps(std::span<const std::uint8_t> ie)
{
    std::array<std::uint8_t, kSerializerCapacity> serialized{};
    std::size_t written{};
    if (!AwdlWinAfSerializeWpsRequest(
            NextSerializationTransactionId(), 1, ie.data(), ie.size(),
            serialized.data(), serialized.size(), &written)) {
        throw std::invalid_argument("wps_ie_invalid");
    }
    return CallSerialized(serialized, written);
}

OperationResult DirectIhv::ClearWps()
{
    std::array<std::uint8_t, kSerializerCapacity> serialized{};
    std::size_t written{};
    if (!AwdlWinAfSerializeWpsClearRequest(
            NextSerializationTransactionId(), serialized.data(), serialized.size(), &written)) {
        throw std::logic_error("wps_clear_serialization_failed");
    }
    auto result = CallSerialized(serialized, written);
    if (result.win32Status == kKnownWpsClearInvalidLength) {
        result.acceptance = RequestAcceptance::Rejected;
        result.wpsClearStatus = WpsClearStatus::KnownInvalidLengthC0010014;
    } else if (result.win32Status == ERROR_SUCCESS &&
               result.responseValidation == ResponseValidation::Valid) {
        result.wpsClearStatus = WpsClearStatus::AcceptedEffectUnverified;
    } else {
        result.wpsClearStatus = WpsClearStatus::Unknown;
    }
    return result;
}

OperationResult DirectIhv::DisableEncryption()
{
    std::array<std::uint8_t, kSerializerCapacity> serialized{};
    std::size_t written{};
    if (!AwdlWinAfSerializeEncryptionDisabledRequest(
            NextSerializationTransactionId(), serialized.data(), serialized.size(), &written)) {
        throw std::logic_error("encryption_disable_serialization_failed");
    }
    return CallSerialized(serialized, written);
}

} // namespace tx10ub::direct_ihv
