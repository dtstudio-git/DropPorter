#pragma once

#include "Tx10ubHost.h"
#include "../driver/tx10ub-probe/tx10ub_action_core.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace tx10ub::direct_ihv {

enum class MacRegister {
    Ce20,
    Ce2c,
    Ce34,
    Ce38,
    ManagementFilter,
};

// Vendor raw-data rate field, in units of 500 kbps.
enum class DataRate : std::uint8_t { Mbps12 = 24, Mbps24 = 48 };

enum class ResponseValidation {
    NotChecked,
    Valid,
    InvalidLength,
    InvalidContents,
};

enum class RequestAcceptance {
    Unknown,
    Accepted,
    Rejected,
};

enum class WpsClearStatus {
    NotApplicable,
    Unknown,
    AcceptedEffectUnverified,
    KnownInvalidLengthC0010014,
};

struct OperationResult {
    DWORD win32Status{ERROR_SUCCESS};
    ResponseValidation responseValidation{ResponseValidation::NotChecked};
    RequestAcceptance acceptance{RequestAcceptance::Unknown};
    WpsClearStatus wpsClearStatus{WpsClearStatus::NotApplicable};
    bool callIssued{false};
    bool transportQuarantined{false};
    // WlanIhvControl success proves neither over-the-air transmission nor peer receipt.
    bool rfCompletionVerified{false};
    std::optional<std::uint32_t> value;
    std::vector<std::uint8_t> response;
    std::chrono::microseconds macReadTime{}, ihvCallTime{};
};

namespace detail {
std::span<const std::uint8_t> ExtractIhvBlob(
    std::span<const std::uint8_t> serializedRequest,
    std::size_t written) noexcept;
ResponseValidation ValidateEchoResponse(std::span<const std::uint8_t> expected,
                                        std::span<const std::uint8_t> response) noexcept;
}

// Calls are synchronous and serialized by the owning caller thread. Callers
// must also hold their session mutex and enforce the auxiliary-stopped guard.
// An ambiguous timeout/RPC failure quarantines this instance from further calls.
class DirectIhv final {
public:
    explicit DirectIhv(const tx10ub::host::Adapter& adapter);
    ~DirectIhv();

    DirectIhv(const DirectIhv&) = delete;
    DirectIhv& operator=(const DirectIhv&) = delete;
    DirectIhv(DirectIhv&&) = delete;
    DirectIhv& operator=(DirectIhv&&) = delete;

    OperationResult VendorId();
    OperationResult QueryEncryptionStatus();
    OperationResult ReadMac(MacRegister address);
    OperationResult SendAction(const AWDLWIN_AF_PARAMETERS& parameters,
                               std::span<const std::uint8_t> serviceBody = {});
    OperationResult SendData(std::span<const std::uint8_t, 6> source,
                             std::span<const std::uint8_t> frame, DataRate rate = DataRate::Mbps12);
    OperationResult SetWps(std::span<const std::uint8_t> ie);
    OperationResult ClearWps();
    OperationResult DisableEncryption();
    DWORD Close() noexcept;

private:
    OperationResult QueryFixedDword(std::uint32_t oid);
    OperationResult Call(std::span<const std::uint8_t> ihvRequest,
                         std::size_t responseCapacity);
    OperationResult CallSerialized(std::span<const std::uint8_t> serializedRequest,
                                   std::size_t written);

    HANDLE client_{};
    GUID adapterGuid_{};
    NET_LUID adapterLuid_{};
    bool transportQuarantined_{};
};

} // namespace tx10ub::direct_ihv
