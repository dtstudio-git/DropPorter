#pragma once

#include <string_view>
#include <utility>

namespace dropporter::supervisor {

inline constexpr wchar_t StatusFileName[] = L"status.txt";
inline constexpr wchar_t ResultFileName[] = L"result.txt";
inline constexpr wchar_t RecoveryResultFileName[] = L"recovery-result.txt";

inline constexpr char StatusKey[] = "status";
inline constexpr char TransferSucceededKey[] = "transfer_succeeded";
inline constexpr char FailureStageKey[] = "failure_stage";
inline constexpr char FailureReasonKey[] = "failure_reason";
inline constexpr char FailureHttpStatusKey[] = "failure_http_status";
inline constexpr char RestorationRequiredKey[] = "restoration_required";
inline constexpr char RecoveryRequiredKey[] = "recovery_required";
inline constexpr char ApRestoredKey[] = "ap_restored";
inline constexpr char AuxiliaryRestoredKey[] = "auxiliary_restored";
inline constexpr char RxReinitializedKey[] = "rx_reinitialized";
inline constexpr char RxRestoreVerifiedKey[] = "rx_restore_verified";
inline constexpr char VendorStateUnchangedKey[] = "vendor_state_unchanged";

inline constexpr char UnsupportedDriverReason[] = "unsupported_driver_image";
inline constexpr char MissingAdapterReason[] = "adapter_not_present";
inline constexpr char MultipleAdaptersReason[] = "multiple_adapters_present";
inline constexpr char TransferHelperBusyReason[] = "another_tx10ub_probe_or_receive_worker_is_running";
inline constexpr char RecoveryAdapterChangedReason[] = "runtime_recovery_adapter_identity_changed";
inline constexpr char RecoveryOperationUnsettledReason[] = "runtime_recovery_lower_operation_not_settled";
inline constexpr char RecoverySnapshotMissingReason[] = "runtime_recovery_snapshot_missing";

enum class RecoveryExit : int {
    Failed = 1,
    UnsupportedDriver = 10,
    MissingAdapter = 11,
    AdapterChanged = 12,
    OperationUnsettled = 13,
    SnapshotMissing = 14,
};

inline constexpr std::pair<RecoveryExit, const char*> RecoveryReasons[] = {
    {RecoveryExit::Failed, "failed"},
    {RecoveryExit::UnsupportedDriver, UnsupportedDriverReason},
    {RecoveryExit::MissingAdapter, MissingAdapterReason},
    {RecoveryExit::AdapterChanged, RecoveryAdapterChangedReason},
    {RecoveryExit::OperationUnsettled, RecoveryOperationUnsettledReason},
    {RecoveryExit::SnapshotMissing, RecoverySnapshotMissingReason},
};

inline constexpr RecoveryExit ClassifyRecoveryFailure(std::string_view reason) noexcept {
    for (const auto& [code, name] : RecoveryReasons) {
        if (reason == name) return code;
    }
    if (reason == "runtime_recovery_device_identity_changed" ||
        reason == "runtime_recovery_target_luid_changed") return RecoveryExit::AdapterChanged;
    if (reason == "runtime_recovery_probe_shutdown_unconfirmed") return RecoveryExit::OperationUnsettled;
    return RecoveryExit::Failed;
}

inline constexpr const char* RecoveryFailureReason(int exitCode) noexcept {
    for (const auto& [code, name] : RecoveryReasons) {
        if (static_cast<int>(code) == exitCode) return name;
    }
    return RecoveryReasons[0].second;
}

enum class Phase {
    Unknown, Preparing, PreparingAdapter, PreparingNetwork, PreparingRadio,
    Discovering, Selecting, Connecting, WaitingAccept, Sending, Finalizing,
    Listening, Restoring, Completed, Cancelled, Failed
};

inline constexpr std::pair<Phase, const char*> PhaseNames[] = {
    {Phase::Preparing, "preparing"},
    {Phase::PreparingAdapter, "preparing_adapter"},
    {Phase::PreparingNetwork, "preparing_network"},
    {Phase::PreparingRadio, "preparing_radio"},
    {Phase::Discovering, "discovering"},
    {Phase::Selecting, "selecting"},
    {Phase::Connecting, "connecting"},
    {Phase::WaitingAccept, "waiting_accept"},
    {Phase::Sending, "sending"},
    {Phase::Finalizing, "finalizing"},
    {Phase::Listening, "listening"},
    {Phase::Restoring, "restoring"},
    {Phase::Completed, "completed"},
    {Phase::Cancelled, "cancelled"},
    {Phase::Failed, "failed"},
};

inline constexpr const char* PhaseName(Phase phase) noexcept {
    for (const auto& [value, name] : PhaseNames) {
        if (value == phase) return name;
    }
    return "";
}

inline constexpr Phase ParsePhase(std::string_view text) noexcept {
    for (const auto& [phase, name] : PhaseNames) {
        if (name == text) return phase;
    }
    return Phase::Unknown;
}

inline constexpr std::string_view TrimStatus(std::string_view text) noexcept {
    const auto first = text.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    return text.substr(first, text.find_last_not_of(" \t\r\n") - first + 1);
}

inline constexpr bool IsFinalPhase(Phase phase) noexcept {
    return phase == Phase::Completed || phase == Phase::Cancelled || phase == Phase::Failed;
}

}
