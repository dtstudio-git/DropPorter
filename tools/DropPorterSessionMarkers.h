#pragma once

namespace dropporter::session_markers {

inline constexpr wchar_t CancelFileName[] = L"cancel.request";
inline constexpr char IdleTimeoutContent[] = "receive_idle_timeout\n";
// Allow a full AWDL channel sequence to deliver the final service records.
inline constexpr unsigned ReceiveWithdrawalWindowMs = 1500;

inline constexpr wchar_t ReceiveStopFileName[] = L"receive-stop.request";
inline constexpr char ReceiveStopContent[] = "stop\n";
inline constexpr wchar_t ProbeStopFileName[] = L"stop.request";
inline constexpr wchar_t ProbeShutdownFileName[] = L"shutdown.complete";
inline constexpr char ProbeShutdownContent[] = "send_ble_usb_stopped=1\n";

inline constexpr wchar_t RadioSnapshotFileName[] = L"radio.snapshot";
inline constexpr wchar_t RestoreBlockedFileName[] = L"restore.blocked";
inline constexpr wchar_t RecoveryCompletedFileName[] = L"recovery.completed";
inline constexpr char RecoveryCompletedContent[] = "1\n";
inline constexpr wchar_t RecoveryDismissedFileName[] = L"recovery.dismissed";
inline constexpr char RecoveryDismissedContent[] = "1\n";

} // namespace dropporter::session_markers
