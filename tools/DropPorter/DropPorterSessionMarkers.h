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
// The runtime left the Wi-Fi adapter in its transfer state for the next transfer
// of the same app run. A later transfer of that run takes the state over
// (RadioAdopted), or the app restores it with "--recover" when it closes.
inline constexpr wchar_t RadioKeptFileName[] = L"radio.kept";
inline constexpr char RadioKeptContent[] = "1\n";
inline constexpr wchar_t RadioAdoptedFileName[] = L"radio.adopted";
inline constexpr char RadioAdoptedContent[] = "1\n";
// Written by the app before stopping a waiting receive for a send: keep the
// transfer state for that send even when the setting is off.
inline constexpr wchar_t HandoverFileName[] = L"handover.request";
inline constexpr char HandoverContent[] = "send\n";

} // namespace dropporter::session_markers
