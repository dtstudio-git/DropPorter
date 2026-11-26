#pragma once

#include "Tx10ubHost.h"

namespace tx10ub::host {

struct NetworkRestartTimings {
    ULONGLONG deviceRestartMs{}, adapterReadyMs{}, wifiRestoreMs{};
    DWORD scanPolicyStatus{ERROR_NOT_SUPPORTED};
};

// Caller holds Global\AWDLWinSend and has closed all vendor transport handles
// and drained requests. originalWifi is captured before the session changes
// radio state; this function never replaces it with a session-time snapshot.
// Returns the same adapter identity with refreshed interface index and LUID.
// On failure, the exception includes any recovery work that remains pending.
// UsbCaptureSession is a direct session captured through USBPcap; profiles with
// usbCaptureRestartCyclesPort restart it by cycling the USB port.
enum class RestartPurpose { DirectIhvSession, PassiveCapture, UsbCaptureSession };
Adapter RestartNetworkAndRestoreWifi(const Adapter& adapter,
                                    const WifiSnapshot& originalWifi,
                                    NetworkRestartTimings* timings = nullptr,
                                    RestartPurpose purpose = RestartPurpose::DirectIhvSession);

// Only for cancellation before any vendor/radio operation was issued.
Adapter RestoreWifiWithoutRestart(const Adapter& adapter, const WifiSnapshot& originalWifi);

} // namespace tx10ub::host
