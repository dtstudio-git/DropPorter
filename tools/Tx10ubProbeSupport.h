#pragma once

#include <windows.h>
#include <iphlpapi.h>
#include <winioctl.h>
#include <wlanapi.h>

#include "../driver/tx10ub-probe/tx10ub_ioctl.h"

namespace tx10ub::probe {

inline constexpr wchar_t kDevice[] = L"\\\\.\\AWDLWinTx10ubProbe";

struct ConnectionSnapshot {
    bool connected = false;
    UCHAR bssid[6]{};
    ULONG channel = 0;
};

struct ScanNotificationContext {
    GUID targetGuid;
    HANDLE event;
    volatile LONG outcome;
};

bool ResolveTarget(NET_LUID& luid, NET_IFINDEX& index);
ConnectionSnapshot ReadConnection(const wchar_t* phase);
void WINAPI OnScanNotification(PWLAN_NOTIFICATION_DATA notification, PVOID callbackContext);

bool ParsePortId(const wchar_t* text, USHORT& portId);
bool ParseUnsigned(const wchar_t* value, ULONG& result);
bool ParseHex(const wchar_t* value, UCHAR* output, size_t capacity, size_t& count);

void PrintHex(const wchar_t* name, ULONG value);
void PrintBytes(const UCHAR* bytes, size_t count);
void PrintActionResult(const AWDLWIN_ACTION_RESULT_V1& result);
int ActionExitCode(BOOL ioctlSuccess, DWORD bytesReturned, const AWDLWIN_ACTION_RESULT_V1& result);
int ReadActionEvents(ULONGLONG afterSequence = 0, ULONGLONG* newest = nullptr, bool printRecords = true);

bool StaStillAssociated(HANDLE client, const GUID& guid, const UCHAR (&bssid)[6]);
#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
bool StaUsesChannel(HANDLE wlan, const GUID& guid, ULONG expected);
#endif

}
