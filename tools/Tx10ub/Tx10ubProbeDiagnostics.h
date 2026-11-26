#pragma once

#include "Tx10ubProbeSupport.h"

namespace tx10ub::probe {

int ReadObservations(const wchar_t* devicePath);
int ReadStationStatus();
int ScanTarget(const wchar_t* guidText);
int RunTwoRequestControl(int argc, wchar_t** argv);
int RunRealtekCensus(int argc, wchar_t** argv);
int RunCompletionGateControl(int argc, wchar_t** argv);
int RunExperimentalAction(int argc, wchar_t** argv);
int RunPocAction(int argc, wchar_t** argv);
bool SaveResponse(const wchar_t* path, const AWDLWIN_G2_RESULT_V1& result);

#ifdef AWDLWIN_ENABLE_AWDL_FORMAT_EXPERIMENT
int ReadDataQueryTrace(const wchar_t* devicePath, ULONG index, ULONGLONG luid);
int ReadDataQueryCorrelation(const wchar_t* devicePath, ULONG index, ULONGLONG luid);
int RunPocAwdlAction(int argc, wchar_t** argv);
int RunStaConnect(int argc, wchar_t** argv, const wchar_t* guidText);
int RunBleV2Advertise(const wchar_t* stopPath);
#endif

}
