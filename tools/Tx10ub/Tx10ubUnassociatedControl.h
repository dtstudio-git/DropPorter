#pragma once

// User-mode lease issued by the radio controller. This child never owns the
// radio: a pre-TCP channel change requires the controller's exact acknowledgement.
#include "Tx10ubRadioHandoff.h"
#include "Tx10ubRadioLease.h"
#include "../DropPorter/DropPorterTargetFiles.h"
#include "../DropPorter/DropPorterSessionMarkers.h"
#include <atomic>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <functional>
#include <iostream>

class UnassociatedControl {
    std::filesystem::path directory_;
    HANDLE parent_=nullptr,wlan_=nullptr;
    GUID guid_{};
    DWORD parent_id_=0;
    ULONGLONG checked_=0;
    bool stopped_=false,faulted_=false;
    unsigned channelGeneration_=0;
    bool radioHandoffPending_=false;
    std::atomic<unsigned> sends_{0};
    std::atomic<bool> uncertain_{false};
    bool fault(const wchar_t* reason) {
        faulted_=true;
        std::wcerr<<L"radio_control_failure="<<reason<<L'\n';
        return false;
    }
    bool read_state(unsigned long& pid,unsigned long long& tick)const {
        HANDLE gate=CreateMutexW(nullptr,FALSE,tx10ub::radio_lease::MutexName);
        if(!gate)return false;
        const auto acquired=WaitForSingleObject(gate, tx10ub::radio_lease::MutexWaitMs);
        if(acquired!=WAIT_OBJECT_0&&acquired!=WAIT_ABANDONED){CloseHandle(gate);return false;}
        HANDLE file=CreateFileW((directory_/tx10ub::radio_lease::FileName).c_str(),GENERIC_READ,
            FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr);
        char bytes[96]{};DWORD count=0;
        const bool ok=file!=INVALID_HANDLE_VALUE&&ReadFile(file,bytes,sizeof(bytes)-1,&count,nullptr)!=FALSE;
        if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);
        ReleaseMutex(gate);CloseHandle(gate);
        if(!ok||!count)return false;
        return tx10ub::radio_lease::Decode(std::string_view(bytes, count), pid, tick);
    }
public:
    UnassociatedControl(const wchar_t* directory,const wchar_t* guidText):directory_(directory) {
        if(!directory_.is_absolute())throw std::runtime_error("unassociated_control_requires_absolute_path");
        unsigned long pid=0;unsigned long long tick=0;
        if(!read_state(pid,tick)||!pid||GetTickCount64()<tick||GetTickCount64()-tick > tx10ub::radio_lease::MaxAgeMs)
            throw std::runtime_error("unassociated_radio_lease_missing");
        parent_id_=pid;
        parent_=OpenProcess(SYNCHRONIZE,FALSE,pid);
        DWORD version=0;
        if(!parent_||FAILED(CLSIDFromString(guidText,&guid_))||
           WlanOpenHandle(2,nullptr,&version,&wlan_)!=ERROR_SUCCESS) {
            if(parent_)CloseHandle(parent_);
            throw std::runtime_error("unassociated_control_open_failed");
        }
    }
    ~UnassociatedControl(){if(wlan_)WlanCloseHandle(wlan_,nullptr);if(parent_)CloseHandle(parent_);}
    bool healthy() {
        if(faulted_||stopped_)return false;
        if(GetFileAttributesW((directory_ / dropporter::session_markers::ProbeStopFileName).c_str())!=INVALID_FILE_ATTRIBUTES) {
            stopped_=true;
            std::wcerr<<L"radio_control_stop_requested=1\n";
            return false;
        }
        const auto parentWait=WaitForSingleObject(parent_,0);
        if(parentWait!=WAIT_TIMEOUT) {
            const auto error=parentWait==WAIT_FAILED?GetLastError():ERROR_SUCCESS;
            std::wcerr<<L"radio_control_parent_wait="<<parentWait<<L" win32="<<error<<L'\n';
            return fault(L"parent_not_running");
        }
        unsigned long pid=0;unsigned long long tick=0;
        if(!read_state(pid,tick))return fault(L"lease_read_failed");
        if(pid!=parent_id_)return fault(L"lease_owner_changed");
        const auto now=GetTickCount64();
        if(now<tick)return fault(L"lease_timestamp_in_future");
        if(now-tick > tx10ub::radio_lease::MaxAgeMs) {
            std::wcerr<<L"radio_control_lease_age_ms="<<now-tick<<L'\n';
            return fault(L"lease_expired");
        }
        if(checked_&&now-checked_<200)return true;
        checked_=now;
        DWORD size=0;PVOID value=nullptr;WLAN_OPCODE_VALUE_TYPE type{};
        const auto error=WlanQueryInterface(wlan_,&guid_,wlan_intf_opcode_interface_state,
            nullptr,&size,&value,&type);
        const bool hasState=error==ERROR_SUCCESS&&value&&size>=sizeof(WLAN_INTERFACE_STATE);
        const auto state=hasState?static_cast<int>(*static_cast<WLAN_INTERFACE_STATE*>(value)):-1;
        if(value)WlanFreeMemory(value);
        if(state!=wlan_interface_state_disconnected) {
            std::wcerr<<L"radio_control_wlan_state="<<state<<L" win32="<<error<<L'\n';
            return fault(hasState?L"interface_not_disconnected":L"interface_state_unavailable");
        }
        return true;
    }
    bool stopped()const{return stopped_&&!faulted_;}
    bool radio_handoff_uncertain()const{return radioHandoffPending_;}
    bool ready_to_withdraw() { return !radioHandoffPending_ && !uncertain_ && sends_==0 && healthy(); }
    bool request_channel(unsigned from,unsigned to,const std::function<bool()>& pump,bool receiving=false) {
        const tx10ub::radio_handoff::Request request{channelGeneration_+1,GetCurrentProcessId(),from,to};
        if(!tx10ub::radio_handoff::valid(request,receiving)||sends_!=0||uncertain_||!healthy())return false;
        const auto requestPath=directory_/tx10ub::radio_handoff::request_name(request.generation);
        auto temporary=requestPath;temporary+=L".tmp";
        {
            std::ofstream out(temporary,std::ios::binary|std::ios::trunc);
            out<<tx10ub::radio_handoff::encode(request);out.close();
            if(!out){faulted_=true;return false;}
        }
        radioHandoffPending_=true;
        if(!MoveFileExW(temporary.c_str(),requestPath.c_str(),MOVEFILE_WRITE_THROUGH)) {faulted_=true;return false;}
        const auto expected=tx10ub::radio_handoff::acknowledgement(request);
        const auto deadline=GetTickCount64()+tx10ub::radio_handoff::acknowledgement_timeout_ms;
        do {
            bool acknowledged=false;
            {
                std::ifstream in(directory_/tx10ub::radio_handoff::acknowledgement_name(request.generation),std::ios::binary);
                char bytes[128]{};in.read(bytes,sizeof(bytes));
                acknowledged=in.gcount()==static_cast<std::streamsize>(expected.size())&&
                    std::string_view(bytes,static_cast<std::size_t>(in.gcount()))==expected;
            }
            if(acknowledged) {
                radioHandoffPending_=false;
                channelGeneration_=request.generation;
                return healthy();
            }
            if(!healthy())return false;
            // The USB owner keeps its original event clock and cancellation
            // checks alive; waiting never fabricates a channel acknowledgement.
            if(!pump||!pump())return false;
        }while(GetTickCount64()<deadline);
        faulted_=true; // Unknown physical channel: stop, never resume old-channel TX.
        return false;
    }
    bool publish_targets(unsigned round,const std::string& rows)const {
        const auto temporary=directory_/(std::wstring(dropporter::target_files::ListName) + L".tmp");
        {std::ofstream out(temporary,std::ios::binary|std::ios::trunc);
         out << dropporter::target_files::Round<<round<<'\n'<<rows;out.close();if(!out)return false;}
        return MoveFileExW(temporary.c_str(),(directory_/dropporter::target_files::ListName).c_str(),MOVEFILE_REPLACE_EXISTING)!=FALSE;
    }
    bool refresh_requested(unsigned generation)const {
        const auto marker=directory_/dropporter::target_files::RefreshName(generation);
        return GetFileAttributesW(marker.c_str())!=INVALID_FILE_ATTRIBUTES;
    }
    std::optional<unsigned> selected_target(unsigned round)const {
        const auto path=directory_/dropporter::target_files::SelectionName(round);
        std::ifstream in(path,std::ios::binary);
        if(!in)return std::nullopt;
        char bytes[32]{};in.read(bytes,sizeof(bytes));
        const auto count=in.gcount();
        const auto id = count > 0 && count < static_cast<std::streamsize>(sizeof(bytes)) ?
            dropporter::target_files::ParseNumber(std::string_view(bytes, static_cast<std::size_t>(count)),
                                              dropporter::target_files::MaxTargetId) : std::nullopt;
        if (!id) throw std::runtime_error("invalid_target_selection");
        return id;
    }
    struct Send {
        UnassociatedControl* owner;
        bool settled=false;
        explicit Send(UnassociatedControl* value):owner(value){if(owner)++owner->sends_;}
        ~Send(){if(owner){if(!settled)owner->uncertain_=true;--owner->sends_;}}
    };
    void shutdown(bool resourcesClosed) {
        if(resourcesClosed&&sends_==0&&!uncertain_) {
            std::ofstream marker(directory_ / dropporter::session_markers::ProbeShutdownFileName, std::ios::trunc);
            marker << dropporter::session_markers::ProbeShutdownContent;
        }
    }
};
