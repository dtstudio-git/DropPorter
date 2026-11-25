#pragma once
#include "DropPorterSessionMarkers.h"
#include "Tx10ubReceiveWorkerProtocol.h"
#include "Tx10ubUserFileAccess.h"
#include <windows.h>
#include <objbase.h>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <mutex>
#include <thread>
#include <vector>
#include <span>
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>

namespace tx10ub::airdrop {
// Anonymous pipes carry application bytes only. Dedicated pipe threads keep
// disk and approval work off the sole USB receive owner, with bounded queues
// in both directions.
class ReceiveWorker {
public:
    struct Message {std::uint8_t type;std::uint32_t connection;std::vector<std::uint8_t> data;};
private:
    HANDLE process_=nullptr,input_=nullptr,output_=nullptr;
    HANDLE stage_=INVALID_HANDLE_VALUE;
    std::filesystem::path control_;
    DWORD ownerPid_=0;
    std::thread writer_,reader_;
    std::mutex mutex_;
    std::condition_variable wake_;
    std::deque<std::vector<std::uint8_t>> writes_;
    std::deque<Message> reads_;
    std::size_t writeBytes_=0,readBytes_=0;
    bool stopping_=false;
    std::atomic<bool> failed_{false};
    static constexpr std::size_t queueLimit=512*1024;
    static bool mark_for_deletion(HANDLE file) {
        FILE_DISPOSITION_INFO info{TRUE};
        return SetFileInformationByHandle(file,FileDispositionInfo,&info,sizeof(info))!=FALSE;
    }
    std::filesystem::path create_stage(const std::filesystem::path& destination) {
        ScopedUserFileAccess access(ownerPid_);
        std::filesystem::create_directories(destination);
        GUID guid{};
        wchar_t id[40]{};
        if(FAILED(CoCreateGuid(&guid))||!StringFromGUID2(guid,id,40))return {};
        const auto path=std::filesystem::absolute(destination)/(L".awdlwin-receive-"+std::wstring(id+1,36));
        if(!CreateDirectoryW(path.c_str(),nullptr))return {};
        SetFileAttributesW(path.c_str(),FILE_ATTRIBUTE_HIDDEN);
        stage_=CreateFileW(path.c_str(),DELETE|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,
                           nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        if(stage_==INVALID_HANDLE_VALUE){
            RemoveDirectoryW(path.c_str());
            return {};
        }
        BY_HANDLE_FILE_INFORMATION info{};
        if(!GetFileInformationByHandle(stage_,&info)||(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)){
            CloseHandle(stage_);
            stage_=INVALID_HANDLE_VALUE;
            return {};
        }
        return path;
    }
    bool clean_stage() {
        if(stage_==INVALID_HANDLE_VALUE)return true;
        bool clean=mark_for_deletion(stage_);
        try {
            if(!clean){
                ScopedUserFileAccess access(ownerPid_);
                std::wstring resolved(32768,L'\0');
                const auto length=GetFinalPathNameByHandleW(stage_,resolved.data(),static_cast<DWORD>(resolved.size()),
                                                           FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
                if(length&&length<resolved.size()){
                    resolved.resize(length);
                    const std::filesystem::path path(resolved);
                    WIN32_FIND_DATAW entry{};
                    const auto list=FindFirstFileW((path/L"*").c_str(),&entry);
                    if(list!=INVALID_HANDLE_VALUE){
                        do {
                            const std::wstring_view name(entry.cFileName);
                            const bool part=name.size()>10&&name.starts_with(L"file-")&&name.ends_with(L".part")&&
                                name.substr(5,name.size()-10).find_first_not_of(L"0123456789")==std::wstring_view::npos;
                            if((entry.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))||
                               (name!=L"upload.body"&&name!=L"decoded.cpio"&&!part))continue;
                            const auto file=CreateFileW((path/entry.cFileName).c_str(),DELETE|FILE_READ_ATTRIBUTES,
                                FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
                            if(file==INVALID_HANDLE_VALUE)continue;
                            BY_HANDLE_FILE_INFORMATION info{};
                            if(GetFileInformationByHandle(file,&info)&&
                               !(info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))&&
                               info.nNumberOfLinks==1)mark_for_deletion(file);
                            CloseHandle(file);
                        }while(FindNextFileW(list,&entry));
                        FindClose(list);
                    }
                    clean=mark_for_deletion(stage_);
                }
            }
        } catch(const std::exception& e){
            std::cerr<<"receive staging cleanup: "<<e.what()<<'\n';
        }
        CloseHandle(stage_);
        stage_=INVALID_HANDLE_VALUE;
        return clean;
    }
    static std::wstring quote(const std::wstring& s){
        std::wstring r=L"\"";unsigned backslashes=0;
        for(auto c:s){if(c==L'\\'){++backslashes;continue;}r.append(c==L'"'?backslashes*2+1:backslashes,L'\\');backslashes=0;r+=c;}
        r.append(backslashes*2,L'\\');return r+L'"';
    }
    static bool exact(HANDLE h,void* data,DWORD size,bool write){
        auto* p=static_cast<std::uint8_t*>(data);
        while(size){DWORD n=0;const auto ok=write?WriteFile(h,p,size,&n,nullptr):ReadFile(h,p,size,&n,nullptr);if(!ok||!n)return false;p+=n;size-=n;}return true;
    }
    void write_loop(){
        for(;;){std::vector<std::uint8_t> frame;
            {std::unique_lock lock(mutex_);wake_.wait(lock,[&]{return stopping_||!writes_.empty();});
             if(writes_.empty())break;frame=std::move(writes_.front());writes_.pop_front();writeBytes_-=frame.size();}
            if(!exact(input_,frame.data(),static_cast<DWORD>(frame.size()),true)){failed_=true;break;}
        }
        CloseHandle(input_);input_=nullptr; // EOF asks the worker to clean its own staging files.
    }
    void read_loop(){
        for(;;){std::uint8_t h[9];if(!exact(output_,h,9,false))break;
            std::uint32_t id=0,length=0;for(unsigned i=0;i<4;++i){id|=std::uint32_t(h[1+i])<<(8*i);length|=std::uint32_t(h[5+i])<<(8*i);}
            const bool progress=h[0]==receive_worker_protocol::FinalizingProgress;
            if((h[0]!=2&&h[0]!=3&&!progress)||!id||length>65536||(h[0]==3&&length>1)||(progress&&length)){failed_=true;break;}
            Message message{h[0],id,std::vector<std::uint8_t>(length)};
            if(length&&!exact(output_,message.data.data(),length,false)){failed_=true;break;}
            if(h[0]==3&&length&&message.data.front()!=receive_worker_protocol::UploadCommitted){failed_=true;break;}
            std::lock_guard lock(mutex_);if(readBytes_+length+9>queueLimit){failed_=true;break;}
            readBytes_+=length+9;reads_.push_back(std::move(message));
        }
    }
public:
    ReceiveWorker()=default;
    ReceiveWorker(const ReceiveWorker&)=delete;
    ~ReceiveWorker(){close();}
    bool start(const std::filesystem::path& workerPath,const std::filesystem::path& control,const std::filesystem::path& destination,DWORD ownerPid=0){
        control_=control;
        ownerPid_=ownerPid;
        SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};HANDLE inRead=nullptr,outWrite=nullptr,err=nullptr;
        auto cleanup=[&]{for(auto h:{inRead,outWrite,err})if(h&&h!=INVALID_HANDLE_VALUE)CloseHandle(h);};
        auto cleanup_parent=[&]{for(auto* h:{&input_,&output_})if(*h){CloseHandle(*h);*h=nullptr;}};
        if(!CreatePipe(&inRead,&input_,&sa,65536)||!CreatePipe(&output_,&outWrite,&sa,65536)||
           !SetHandleInformation(input_,HANDLE_FLAG_INHERIT,0)||!SetHandleInformation(output_,HANDLE_FLAG_INHERIT,0)){cleanup();cleanup_parent();return false;}
        err=CreateFileW((control/L"receive-worker-error.txt").c_str(),GENERIC_WRITE,FILE_SHARE_READ,&sa,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
        if(err==INVALID_HANDLE_VALUE){cleanup();cleanup_parent();return false;}
        const auto executable=workerPath.wstring();
        const auto directory=workerPath.parent_path();
        auto command=quote(executable)+
            L" --control "+quote(control.wstring())+L" --destination "+quote(destination.wstring());
        if(ownerPid)command+=L" --owner-pid "+std::to_wstring(ownerPid);
        try {
            const auto stage=create_stage(destination);
            if(stage.empty()){cleanup();cleanup_parent();return false;}
            command+=L" --staging "+quote(stage.wstring());
        } catch(const std::exception& e){
            std::cerr<<"receive staging initialization: "<<e.what()<<'\n';
            cleanup();cleanup_parent();return false;
        }
        STARTUPINFOEXW si{};si.StartupInfo.cb=sizeof(si);si.StartupInfo.dwFlags=STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput=inRead;si.StartupInfo.hStdOutput=outWrite;si.StartupInfo.hStdError=err;
        SIZE_T bytes=0;InitializeProcThreadAttributeList(nullptr,1,0,&bytes);
        std::vector<std::uint8_t> attributes(bytes);si.lpAttributeList=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
        if(!InitializeProcThreadAttributeList(si.lpAttributeList,1,0,&bytes)){cleanup();cleanup_parent();return false;}
        HANDLE inherited[]{inRead,outWrite,err};PROCESS_INFORMATION pi{};
        const bool updated=UpdateProcThreadAttribute(si.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited,sizeof(inherited),nullptr,nullptr)!=FALSE;
        const bool created=updated&&CreateProcessW(executable.c_str(),command.data(),nullptr,nullptr,TRUE,
            CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,nullptr,directory.c_str(),&si.StartupInfo,&pi)!=FALSE;
        DeleteProcThreadAttributeList(si.lpAttributeList);cleanup();if(!created){cleanup_parent();return false;}
        process_=pi.hProcess;CloseHandle(pi.hThread);
        writer_=std::thread([this]{write_loop();});reader_=std::thread([this]{read_loop();});return true;
    }
    // Only the radio thread enqueues frames. Once admitted, its whole TLS read
    // fits, even if the pipe writer makes no progress. Leave room for closes.
    bool can_queue_read(std::size_t maxBytes) {
        constexpr auto frame = receive_worker_protocol::MaxFrameBytes;
        constexpr auto closeReserve = receive_worker_protocol::MaxConnections * (9 + 1);
        if (maxBytes > queueLimit) return false;
        const auto needed = maxBytes + 9 * ((maxBytes + frame - 1) / frame) + closeReserve;
        std::lock_guard lock(mutex_);
        return needed <= queueLimit - writeBytes_;
    }
    bool send(std::uint8_t type,std::uint32_t id,std::span<const std::uint8_t> data={}){
        if(data.size()>receive_worker_protocol::MaxFrameBytes||!healthy()){
            std::wcerr<<L"receive_worker_send_unavailable type="<<unsigned(type)<<L" id="<<id
                      <<L" bytes="<<data.size()<<L'\n';
            return false;
        }
        std::vector<std::uint8_t> b(9+data.size());b[0]=type;
        for(unsigned i=0;i<4;++i){b[1+i]=std::uint8_t(id>>(8*i));b[5+i]=std::uint8_t(data.size()>>(8*i));}
        std::copy(data.begin(),data.end(),b.begin()+9);std::lock_guard lock(mutex_);
        if(stopping_||writeBytes_+b.size()>queueLimit){
            std::wcerr<<L"receive_worker_send_rejected type="<<unsigned(type)<<L" id="<<id
                      <<L" bytes="<<data.size()<<L" queued_bytes="<<writeBytes_<<L" stopping="<<stopping_<<L'\n';
            return false;
        }
        writeBytes_+=b.size();writes_.push_back(std::move(b));wake_.notify_one();return true;
    }
    std::deque<Message> take(){std::lock_guard lock(mutex_);auto r=std::move(reads_);reads_.clear();readBytes_=0;return r;}
    bool healthy()const{return process_&&!failed_&&WaitForSingleObject(process_,0)==WAIT_TIMEOUT;}
    bool close(){
        // File cancellation remains observable while the worker is inside a
        // bounded archive copy/decode loop and cannot yet consume pipe EOF.
        if(process_&&!control_.empty()){
            std::ofstream stop(control_ / dropporter::session_markers::ReceiveStopFileName,
                               std::ios::binary | std::ios::trunc);
            stop << dropporter::session_markers::ReceiveStopContent;
        }
        {std::lock_guard lock(mutex_);stopping_=true;}wake_.notify_all();
        bool clean=true;
        if(process_&&WaitForSingleObject(process_,5000)!=WAIT_OBJECT_0){clean=false;TerminateProcess(process_,1);WaitForSingleObject(process_,INFINITE);}
        if(process_){DWORD result=1;if(!GetExitCodeProcess(process_,&result)||result!=0)clean=false;}
        if(writer_.joinable())writer_.join();
        if(reader_.joinable())reader_.join();
        for(auto* h:{&input_,&output_,&process_})if(*h){CloseHandle(*h);*h=nullptr;}
        if(!clean_stage()){
            std::wcerr<<L"receive_staging_cleanup_failed\n";
            clean=false;
        }
        return clean;
    }
};
}
