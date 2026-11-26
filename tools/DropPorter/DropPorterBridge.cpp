#include "DropPorterApplication.h"
#include "DropPorterBridgeIds.h"
#include "DropPorterBroker.h"
#include <array>
#include <cstring>
#include <future>
#include <memory>
#include <thread>
#include <wlanapi.h>

#pragma comment(lib, "wlanapi.lib")

using namespace dropporter;
namespace {
constexpr int ControlFieldCount=static_cast<int>(TextField::ItemLabel);
constexpr int ResultFieldCount=static_cast<int>(TextField::OfferPreviewPath)-static_cast<int>(TextField::ResultTitle)+1;
constexpr bool IsTransferMode(TransferMode mode) {
    return mode==TransferMode::Send || mode==TransferMode::Receive;
}

bool HasConnectedWifi() noexcept {
    HANDLE client = nullptr;
    DWORD version = 0;
    if (WlanOpenHandle(2, nullptr, &version, &client) != ERROR_SUCCESS) return false;

    PWLAN_INTERFACE_INFO_LIST interfaces = nullptr;
    bool connected = false;
    if (WlanEnumInterfaces(client, nullptr, &interfaces) == ERROR_SUCCESS) {
        for (DWORD i = 0; i < interfaces->dwNumberOfItems; ++i) {
            if (interfaces->InterfaceInfo[i].isState == wlan_interface_state_connected) {
                connected = true;
                break;
            }
        }
        WlanFreeMemory(interfaces);
    }
    WlanCloseHandle(client, nullptr);
    return connected;
}
static_assert(static_cast<int>(TextField::ChooseFile)==static_cast<int>(TransferField::ChooseFile));
static_assert(static_cast<int>(TextField::PrimaryAction)==static_cast<int>(TransferField::PrimaryAction));
static_assert(static_cast<int>(TextField::Cancel)==static_cast<int>(TransferField::Cancel));
static_assert(static_cast<int>(TextField::FilePath)==static_cast<int>(TransferField::FilePath));
static_assert(static_cast<int>(TextField::Status)==static_cast<int>(TransferField::Status));
static_assert(static_cast<int>(TextField::Details)==static_cast<int>(TransferField::Details));
static_assert(static_cast<int>(TextField::Target)==static_cast<int>(TransferField::Target));
static_assert(static_cast<int>(TextField::Files)==static_cast<int>(TransferField::Files));
static_assert(static_cast<int>(TextField::OpenFile)==static_cast<int>(TransferField::OpenFile));
static_assert(static_cast<int>(TextField::OpenFolder)==static_cast<int>(TransferField::OpenFolder));
// Keep overlapped storage and its pipe alive until cancellation has actually
// completed. Cancelling a request does not prove that the runtime was not started.
struct BrokerTransaction {
    UniqueHandle pipe,event{CreateEventW(nullptr,TRUE,FALSE,nullptr)};
    OVERLAPPED io{};
    std::vector<BYTE> message;
    broker::Reply reply{};
    DWORD bytes=0;
    bool pending=false;
    bool cancelling=false;
    BrokerTransaction() {io.hEvent=event.get();}
};
struct BrokerElevation {
    UniqueHandle process;
    DWORD error;
    std::int64_t startedUs{},returnedUs{};
    BrokerElevation(HANDLE handle,DWORD result):process(handle),error(result) {}
    BrokerElevation(BrokerElevation&& other) noexcept:process(other.process.release()),error(other.error),
        startedUs(other.startedUs),returnedUs(other.returnedUs) {}
};
struct PendingLaunch {
    std::wstring parameters, pipeName;
    std::future<BrokerElevation> elevation;
    std::jthread elevationThread;
    ULONGLONG deadline=0;
    bool restoreForeground=false;
};
struct Session;
struct View final : TransferView {
    Session& session;
    std::array<std::wstring,ControlFieldCount> text;
    std::array<std::wstring,ResultFieldCount> resultText;
    std::array<bool,ControlFieldCount> enabled{};
    std::vector<TargetRow> targets;
    std::vector<std::filesystem::path> files;
    int target=-1, file=-1;
    explicit View(Session& owner):session(owner) { enabled.fill(true); }
    void SetControlText(TransferField field,const std::wstring& value) override {text.at(static_cast<size_t>(field))=value;}
    void EnableControl(TransferField field,bool value) override {enabled.at(static_cast<size_t>(field))=value;}
    int SelectedTarget() const override {return target;}
    bool ShowTargets(const std::vector<TargetRow>& rows,int selected) override {targets=rows;target=selected;return true;}
    int SelectedSavedFile() const override {return file;}
    void ShowSavedFiles(const std::vector<std::filesystem::path>& paths,int selected) override {files=paths;file=selected;}
    bool StartPolling() override {return true;}
    void StopPolling() override {}
    std::optional<bool> LaunchRuntime(const std::filesystem::path&,const std::wstring&,HANDLE&,DWORD&) override;
    void OperationStarted() override;
    void OperationFinished(Operation,bool) override;
};
struct Session {
    HWND owner;
    DWORD thread=GetCurrentThreadId();
    ShareLifecycle lifecycle;
    View sendView{*this},receiveView{*this};
    SenderController send{lifecycle,sendView};
    ReceiverController receive{lifecycle,receiveView};
    bool closeReady=false;
    int resultTab=-1;
    unsigned resultRevision=0;
    unsigned depth=0;
    // Elevated launcher for this app run; closing the pipe ends it.
    UniqueHandle brokerProcess,brokerPipe;
    std::optional<PendingLaunch> pendingLaunch;
    std::unique_ptr<BrokerTransaction> brokerTransaction;
    bool launchStopRequested=false;
    std::wstring recoveryText;
    // Restores the Wi-Fi state this app run kept, on close or once the setting is off.
    UniqueHandle restoreProcess;
    std::filesystem::path restoreRequest;
    bool restoreCheckDue=true;
    // A send waiting for the listening receive to stop, then started by Poll.
    bool sendAfterReceive=false,startSendDue=false,receiveBlockedSend=false;
    bool BeginRestore();
    void CompleteRestoreLaunch(bool launched,HANDLE process,DWORD error);
    void PollRestore();
    void FinishRestore(bool restored,int exitCode=1);
    void BeginLaunch(const std::filesystem::path& runtime,const std::wstring& parameters);
    void PollLaunch();
    std::optional<bool> AdvanceLaunch(HANDLE& process,DWORD& error);
    bool BeginBrokerTransaction(DWORD& error);
    void RestoreForeground();
    explicit Session(HWND window):owner(window) {
        sendView.text[static_cast<size_t>(TextField::PrimaryAction)]=L"送信先を探す";
        sendView.text[static_cast<size_t>(TextField::Cancel)]=L"キャンセル";
        sendView.text[static_cast<size_t>(TextField::Status)]=send.Status();
        sendView.enabled[static_cast<size_t>(TextField::PrimaryAction)]=sendView.enabled[static_cast<size_t>(TextField::Cancel)]=sendView.enabled[static_cast<size_t>(TextField::Target)]=false;
        receiveView.text[static_cast<size_t>(TextField::FilePath)]=receive.ReceiveFolder();
        receiveView.text[static_cast<size_t>(TextField::Status)]=receive.Status();
        receive.RefreshControls();
    }
    void Availability() {
        // A receive that only waits for a sender gives way to a send.
        const bool receiveBlocksSend=lifecycle.active==Operation::Receive && !receive.CanYieldToSend();
        if(sendAfterReceive) send.WaitForReceiveStop();
        else send.SetOtherModeBusy(receiveBlocksSend||lifecycle.active==Operation::Restore);
        receive.SetOtherModeBusy(lifecycle.active==Operation::Send||lifecycle.active==Operation::Restore);
    }
    bool RequestClose() {
        if(lifecycle.active==Operation::None && depth==0) {
            // Close after the Wi-Fi state this app run kept is restored.
            if(!BeginRestore()) return true;
            lifecycle.closeRequested=true;
            return false;
        }
        lifecycle.closeRequested=true;
        if(lifecycle.active!=Operation::Restore) RequestLaunchStop();
        return false;
    }
    void RequestLaunchStop() {
        launchStopRequested=true;
        if(lifecycle.active==Operation::Send) send.RequestHostClose();
        if(lifecycle.active==Operation::Receive) receive.RequestHostClose();
        if(send.IsStarting() || receive.IsStarting()) {
            auto& view=lifecycle.active==Operation::Send?sendView:receiveView;
            view.EnableControl(TransferField::Cancel,false);
            view.SetControlText(TransferField::Status,L"準備を中止しています。");
        }
    }
};
void View::OperationStarted() { session.Availability(); }
void View::OperationFinished(Operation operation,bool restored) {
    const bool closeWasRequested=session.lifecycle.closeRequested;
    session.closeReady=session.lifecycle.Finish(restored);
    session.restoreCheckDue=true;
    if(operation==Operation::Receive && session.sendAfterReceive) {
        session.sendAfterReceive=false;
        session.startSendDue=!session.lifecycle.closeRequested && !closeWasRequested;
    }
    // The finished transfer may have kept its state; restore it before closing.
    if(session.closeReady && session.BeginRestore()) {
        session.closeReady=false;
        session.lifecycle.closeRequested=true;
    }
    if(closeWasRequested && !session.closeReady) {
        session.resultTab=static_cast<int>(operation==Operation::Send?TransferMode::Send:TransferMode::Receive);
        ++session.resultRevision;
    }
    session.Availability();
}
BrokerElevation ElevateBroker(HWND owner,const std::filesystem::path& runtime,const std::wstring& parameters) {
    const HRESULT initialized=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED|COINIT_DISABLE_OLE1DDE);
    if(FAILED(initialized)) return {nullptr,ERROR_GEN_FAILURE};
    struct Apartment {~Apartment(){CoUninitialize();}} apartment;
    SHELLEXECUTEINFOW launch{};
    launch.cbSize=sizeof(launch);launch.fMask=SEE_MASK_NOCLOSEPROCESS|SEE_MASK_NOASYNC;
    launch.hwnd=owner;launch.lpVerb=L"runas";launch.lpFile=runtime.c_str();
    launch.lpParameters=parameters.c_str();
    const auto directory=runtime.parent_path().wstring();launch.lpDirectory=directory.c_str();launch.nShow=SW_HIDE;
    if(!ShellExecuteExW(&launch)) return {nullptr,GetLastError()};
    if(!launch.hProcess) return {nullptr,ERROR_INVALID_HANDLE};
    return {launch.hProcess,ERROR_SUCCESS};
}
void Session::BeginLaunch(const std::filesystem::path& runtime,const std::wstring& parameters) {
    PendingLaunch next;
    next.parameters=parameters;
    if(!brokerPipe || WaitForSingleObject(brokerProcess.get(),0)!=WAIT_TIMEOUT) {
        brokerPipe.reset();brokerProcess.reset();
        const auto token=NewToken();
        if(!token) throw std::runtime_error("broker token unavailable");
        const auto arguments=L"--broker "+std::to_wstring(GetCurrentProcessId())+L" "+*token;
        next.pipeName=broker::PipeName(*token);
        next.restoreForeground=owner && GetForegroundWindow()==owner;
        // Use a dedicated STA so shell activation does not occupy the UI thread
        // or inherit a thread-pool thread's COM apartment.
        std::packaged_task<BrokerElevation()> elevate([window=owner,runtime,arguments] {
            const auto started=discovery_timing::NowUs();
            auto result=ElevateBroker(window,runtime,arguments);
            result.startedUs=started;
            result.returnedUs=discovery_timing::NowUs();
            return result;
        });
        next.elevation=elevate.get_future();
        next.elevationThread=std::jthread([task=std::move(elevate)]() mutable {
            task.make_ready_at_thread_exit();
        });
    } else if(lifecycle.active==Operation::Send) send.LogDiscoveryTiming("broker_reused");
    launchStopRequested=false;
    pendingLaunch.emplace(std::move(next));
}
void Session::RestoreForeground() {
    if(pendingLaunch->restoreForeground && IsWindowVisible(owner) && !IsIconic(owner)) SetForegroundWindow(owner);
    pendingLaunch->restoreForeground=false;
}
bool Session::BeginBrokerTransaction(DWORD& error) {
    const auto& parameters=pendingLaunch->parameters;
    auto transaction=std::make_unique<BrokerTransaction>();
    if(!transaction->event) {error=GetLastError();return false;}
    const broker::RequestHeader header{broker::kRequestMagic,static_cast<DWORD>(parameters.size())};
    transaction->message.resize(sizeof(header)+parameters.size()*sizeof(wchar_t));
    std::memcpy(transaction->message.data(),&header,sizeof(header));
    std::memcpy(transaction->message.data()+sizeof(header),parameters.data(),parameters.size()*sizeof(wchar_t));
    transaction->pipe.reset(brokerPipe.release());
    brokerTransaction=std::move(transaction);
    auto& request=*brokerTransaction;
    const auto requestSentAt=discovery_timing::NowUs();
    const bool completed=TransactNamedPipe(request.pipe.get(),request.message.data(),static_cast<DWORD>(request.message.size()),
        &request.reply,sizeof(request.reply),&request.bytes,&request.io)!=FALSE;
    request.pending=!completed && GetLastError()==ERROR_IO_PENDING;
    if(!completed) request.bytes=0;
    pendingLaunch->deadline=GetTickCount64()+broker::kReplyTimeoutMs;
    if(lifecycle.active==Operation::Send)send.LogDiscoveryTiming("broker_request_sent",requestSentAt);
    return true;
}
std::optional<bool> Session::AdvanceLaunch(HANDLE& process,DWORD& error) {
    auto& launch=*pendingLaunch;
    if(launch.elevation.valid()) {
        if(launch.elevation.wait_for(std::chrono::seconds(0))!=std::future_status::ready) return std::nullopt;
        auto result=launch.elevation.get();
        if(lifecycle.active==Operation::Send) {
            send.LogDiscoveryTiming("broker_elevation_started",result.startedUs);
            send.LogDiscoveryTiming("broker_elevation_returned",result.returnedUs);
        }
        brokerProcess.reset(result.process.release());
        if(!brokerProcess) {error=result.error;return false;}
        launch.deadline=GetTickCount64()+broker::kConnectTimeoutMs;
    }
    if(!brokerTransaction) {
        if(launchStopRequested) {error=ERROR_CANCELLED;return false;}
        if(!brokerPipe) {
            const auto peer=WaitForSingleObject(brokerProcess.get(),0);
            if(peer!=WAIT_TIMEOUT || GetTickCount64()>=launch.deadline) {
                error=peer==WAIT_TIMEOUT?ERROR_TIMEOUT:ERROR_PROCESS_ABORTED;return false;
            }
            const HANDLE pipe=CreateFileW(launch.pipeName.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr);
            if(pipe==INVALID_HANDLE_VALUE) {
                error=GetLastError();
                if(error==ERROR_FILE_NOT_FOUND || error==ERROR_PIPE_BUSY) return std::nullopt;
                return false;
            }
            UniqueHandle connection(pipe);
            ULONG server=0;
            DWORD mode=PIPE_READMODE_MESSAGE;
            if(!GetNamedPipeServerProcessId(pipe,&server) || server!=GetProcessId(brokerProcess.get())) {
                error=ERROR_ACCESS_DENIED;return false;
            }
            if(!SetNamedPipeHandleState(pipe,&mode,nullptr,nullptr)) {error=GetLastError();return false;}
            brokerPipe.reset(connection.release());
            if(lifecycle.active==Operation::Send)send.LogDiscoveryTiming("broker_pipe_connected");
            // The broker grants activation back before publishing the pipe.
            RestoreForeground();
        }
        if(!BeginBrokerTransaction(error)) return false;
    }

    auto& request=*brokerTransaction;
    if(request.pending) {
        if(WaitForSingleObject(request.event.get(),0)!=WAIT_OBJECT_0) {
            // Stop requests write the transfer's cancellation marker. Keep
            // waiting for its process handle so restoration can be observed.
            if(!request.cancelling && (GetTickCount64()>=launch.deadline ||
                WaitForSingleObject(brokerProcess.get(),0)!=WAIT_TIMEOUT)) {
                (void)CancelIoEx(request.pipe.get(),&request.io);
                request.cancelling=true;
            }
            return std::nullopt;
        }
        if(!GetOverlappedResult(request.pipe.get(),&request.io,&request.bytes,FALSE)) request.bytes=0;
    }
    if(request.bytes!=sizeof(request.reply) || request.reply.magic!=broker::kReplyMagic) {
        brokerTransaction.reset();
        brokerProcess.reset();
        // An issued request may have succeeded. Keep the operation active and
        // request cancellation even if the process handle could not be obtained.
        return true;
    }
    const auto reply=request.reply;
    brokerPipe.reset(request.pipe.release());
    brokerTransaction.reset();
    error=reply.error;
    if(error!=ERROR_SUCCESS) return false;
    process=reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(reply.process));
    return true;
}
void Session::PollLaunch() {
    if(!pendingLaunch) return;
    HANDLE process=nullptr;
    DWORD error=ERROR_SUCCESS;
    std::optional<bool> launched;
    try {launched=AdvanceLaunch(process,error);}
    catch(...) {launched=false;error=ERROR_GEN_FAILURE;}
    if(!launched) return;
    if(!*launched && !brokerPipe) brokerProcess.reset();
    RestoreForeground();
    pendingLaunch.reset();
    if(lifecycle.active==Operation::Send) send.CompleteLaunch(*launched,process,error);
    else if(lifecycle.active==Operation::Restore) CompleteRestoreLaunch(*launched,process,error);
    else receive.CompleteLaunch(*launched,process,error);
}
bool Session::BeginRestore() {
    if(lifecycle.active!=Operation::None || pendingLaunch) return false;
    const auto kept=FindKeptRadioSession(UserSessionDirectory(),GetCurrentProcessId());
    const auto runtime=FindRuntimeExecutable();
    if(!kept || !runtime || !lifecycle.TryBegin(Operation::Restore)) return false;
    restoreRequest=*kept;
    Availability();
    try {BeginLaunch(*runtime,L"--recover "+QuoteWindowsArgument(kept->wstring()));}
    catch(...) {FinishRestore(false);return false;}
    return true;
}
void Session::CompleteRestoreLaunch(bool launched,HANDLE process,DWORD) {
    if(launched && process) {restoreProcess.reset(process);return;}
    if(process) CloseHandle(process);
    FinishRestore(false);
}
void Session::PollRestore() {
    if(!restoreProcess || WaitForSingleObject(restoreProcess.get(),0)!=WAIT_OBJECT_0) return;
    DWORD exitCode=1;
    if(!GetExitCodeProcess(restoreProcess.get(),&exitCode)) exitCode=1;
    restoreProcess.reset();
    FinishRestore(exitCode==0,static_cast<int>(exitCode));
}
void Session::FinishRestore(bool restored,int exitCode) {
    if(restored) {
        (void)WriteNewFile(restoreRequest.parent_path()/session_markers::RecoveryCompletedFileName,
            session_markers::RecoveryCompletedContent);
    } else {
        // A failed restore turns the kept state into a regular Wi-Fi recovery case.
        const auto result=std::string(supervisor::FailureReasonKey)+'='+supervisor::RecoveryFailureReason(exitCode)+'\n';
        (void)PublishLocalFile(restoreRequest.parent_path()/supervisor::RecoveryResultFileName,result,true);
    }
    closeReady=lifecycle.Finish(restored);
    restoreCheckDue=false;
    Availability();
}
std::optional<bool> View::LaunchRuntime(const std::filesystem::path& runtime,const std::wstring& parameters,HANDLE& process,DWORD& error) {
    process=nullptr;
    if(parameters.empty() || parameters.size()>broker::kMaxParameterChars) {error=ERROR_FILENAME_EXCED_RANGE;return false;}
    try {session.BeginLaunch(runtime,parameters);}
    catch(...) {error=ERROR_GEN_FAILURE;return false;}
    EnableControl(TransferField::Cancel,true);
    return std::nullopt;
}
Session* Checked(void* handle) {
    auto* session=static_cast<Session*>(handle);
    return session && session->thread==GetCurrentThreadId()?session:nullptr;
}
}
// All calls belong to the creating STA/UI thread. Text pointers remain valid until
// the next command; the managed adapter copies them before making another call.
extern "C" __declspec(dllexport) void* DD_Create(HWND owner) noexcept {
    try {return new Session(owner);} catch(...) {return nullptr;}
}
extern "C" __declspec(dllexport) int DD_Destroy(void* handle) noexcept {
    auto* s=Checked(handle);
    if(!s || s->depth || s->pendingLaunch || s->lifecycle.active!=Operation::None) return 0;
    delete s;return 1;
}
extern "C" __declspec(dllexport) int DD_Command(void* handle,int modeId,int commandId,const wchar_t* path,int index) noexcept {
    const auto mode=static_cast<TransferMode>(modeId);
    auto* s=Checked(handle);if(!s || !IsTransferMode(mode)) return -1;
    const auto command=static_cast<BridgeCommand>(commandId);
    if(command==BridgeCommand::RequestClose) {try {return s->RequestClose()?1:0;}catch(...){return -1;}}
    if(s->depth) return 0;
    struct Scope {Session& s;explicit Scope(Session& v):s(v){++s.depth;}~Scope(){--s.depth;if(!s.depth && s.lifecycle.active==Operation::None && s.lifecycle.closeRequested){s.closeReady=true;s.lifecycle.closeRequested=false;}}} scope(*s);
    try {
        auto& view=mode==TransferMode::Send?s->sendView:s->receiveView;
        const auto openReceiveFolder = [&](const wchar_t* folder) {
            if (*folder && reinterpret_cast<INT_PTR>(ShellExecuteW(s->owner, L"open", folder, nullptr, nullptr, SW_SHOWNORMAL)) <= 32)
                s->receive.ReportUiError(L"保存先フォルダーを開けませんでした。");
        };
        switch(command) {
        case BridgeCommand::Poll:
            s->PollLaunch();s->send.PollChild();s->receive.PollChild();s->PollRestore();
            if(s->startSendDue && s->lifecycle.active==Operation::None && !s->pendingLaunch) {
                s->startSendDue=false;
                s->send.StartSend();
            }
            // An offer arriving makes the listening receive no longer give way.
            if(const bool blocks=s->lifecycle.active==Operation::Receive && !s->receive.CanYieldToSend();
               blocks!=s->receiveBlockedSend) {
                s->receiveBlockedSend=blocks;
                s->Availability();
            }
            // Restore a kept state as soon as the setting is off and nothing runs.
            if(s->restoreCheckDue && s->lifecycle.active==Operation::None && !s->pendingLaunch) {
                s->restoreCheckDue=false;
                if(!KeepRadioPreference()) s->BeginRestore();
            }
            break;
        case BridgeCommand::SetKeepRadio:
            if(index!=0 && index!=1) return -1;
            if(!PersistKeepRadioPreference(index==1)) return 0;
            s->restoreCheckDue=true;
            break;
        case BridgeCommand::SelectPath: if(path) {if(mode==TransferMode::Send)s->send.SelectFile(path);else s->receive.SelectReceiveFolder(path);}break;
        case BridgeCommand::Start:
            if(index!=-1 && index!=1)return -1;
            if(mode==TransferMode::Send && s->lifecycle.active==Operation::Receive && !s->send.IsRunning() &&
               !s->send.IsStarting() && !s->send.SelectedFiles().empty()) {
                // Stop a receive that is only waiting, then search for the send target.
                if(!s->sendAfterReceive && s->receive.StopWaitingForSend()) s->sendAfterReceive=true;
                s->Availability();
                break;
            }
            if(mode==TransferMode::Send)s->send.StartSend();else s->receive.StartReceive();
            break;
        case BridgeCommand::Cancel:
            if(mode==TransferMode::Send?s->send.IsStarting():s->receive.IsStarting()) s->RequestLaunchStop();
            else if(mode==TransferMode::Send) s->send.RequestCancel();
            else if(s->receive.HasIncoming()) s->receive.SubmitDecision(false);
            else s->receive.RequestCancel();
            break;
        case BridgeCommand::SelectItem:
            if(mode==TransferMode::Send) {view.target=index>=0&&static_cast<size_t>(index)<view.targets.size()?index:-1;s->send.TargetSelectionChanged();}
            else {view.file=index>=0&&static_cast<size_t>(index)<view.files.size()?index:-1;s->receive.RefreshControls();}
            break;
        case BridgeCommand::RefreshTargets: if(mode==TransferMode::Send)s->send.RefreshTargets();break;
        case BridgeCommand::SendToPeer: {
            if(mode!=TransferMode::Send || !path)return -1;
            const auto mac=Utf8(path);
            if(!IsTargetPeerMac(mac))return -1;
            if(!s->send.CanRefreshTargets())return 0;
            int match=-1;
            for(size_t i=0;i<view.targets.size();++i) {
                if(view.targets[i].peerMac!=mac)continue;
                if(match>=0)return -1;
                match=static_cast<int>(i);
            }
            if(match<0)return 0;
            view.target=match;
            s->send.SubmitTarget();
            return s->send.CanRefreshTargets() ? -1 : 1;
        }
        case BridgeCommand::RespondToOffer: {
            const auto decision=static_cast<OfferDecision>(index);
            if(mode==TransferMode::Receive && path && (decision==OfferDecision::Reject || decision==OfferDecision::Accept))
                s->receive.SubmitNotificationDecision(path,decision==OfferDecision::Accept);
            break;
        }
        case BridgeCommand::SelectSendFiles:
            if(mode==TransferMode::Send && path && s->send.CanChooseFiles()) {
                std::vector<std::filesystem::path> files;
                try {files = tx10ub::send_files::PathsFromLines(path);}
                catch(const std::length_error&) {s->send.ReportUiError(SendFileCountLimit);break;}
                catch(const std::invalid_argument&) {s->send.ReportUiError(L"ファイルを選び直してください。");break;}
                s->send.SelectFiles(std::move(files));
            }
            break;
        case BridgeCommand::RecordRecoveryCompleted: {
            if (mode != TransferMode::Send || !path) return -1;
            const std::filesystem::path request(path);
            if (!request.is_absolute() || request.filename() != request_file::FileName) return -1;
            return WriteNewFile(request.parent_path() / session_markers::RecoveryCompletedFileName,
                                session_markers::RecoveryCompletedContent) ? 1 : 0;
        }
        case BridgeCommand::DismissRecovery:
        case BridgeCommand::RecordRecoveryFailure: {
            if (mode != TransferMode::Send || !path) return -1;
            const std::filesystem::path request(path);
            const auto directory = request.parent_path();
            if (!request.is_absolute() || request.filename() != request_file::FileName ||
                directory.parent_path() != UserSessionDirectory() ||
                !request_file::ValidDirectory(directory.filename().native())) return -1;
            if (command == BridgeCommand::DismissRecovery) {
                return PublishLocalFile(directory / session_markers::RecoveryDismissedFileName,
                                        session_markers::RecoveryDismissedContent, true) ? 1 : 0;
            }
            const auto result = std::string(supervisor::FailureReasonKey) + '=' +
                supervisor::RecoveryFailureReason(index) + '\n';
            return PublishLocalFile(directory / supervisor::RecoveryResultFileName, result, true) ? 1 : 0;
        }
        case BridgeCommand::OpenFile: {
            const auto file=s->receive.SelectedFileToOpen();
            if(file) {
                SHELLEXECUTEINFOW open{};open.cbSize=sizeof(open);open.fMask=SEE_MASK_NOASYNC|SEE_MASK_FLAG_NO_UI;
                open.hwnd=s->owner;open.lpVerb=L"open";open.lpFile=file->c_str();open.nShow=SW_SHOWNORMAL;
                if(!ShellExecuteExW(&open)) s->receive.ReportUiError(L"ファイルを開けませんでした。");
            }break;
        }
        case BridgeCommand::OpenFolder:
            openReceiveFolder(s->receive.ReceiveFolder().c_str());
            break;
        case BridgeCommand::ShowInFolder: {
            if (s->receiveView.SelectedSavedFile() < 0) {
                if (const auto folder = s->receive.SavedFilesFolder())
                    openReceiveFolder(folder->c_str());
                break;
            }
            // Same validated saved-file path as "open"; Explorer selects it in its folder.
            const auto file=s->receive.SelectedFileToOpen();
            if(file) {
                PIDLIST_ABSOLUTE item=ILCreateFromPathW(file->c_str());
                const bool shown=item && SUCCEEDED(SHOpenFolderAndSelectItems(item,0,nullptr,0));
                if(item) ILFree(item);
                if(!shown) s->receive.ReportUiError(L"フォルダーを開けませんでした。");
            }break;
        }
        default:return -1;
        }
        return 1;
    } catch(...) {
        try {if(mode==TransferMode::Send)s->send.ReportUiError(L"処理中に問題が発生しました。");else s->receive.ReportUiError(L"処理中に問題が発生しました。");}catch(...){}
        return -1;
    }
}
extern "C" __declspec(dllexport) int DD_Value(void* handle,int modeId,int kind,int field) noexcept {
    const auto mode=static_cast<TransferMode>(modeId);
    const auto* s=Checked(handle);if(!s || !IsTransferMode(mode))return -1;
    const auto& v=mode==TransferMode::Send?s->sendView:s->receiveView;
    switch(static_cast<ValueKind>(kind)) {
    case ValueKind::ControlEnabled:return field>=0&&field<ControlFieldCount?v.enabled[static_cast<size_t>(field)]:0;
    case ValueKind::ItemCount:return static_cast<int>(mode==TransferMode::Send?v.targets.size():v.files.size());
    case ValueKind::SelectedItem:return mode==TransferMode::Send?v.target:v.file;
    case ValueKind::CloseReady:return s->closeReady;
    case ValueKind::ResultRevision:return static_cast<int>(s->resultRevision);
    case ValueKind::ResultTab:return s->resultTab;
    case ValueKind::HasIncoming:return mode==TransferMode::Receive&&s->receive.HasIncoming();
    // Closing now would stop a send or an offered/in-progress receive.
    case ValueKind::ConfirmClose:return s->send.IsRunning()||s->send.IsStarting()||s->receive.HasIncoming()||s->receive.IsReceiving();
    case ValueKind::ShowSearchHelp:return mode==TransferMode::Send&&s->send.ShowsSearchHelp();
    case ValueKind::Activity:return static_cast<int>(mode==TransferMode::Send?s->send.Activity():s->receive.Activity());
    case ValueKind::CanRefreshTargets:return mode==TransferMode::Send&&s->send.CanRefreshTargets();
    case ValueKind::SendFileCount:return mode==TransferMode::Send?static_cast<int>(s->send.SelectedFiles().size()):0;
    case ValueKind::TransferActive:return s->lifecycle.active!=Operation::None || s->depth!=0;
    case ValueKind::ShowDriverHelp:return mode==TransferMode::Send?s->send.Result().showDriverHelp:s->receive.Result().showDriverHelp;
    case ValueKind::ShowRecoveryDriverHelp:
        return mode == TransferMode::Send &&
            field == static_cast<int>(supervisor::RecoveryExit::UnsupportedDriver);
    case ValueKind::WifiConnected: return mode == TransferMode::Send && HasConnectedWifi();
    case ValueKind::OfferFileCount: return mode == TransferMode::Receive ? static_cast<int>(s->receive.OfferFileCount()) : 0;
    case ValueKind::SendCompleted: return mode==TransferMode::Send && s->send.SendCompleted();
    case ValueKind::KeepRadio: return KeepRadioPreference();
    case ValueKind::RestoringRadio: return s->lifecycle.active==Operation::Restore;
    default:return -1;
    }
}
extern "C" __declspec(dllexport) const wchar_t* DD_Text(void* handle,int modeId,int fieldId,int index) noexcept {
    const auto mode=static_cast<TransferMode>(modeId);
    auto* s=Checked(handle);if(!s || !IsTransferMode(mode))return L"";
    auto& v=mode==TransferMode::Send?s->sendView:s->receiveView;
    const auto field=static_cast<TextField>(fieldId);
    if (mode == TransferMode::Send && field == TextField::RecoveryFailureMessage)
        return RecoveryFailureText(supervisor::RecoveryFailureReason(index));
    if (mode==TransferMode::Send && (field==TextField::RecoveryRequestPath || field==TextField::RuntimePath)) {
        try {
            const auto path=field==TextField::RecoveryRequestPath?FindPendingWifiRecovery(UserSessionDirectory(),GetCurrentProcessId()):FindRuntimeExecutable();
            s->recoveryText=path?path->wstring():L"";
            return s->recoveryText.c_str();
        } catch (...) {return L"";}
    }
    if(field>=TextField::ResultTitle && field<=TextField::OfferPreviewPath) {
        try {
            auto& text=v.resultText[static_cast<size_t>(fieldId-static_cast<int>(TextField::ResultTitle))];
            if(field==TextField::OfferPreviewPath) text=mode==TransferMode::Receive?s->receive.OfferPreviewPath():L"";
            else if(field==TextField::SendSelectionSize) text=mode==TransferMode::Send?s->send.SelectionSizeText():L"";
            else if(field==TextField::SendFilePath) {
                const auto& paths=s->send.SelectedFiles();
                return mode==TransferMode::Send&&index>=0&&static_cast<size_t>(index)<paths.size()?paths[index].c_str():L"";
            }
            else if(field==TextField::OfferExpiration) text=mode==TransferMode::Receive?s->receive.OfferExpiration():L"";
            else if(field==TextField::OfferToken) {
                const auto* offer=mode==TransferMode::Receive?s->receive.PendingOffer():nullptr;
                text=offer?std::wstring(offer->token.begin(),offer->token.end()):L"";
            }
            else if(field==TextField::OfferSize) text=mode==TransferMode::Receive?s->receive.OfferSizeText():L"";
            else {
                const auto result=mode==TransferMode::Send?s->send.Result():s->receive.Result();
                text=field==TextField::ResultTitle?result.title:field==TextField::ResultDetail?result.detail:result.restoration;
            }
            return text.c_str();
        } catch(...) {return L"";}
    }
    if(fieldId>=0 && fieldId<ControlFieldCount)return v.text[static_cast<size_t>(fieldId)].c_str();
    if(field==TextField::ItemLabel && index>=0) {
        if(mode==TransferMode::Send && static_cast<size_t>(index)<v.targets.size())return v.targets[index].label.c_str();
        if(mode==TransferMode::Receive && static_cast<size_t>(index)<v.files.size())return v.files[index].c_str();
    }
    if(field==TextField::ItemPeerAddress && mode==TransferMode::Send &&
       index>=0 && static_cast<size_t>(index)<v.targets.size()) {
        try {
            static thread_local std::wstring address;
            const auto& peer=v.targets[index].peerMac;
            address.assign(peer.begin(),peer.end());
            return address.c_str();
        } catch(...) {return L"";}
    }
    return L"";
}
// Returns 1 with the current byte counts while a send/receive reports measurable progress.
extern "C" __declspec(dllexport) int DD_Progress(void* handle,int modeId,unsigned long long* processed,unsigned long long* total) noexcept {
    const auto mode=static_cast<TransferMode>(modeId);
    const auto* s=Checked(handle);if(!s || !IsTransferMode(mode) || !processed || !total)return -1;
    try {
        const auto progress=mode==TransferMode::Send?s->send.Progress():s->receive.Progress();
        if(!progress)return 0;
        *processed=progress->processed;*total=progress->total;
        return 1;
    } catch(...) {return -1;}
}
