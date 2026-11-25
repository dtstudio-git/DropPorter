#include "DropPorterApplication.h"

namespace dropporter {

SenderController::SenderController(ShareLifecycle& lifecycle, TransferView& view) : lifecycle_(lifecycle), view_(view) {}

bool SenderController::CanRefreshTargets() const {return running_&&selectingTarget_&&targetRound_&&!targetSubmitted_&&!refreshingTargets_&&!cancellationRequested_;}

bool SenderController::CanChooseFiles() const noexcept {
    if (starting_ || otherModeBusy_) return false;
    if (!running_) return true;
    if (!childProcess_ || cancellationRequested_ || targetConfirmed_) return false;
    using supervisor::Phase;
    return phase_ == Phase::Unknown || phase_ == Phase::Preparing || phase_ == Phase::PreparingAdapter ||
        phase_ == Phase::PreparingNetwork || phase_ == Phase::PreparingRadio ||
        phase_ == Phase::Discovering || phase_ == Phase::Selecting;
}

bool SenderController::IsRunning() const noexcept { return running_; }

bool SenderController::IsStarting() const noexcept { return starting_; }

std::optional<TransferProgress> SenderController::Progress() const { return running_ ? progress_ : std::nullopt; }

TransferActivity SenderController::Activity() const {
    using supervisor::Phase;
    if (running_ && !cancellationRequested_ && phase_ == Phase::Selecting && targetSubmitted_)
        return TransferActivity::Working;
    if (running_ && !cancellationRequested_ && !targetSubmitted_ &&
        (phase_ == Phase::Discovering || (phase_ == Phase::Selecting && (refreshingTargets_ || targets_.empty()))))
        return TransferActivity::SearchingTargets;
    return ClassifyTransferActivity(running_, cancellationRequested_, phase_);
}

const TransferResultDisplay& SenderController::Result() const {return result_;}

bool SenderController::ShowsSearchHelp(std::chrono::steady_clock::time_point now) const noexcept {
    if (!running_) return showSearchHelpAfterResult_;
    return !cancellationRequested_ && !targetSubmitted_ && targets_.empty() && searchStarted_ &&
        (phase_ == supervisor::Phase::Discovering || phase_ == supervisor::Phase::Selecting || phase_ == supervisor::Phase::Restoring) &&
        now - *searchStarted_ >= std::chrono::seconds(12);
}

const std::wstring& SenderController::Status() const noexcept { return currentStatus_; }

void SenderController::ReportUiError(std::wstring message) {
    if (running_) {
        currentDetails_ = std::move(message);
        view_.SetControlText(TransferField::Details, currentDetails_);
    } else {
        result_ = {};
        currentStatus_ = std::move(message);
        view_.SetControlText(TransferField::Status, currentStatus_);
    }
}

void SenderController::SelectFile(const std::filesystem::path& path) {
    SelectFiles({path});
}

const std::vector<std::filesystem::path>& SenderController::SelectedFiles() const noexcept { return selectedFiles_; }

std::wstring SenderController::SelectionSizeText() const {
    return selectedBytes_ ? L"合計 " + FormatBytes(*selectedBytes_) : L"";
}

void SenderController::SelectFiles(std::vector<std::filesystem::path> paths) {
    if (!CanChooseFiles()) return;
    std::wstring error;
    std::uint64_t bytes = 0;
    const bool valid = ValidateSelectedFiles(paths, bytes, error);
    if (running_ && !paths.empty() && !valid) {
        ReportUiError(std::move(error));
        return;
    }

    selectedFiles_=std::move(paths);
    view_.SetControlText(TransferField::FilePath,selectedFiles_.empty()?L"":selectedFiles_.front().wstring());
    selectedBytes_=valid?std::optional<std::uint64_t>(bytes):std::nullopt;
    showSearchHelpAfterResult_ = false;
    if (!running_) {
        result_ = {};
        currentStatus_ = std::move(error);
        view_.SetControlText(TransferField::Status, currentStatus_);
    }
    currentDetails_.clear();
    view_.SetControlText(TransferField::Details, currentDetails_);
    if (running_) TargetSelectionChanged();
    else view_.EnableControl(TransferField::PrimaryAction, valid);
}

void SenderController::TargetSelectionChanged() {
    view_.EnableControl(TransferField::PrimaryAction,
        CanRefreshTargets() && !otherModeBusy_ && selectedBytes_.has_value() && view_.SelectedTarget() >= 0);
}

void SenderController::StartSend() {
    if(CanRefreshTargets()){SubmitTarget();return;}
    if (running_ || starting_ || selectedFiles_.empty()) return;
    sendCompleted_=false;
    if (lifecycle_.active != Operation::None) {
        currentStatus_ = L"受信処理中です。受信を停止すると送信できます。";
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }
    targetSnapshot_.clear();targets_.clear();targetRound_=0;selectingTarget_=targetSubmitted_=false;
    targetConfirmed_ = false;
    initialTargetSelected_=false;
    refreshGeneration_=refreshSelection_=0;refreshingTargets_=false;
    view_.ShowTargets({}, -1);view_.EnableControl(TransferField::Target,FALSE);
    currentDetails_.clear();progress_.reset();phase_=supervisor::Phase::Unknown;result_={};
    searchStarted_.reset();showSearchHelpAfterResult_=false;
    view_.SetControlText(TransferField::Details, currentDetails_);
    std::wstring validationError;
    std::uint64_t bytes = 0;
    if (!ValidateSelectedFiles(selectedFiles_, bytes, validationError)) {
        selectedBytes_.reset();
        view_.EnableControl(TransferField::PrimaryAction, FALSE);
        currentStatus_ = validationError;
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }
    selectedBytes_ = bytes;

    const auto runtime = FindRuntimeExecutable();
    if (!runtime) {
        currentStatus_ = L"送信を開始できませんでした。配布ファイルをすべて展開し直してください。";
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }
    const auto artifacts = UserSessionDirectory();
    if (artifacts.empty()) {
        currentStatus_ = SendStartFailure;
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }

    std::error_code filesystemError;
    std::filesystem::create_directories(artifacts, filesystemError);
    if (filesystemError) {
        currentStatus_ = SendStartFailure;
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }

    std::wstring token;
    for (int attempt = 0; attempt < 8; ++attempt) {
        const auto generated = NewToken();
        if (!generated) break;
        token = *generated;
        requestDirectory_ = artifacts / request_file::Directory(token);
        if (CreateDirectoryW(requestDirectory_.c_str(), nullptr)) break;
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            requestDirectory_.clear();
            break;
        }
        requestDirectory_.clear();
        token.clear();
    }
    if (token.empty() || requestDirectory_.empty()) {
        currentStatus_ = SendStartFailure;
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }

    requestFile_ = requestDirectory_ / request_file::FileName;
    statusFile_ = requestDirectory_ / supervisor::StatusFileName;
    progressFile_ = requestDirectory_ / tx10ub::probe_events::ProgressFileName;
    resultFile_ = requestDirectory_ / supervisor::ResultFileName;
    cancelFile_ = requestDirectory_ / session_markers::CancelFileName;
    const auto candidateName = Utf8(request_file::Candidate(token));
    const std::string request = "{\n  " + request_file::Field(request_file::Mode) + '"' + request_file::SendMode +
        "\",\n  " + WideChannelRequestField() + request_file::Field(request_file::CandidateName) + '"' + candidateName +
        "\",\n  " + request_file::Field(request_file::OwnerPid) + std::to_string(GetCurrentProcessId()) + "\n}\n";
    if (!WriteNewFile(requestFile_, request)) {
        currentStatus_ = SendStartFailure;
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }

    const std::wstring parameters = L"--request " + QuoteWindowsArgument(requestFile_.wstring());
    if (parameters.size() > 32760) {
        currentStatus_ = L"送信を開始できませんでした。";
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }
    if (!lifecycle_.TryBegin(Operation::Send)) return;
    starting_ = true;
    view_.OperationStarted();
    view_.EnableControl(TransferField::ChooseFile, FALSE);
    view_.EnableControl(TransferField::PrimaryAction, FALSE);
    if (!view_.StartPolling()) {
        starting_ = false;
        view_.OperationFinished(Operation::Send, true);
        currentStatus_ = L"送信を開始できませんでした。Drop Porterを開き直してください。";
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }
    currentStatus_ = L"権限確認を待っています。";
    view_.SetControlText(TransferField::Status, currentStatus_);
    HANDLE process = nullptr;
    DWORD launchError = ERROR_SUCCESS;
    if (const auto launched = view_.LaunchRuntime(*runtime, parameters, process, launchError))
        CompleteLaunch(*launched, process, launchError);
}

void SenderController::CompleteLaunch(bool launched, HANDLE process, DWORD error) {
    if (!launched) {
        cancelAfterStart_ = false;
        view_.StopPolling();
        starting_ = false;
        view_.EnableControl(TransferField::Cancel, false);
        view_.OperationFinished(Operation::Send, true);
        currentStatus_ = error == ERROR_CANCELLED ? L"送信を開始しませんでした。" : SendStartFailure;
        view_.SetControlText(TransferField::Status, currentStatus_);
        view_.SetControlText(TransferField::Details, currentDetails_);
        return;
    }
    childProcess_.reset(process);
    starting_ = false;
    running_ = true;
    cancellationRequested_ = false;
    currentStatus_ = childProcess_ ? SendPhaseText(supervisor::Phase::Preparing,false) :
        L"送信の準備を中止します。";
    currentDetails_.clear();
    view_.EnableControl(TransferField::ChooseFile, CanChooseFiles());
    view_.EnableControl(TransferField::PrimaryAction, FALSE);
    view_.EnableControl(TransferField::Cancel, TRUE);
    view_.SetControlText(TransferField::Status, currentStatus_);
    view_.SetControlText(TransferField::Details, currentDetails_);
    if (!childProcess_) {
        currentDetails_ = L"この画面を開いたままお待ちください。";
        view_.SetControlText(TransferField::Details, currentDetails_);
        RequestCancel();
    }
    if (cancelAfterStart_) {
        cancelAfterStart_ = false;
        RequestCancel();
    }
}

void SenderController::RefreshTargets() {
    if(!CanRefreshTargets())return;
    const auto marker=target_files::RefreshName(refreshGeneration_ + 1);
    if(!PublishLocalFile(requestDirectory_ / marker, target_files::RefreshContent, false)) {
        currentDetails_=L"送信先を再読み込みできませんでした。";
        view_.SetControlText(TransferField::Details,currentDetails_);
        return;
    }
    const auto row=view_.SelectedTarget();
    refreshSelection_=row>=0&&static_cast<std::size_t>(row)<targets_.size()?targets_[row].id:0;
    ++refreshGeneration_;refreshingTargets_=true;
    view_.ShowTargets({},-1);
    view_.EnableControl(TransferField::PrimaryAction,false);view_.EnableControl(TransferField::Target,false);
    currentDetails_.clear();view_.SetControlText(TransferField::Details,currentDetails_);
    currentStatus_=L"送信先を再読み込みしています。";view_.SetControlText(TransferField::Status,currentStatus_);
}

void SenderController::SubmitTarget() {
    if (!CanRefreshTargets() || !selectedBytes_) return;
    const auto row=view_.SelectedTarget();
    if(row<0||static_cast<std::size_t>(row)>=targets_.size()||!targetRound_)return;
    std::wstring error;
    std::uint64_t bytes = 0;
    if (!ValidateSelectedFiles(selectedFiles_, bytes, error)) {
        ReportUiError(std::move(error));
        return;
    }
    std::string selection = std::to_string(targets_[row].id);
    for (const auto& file : selectedFiles_) {
        std::error_code pathError;
        const auto absolute = std::filesystem::absolute(file, pathError).lexically_normal();
        const auto path = absolute.native();
        const auto utf8 = Utf8(path);
        if (pathError || !tx10ub::send_files::ValidPath(path) || utf8.empty()) {
            ReportUiError(L"選択したファイルは送信できません。選び直してください。");
            return;
        }
        selection += '\n';
        selection += utf8;
    }
    const auto path=requestDirectory_/target_files::CommittedSelectionName;
    if (!PublishLocalFile(path, selection, false)) {
        currentDetails_=L"選んだ端末への送信を開始できませんでした。キャンセルしてから、もう一度お試しください。";
        view_.SetControlText(TransferField::Details,currentDetails_);return;
    }
    targetSubmitted_=true;
    targetConfirmed_=true;
    selectedBytes_ = bytes;
    currentDetails_.clear();
    view_.SetControlText(TransferField::Details, currentDetails_);
    view_.EnableControl(TransferField::ChooseFile,FALSE);
    view_.EnableControl(TransferField::Target,FALSE);view_.EnableControl(TransferField::PrimaryAction,FALSE);
    currentStatus_=L"選択したデバイスに接続しています。";
    view_.SetControlText(TransferField::Status,currentStatus_);
}

void SenderController::UpdateTargets() {
    if (targetSubmitted_) return;
    if(const auto text=ReadSmallTextFile(requestDirectory_/target_files::ListName);text&&*text!=targetSnapshot_) {
        if(auto list=ParseTargetList(*text);list&&list->refresh==refreshGeneration_) {
            const int current=view_.SelectedTarget();
            const auto selected=refreshingTargets_?refreshSelection_:
                current>=0&&static_cast<std::size_t>(current)<targets_.size()?targets_[current].id:0;
            refreshingTargets_=false;
            const auto sessions=UserSessionDirectory();
            if(!sessions.empty())ApplyRememberedTargetNames(sessions.parent_path()/L"target-names.txt",list->rows);
            targetSnapshot_=*text;targetRound_=list->round;targets_=std::move(list->rows);
            int next=-1;
            for(std::size_t i=0;i<targets_.size();++i) if(targets_[i].id==selected) next=static_cast<int>(i);
            const bool initial=!initialTargetSelected_&&!targets_.empty();
            if(initial) next=0;
            if(!view_.ShowTargets(targets_,next)) {targets_.clear();targetSnapshot_.clear();}
            else if(initial) initialTargetSelected_=true;
        }
    }
    view_.SetControlText(TransferField::PrimaryAction,L"送信");
    view_.EnableControl(TransferField::Target,CanRefreshTargets());
    TargetSelectionChanged();
}

void SenderController::RequestCancel() {
    if (!running_ || cancellationRequested_) return;
    if (!WriteCancelMarker(cancelFile_)) {
        currentStatus_ = L"送信を止められませんでした。まだ送信中なら、もう一度「キャンセル」を押してください。";
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }
    cancellationRequested_ = true;
    currentStatus_ = L"送信を中止しています。しばらくお待ちください。";
    view_.EnableControl(TransferField::ChooseFile,FALSE);
    view_.EnableControl(TransferField::Target,FALSE);
    view_.EnableControl(TransferField::PrimaryAction,FALSE);
    view_.EnableControl(TransferField::Cancel, FALSE);
    view_.SetControlText(TransferField::Status, currentStatus_);
}

void SenderController::PollChild() {
    if (!running_) return;
    if (!cancellationRequested_) {
        const auto status = ReadSmallTextFile(statusFile_);
        if (status) {
            const auto phase = supervisor::ParsePhase(supervisor::TrimStatus(*status));
            if (phase == supervisor::Phase::Restoring && phase_ != phase && !ShowsSearchHelp())
                searchStarted_.reset();
            phase_=phase;
            view_.EnableControl(TransferField::ChooseFile, CanChooseFiles());
            if (!searchStarted_ && (phase == supervisor::Phase::Discovering || phase == supervisor::Phase::Selecting))
                searchStarted_ = std::chrono::steady_clock::now();
            selectingTarget_=phase==supervisor::Phase::Selecting;
            if(selectingTarget_)UpdateTargets();
            else {view_.EnableControl(TransferField::Target,FALSE);view_.EnableControl(TransferField::PrimaryAction,FALSE);}
            auto label=SendPhaseText(phase,targetSubmitted_);
            if(refreshingTargets_&&(selectingTarget_||phase==supervisor::Phase::Discovering))label=L"送信先を再読み込みしています。";
            else if(selectingTarget_&&!targetSubmitted_&&targets_.empty()) label=L"送信先を探しています。";
            if (label != currentStatus_) {
                currentStatus_ = std::move(label);
                view_.SetControlText(TransferField::Status, currentStatus_);
            }
            if(phase==supervisor::Phase::Sending||phase==supervisor::Phase::Finalizing) {
                if(const auto progress=ReadSmallTextFile(progressFile_)) {
                    const auto values=ParseKeyValues(*progress);
                    if(const auto parsed=ParseSendProgress(values))progress_=TransferProgress{parsed->processed,parsed->total};
                    const auto details=SendProgressText(values);
                    if(!details.empty()&&details!=currentDetails_) {
                        currentDetails_=details;
                        view_.SetControlText(TransferField::Details,currentDetails_);
                    }
                }
            }
        }
    }
    if (!childProcess_) {
        if (HasFinalSupervisorResult(resultFile_)) FinishChild(ERROR_PROCESS_ABORTED);
        return;
    }
    const DWORD wait = WaitForSingleObject(childProcess_.get(), 0);
    if (wait == WAIT_OBJECT_0) {
        DWORD exitCode = ERROR_PROCESS_ABORTED;
        if (!GetExitCodeProcess(childProcess_.get(), &exitCode)) exitCode = ERROR_PROCESS_ABORTED;
        FinishChild(exitCode);
    }
}

void SenderController::FinishChild(DWORD exitCode) {
    view_.StopPolling();
    childProcess_.reset();
    running_ = false;progress_.reset();
    selectingTarget_=targetSubmitted_=false;view_.EnableControl(TransferField::Target,FALSE);
    view_.SetControlText(TransferField::PrimaryAction,L"送信先を探す");
    view_.EnableControl(TransferField::ChooseFile, TRUE);
    view_.EnableControl(TransferField::Cancel, FALSE);
    bool canCloseAfterCompletion = false;
    const auto resultText = ReadSmallTextFile(resultFile_);
    if (!resultText) {
        (void)exitCode;
        constexpr auto checkDelivery = L"送信が完了したかどうか、相手の端末で確認してください。";
        currentStatus_ = ResultStatus(checkDelivery, Restoration::Unknown);
        currentDetails_.clear();
        result_={checkDelivery,L"",RestorationDetail(Restoration::Unknown)};
        AppendLine(currentDetails_, RestorationDetail(Restoration::Unknown));
    } else {
        const auto result = ParseKeyValues(*resultText);
        const bool sent = IsOne(result, supervisor::TransferSucceededKey);
        const auto restoration = ClassifyRestoration(result);
        const auto finalStatus = supervisor::ParsePhase(Value(result, supervisor::StatusKey));
        const auto reason = std::string_view(Value(result, supervisor::FailureReasonKey));
        const auto stage = std::string_view(Value(result, supervisor::FailureStageKey));
        const bool notFound = !sent && finalStatus != supervisor::Phase::Cancelled && reason == "not_found";
        showSearchHelpAfterResult_ = notFound || (!sent && finalStatus != supervisor::Phase::Cancelled && targets_.empty() && reason == "timeout" &&
            (stage == "discovery" || stage == "select"));
        const auto title = sent ? L"送信完了" : finalStatus == supervisor::Phase::Cancelled ?
            L"送信をキャンセルしました。" : notFound ? L"送信先が見つかりませんでした。" : L"送信できませんでした。";
        currentStatus_ = ResultStatus(title, restoration);
        currentDetails_.clear();
        if (!sent && finalStatus != supervisor::Phase::Cancelled && !notFound) AppendLine(currentDetails_, SendFailureText(result));
        result_={title,currentDetails_,RestorationDetail(restoration),
            !sent && finalStatus == supervisor::Phase::Failed && reason == UnsupportedDriverReason};
        AppendLine(currentDetails_, RestorationDetail(restoration));
        canCloseAfterCompletion = !RestorationNeedsAttention(restoration);
        sendCompleted_ = sent && finalStatus == supervisor::Phase::Completed && canCloseAfterCompletion;
    }
    view_.EnableControl(TransferField::PrimaryAction, selectedBytes_.has_value());
    view_.SetControlText(TransferField::Status, currentStatus_);
    view_.SetControlText(TransferField::Details, currentDetails_);
    view_.OperationFinished(Operation::Send, canCloseAfterCompletion);
}

void SenderController::SetOtherModeBusy(bool busy) {
    otherModeBusy_ = busy;
    if (!running_ && !starting_) {
        view_.EnableControl(TransferField::ChooseFile, !busy);
        view_.EnableControl(TransferField::PrimaryAction, !busy && selectedBytes_.has_value());
    }
    view_.SetControlText(TransferField::Status, busy && !running_ && !starting_ ?
        L"受信処理中です。受信を停止すると送信できます。" : currentStatus_);
}

void SenderController::RequestHostClose() {
    if (starting_) {
        cancelAfterStart_ = true;
        if (!cancelFile_.empty()) (void)WriteCancelMarker(cancelFile_);
    }
    if (running_) RequestCancel();
}

}
