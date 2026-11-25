#include "DropPorterApplication.h"

namespace dropporter {

using tx10ub::receive_state::Phase;

ReceiverController::ReceiverController(ShareLifecycle& lifecycle, TransferView& view) : lifecycle_(lifecycle), view_(view), downloadsPath_(PreferredReceiveFolder()) {}

bool ReceiverController::IsRunning() const noexcept { return running_; }

bool ReceiverController::IsStarting() const noexcept { return starting_; }

const std::wstring& ReceiverController::Status() const noexcept { return currentStatus_; }

void ReceiverController::ReportUiError(std::wstring message) { result_={};liveResultVisible_=false;currentStatus_=std::move(message); view_.SetControlText(TransferField::Status,currentStatus_); }

const std::wstring& ReceiverController::ReceiveFolder() const noexcept { return downloadsPath_; }

bool ReceiverController::HasIncoming() const noexcept { return running_&&incoming_.has_value(); }

bool ReceiverController::IsReceiving() const noexcept { return running_&&receiveState_&&receiveState_->phase==Phase::Receiving; }

bool ReceiverController::WaitingForOffer() const noexcept {
    return running_ && !cancellationRequested_ && !incoming_ && supervisorPhase_ == supervisor::Phase::Listening &&
        receiveState_ && RecentlyDiscoveredForReceive(*receiveState_, GetTickCount64());
}

TransferActivity ReceiverController::Activity() const {
    if (running_ && !cancellationRequested_ && supervisorPhase_ != supervisor::Phase::Restoring) {
        if (incoming_) return decisionSubmitted_ ? TransferActivity::Working : TransferActivity::None;
        if (receiveState_ && receiveState_->phase == Phase::ApprovalPending) return TransferActivity::Working;
        if (WaitingForOffer()) return TransferActivity::Working;
    }
    return ClassifyTransferActivity(running_, cancellationRequested_, supervisorPhase_, IsReceiving());
}

std::size_t ReceiverController::OfferFileCount() const noexcept { return incoming_ ? incoming_->files.size() : 0; }
std::wstring ReceiverController::OfferSizeText() const { return incoming_ ? IncomingSizeText(*incoming_) : L""; }

const IncomingRequest* ReceiverController::PendingOffer() const noexcept {
    return HasIncoming() && !cancellationRequested_ && !decisionSubmitted_ ? &*incoming_ : nullptr;
}

std::wstring ReceiverController::OfferPreviewPath() const {
    const auto* offer = PendingOffer();
    if (!offer || !offer->hasPreview) return {};
    return (requestDirectory_ / receive_offer::PreviewName(offer->token)).wstring();
}

std::wstring ReceiverController::OfferExpiration() const {
    const auto* offer = PendingOffer();
    return offer && receiveState_ && receiveState_->phase == Phase::ApprovalPending &&
        receiveState_->token == offer->token ? receiveState_->expiresAtUtc : L"";
}

TransferResultDisplay ReceiverController::Result() const {
    if(!liveResultVisible_ || WaitingForOffer()) return {};
    if(!running_) return result_;
    if(receiveState_ && (receiveState_->phase==Phase::Completed || receiveState_->phase==Phase::Failed))
        return {receiveState_->phase==Phase::Completed?L"受信しました。":L"受信できませんでした。",ReceiveFailureText(receiveState_->failureReason),
            supervisorPhase_==supervisor::Phase::Restoring?L"Wi-Fiを元の接続に戻しています。":L""};
    return {};
}

std::optional<TransferProgress> ReceiverController::Progress() const {
    if(!IsReceiving()||!receiveState_->receivedBytes||!receiveState_->totalBytes||
       *receiveState_->receivedBytes>*receiveState_->totalBytes)return std::nullopt;
    return TransferProgress{*receiveState_->receivedBytes,*receiveState_->totalBytes};
}

void ReceiverController::StartReceive() {
    if (running_) {
        if (incoming_ && !decisionSubmitted_) SubmitDecision(true);
        return;
    }
    if (starting_) return;
    supervisorPhase_=supervisor::Phase::Unknown;
    result_={};liveResultVisible_=true;
    if (lifecycle_.active != Operation::None) {
        currentStatus_ = L"送信処理中です。送信を停止すると受信できます。";
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }
    if (downloadsPath_.empty()) {
        currentStatus_ = L"保存先を選んでください。";
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }
    sessionDestination_ = std::filesystem::path(downloadsPath_);
    const DWORD destinationAttributes = GetFileAttributesW(sessionDestination_.c_str());
    if (!sessionDestination_.is_absolute() || destinationAttributes == INVALID_FILE_ATTRIBUTES ||
        !(destinationAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        currentStatus_ = L"保存先フォルダーが見つかりません。";
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }
    const auto runtime = FindRuntimeExecutable();
    if (!runtime) {
        currentStatus_ = L"受信を開始できませんでした。配布ファイルをすべて展開し直してください。";
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }
    const auto artifacts = UserSessionDirectory();
    if (artifacts.empty()) {
        currentStatus_ = ReceiveStartFailure;
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }

    std::error_code filesystemError;
    std::filesystem::create_directories(artifacts, filesystemError);
    if (filesystemError) {
        currentStatus_ = ReceiveStartFailure;
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
        currentStatus_ = ReceiveStartFailure;
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }

    requestFile_ = requestDirectory_ / request_file::FileName;
    statusFile_ = requestDirectory_ / supervisor::StatusFileName;
    resultFile_ = requestDirectory_ / supervisor::ResultFileName;
    cancelFile_ = requestDirectory_ / session_markers::CancelFileName;
    incomingFile_ = requestDirectory_ / receive_offer::FileName;
    receiveStateFile_ = requestDirectory_ / tx10ub::receive_state::FileName;
    const auto filePathUtf8 = Utf8(sessionDestination_.wstring());
    const auto candidateName = Utf8(request_file::Candidate(token));
    if (filePathUtf8.empty()) {
        currentStatus_ = L"選んだフォルダーには保存できません。別のフォルダーを選んでください。";
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }
    std::string ackRateField;
    wchar_t ackRate[3]{};
    if (GetEnvironmentVariableW(L"DROPPORTER_RECEIVE_ACK_MBPS", ackRate, 3) == 2) {
        const std::wstring_view value(ackRate, 2);
        if (value == L"12" || value == L"24") {
            ackRateField = request_file::Field(request_file::ReceiveAckRateMbps) + Utf8(value) + ",\n  ";
        }
    }
    const std::string request = "{\n  " + request_file::Field(request_file::FilePath) + '"' + JsonEscape(filePathUtf8) +
        "\",\n  " + request_file::Field(request_file::Mode) + '"' + request_file::ReceiveMode +
        "\",\n  " + WideChannelRequestField() + ackRateField + request_file::Field(request_file::CandidateName) + '"' + candidateName +
        "\",\n  " + request_file::Field(request_file::OwnerPid) + std::to_string(GetCurrentProcessId()) + "\n}\n";
    if (!WriteNewFile(requestFile_, request)) {
        currentStatus_ = ReceiveStartFailure;
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }

    const std::wstring parameters = L"--request " + QuoteWindowsArgument(requestFile_.wstring());
    if (parameters.size() > 32760) {
        currentStatus_ = L"受信を開始できませんでした。";
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }
    if (!lifecycle_.TryBegin(Operation::Receive)) return;
    starting_ = true;
    view_.OperationStarted();
    RefreshControls();
    if (!view_.StartPolling()) {
        starting_ = false;
        view_.OperationFinished(Operation::Receive, true);
        currentStatus_ = L"受信を開始できませんでした。Drop Porterを開き直してください。";
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

void ReceiverController::CompleteLaunch(bool launched, HANDLE process, DWORD error) {
    if (!launched) {
        cancelAfterStart_ = false;
        view_.StopPolling();
        starting_ = false;
        view_.OperationFinished(Operation::Receive, true);
        currentStatus_ = error == ERROR_CANCELLED ? L"受信を開始しませんでした。" : ReceiveStartFailure;
        view_.SetControlText(TransferField::Status, currentStatus_);
        RefreshControls();
        return;
    }

    childProcess_.reset(process);
    starting_ = false;
    running_ = true;
    cancellationRequested_ = false;
    decisionSubmitted_ = false;
    incoming_.reset();
    receiveState_.reset();
    result_={};liveResultVisible_=true;
    currentSender_ = L"";
    currentFiles_.clear();
    currentDetails_.clear();
    RefreshSavedFiles({});
    currentStatus_ = childProcess_ ? L"受信の準備中です。" :
        L"受信の準備を中止します。";
    view_.SetControlText(TransferField::Status, currentStatus_);
    view_.SetControlText(TransferField::Details, currentDetails_);
    view_.SetControlText(TransferField::Target, currentSender_);
    RefreshControls();
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

void ReceiverController::SubmitDecision(bool accept) {
    if (!running_ || cancellationRequested_ || decisionSubmitted_ || !incoming_ ||
        !receive_offer::ValidToken(incoming_->token)) return;
    const auto path = requestDirectory_ / receive_offer::DecisionName(incoming_->token);
    const std::string decision = receive_offer::EncodeDecision(accept);
    // The worker polls this name and treats an unreadable decision as a rejection.
    if (!PublishLocalFile(path, decision, false)) {
        currentStatus_ = accept ? L"受信を開始できません。もう一度お試しください。" : L"受信を見送れません。もう一度お試しください。";
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }
    decisionSubmitted_ = true;
    currentStatus_ = accept ? L"受信を準備しています。" : L"受信を見送りました。";
    view_.SetControlText(TransferField::Status, currentStatus_);
    RefreshControls();
}

void ReceiverController::SubmitNotificationDecision(std::wstring_view token, bool accept) {
    const auto* offer = PendingOffer();
    if (!offer || token != std::wstring(offer->token.begin(), offer->token.end())) return;
    const auto text = ReadSmallTextFile(incomingFile_);
    const auto current = text ? ParseIncomingRequest(*text) : std::nullopt;
    if (current && current->token == offer->token) SubmitDecision(accept);
}

void ReceiverController::RequestCancel() {
    if (!running_ || cancellationRequested_) return;
    if (!WriteCancelMarker(cancelFile_)) {
        currentStatus_ = incoming_ ? L"受信を止められませんでした。この画面を開いたままお待ちください。" :
            L"受信を止められませんでした。まだ受信中なら、もう一度「停止」を押してください。";
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }
    cancellationRequested_ = true;
    currentStatus_ = L"受信を停止しています。しばらくお待ちください。";
    view_.SetControlText(TransferField::Status, currentStatus_);
    RefreshControls();
}

void ReceiverController::RefreshFromFiles() {
    liveResultVisible_=true;
    const auto incomingText = ReadSmallTextFile(incomingFile_);
    bool incomingValid = false;
    if (incomingText) {
        if (const auto request = ParseIncomingRequest(*incomingText)) {
            if (!incoming_ || incoming_->token != request->token) {
                decisionSubmitted_ = false;
                currentDetails_.clear();
            }
            incoming_ = request;
            currentSender_ = incoming_->sender;
            currentFiles_ = IncomingFilesText(*incoming_);
            if (!decisionSubmitted_) currentStatus_ = L"このファイルを受信しますか？";
            incomingValid = true;
        } else {
            incoming_.reset();
            decisionSubmitted_ = false;
            currentStatus_ = L"いまの依頼では受信できません。相手にあとでもう一度送信してもらってください。";
            currentDetails_.clear();
        }
    } else {
        incoming_.reset();
        decisionSubmitted_ = false;
    }
    const auto stateText = ReadSmallTextFile(receiveStateFile_);
    receiveState_ = stateText ? ParseReceiveState(*stateText) : std::nullopt;
    if (receiveState_) {
        if (HasPublishedReceivePaths(*receiveState_)) RefreshSavedFiles(receiveState_->savedPaths);
    }
    if (cancellationRequested_) return;

    const auto status = ReadSmallTextFile(statusFile_);
    const auto statusText = status ? supervisor::TrimStatus(*status) : std::string_view{};
    const auto supervisorPhase = supervisor::ParsePhase(statusText);
    supervisorPhase_=supervisorPhase;

    if (ReadSmallTextFile(cancelFile_) == session_markers::IdleTimeoutContent) {
        cancellationRequested_ = true;
        currentStatus_ = L"受信待機を自動で終了し、Wi-Fiを復旧しています。";
        view_.SetControlText(TransferField::Status, currentStatus_);
        return;
    }

    if (incomingValid && incoming_) {
        if (!decisionSubmitted_) currentStatus_ = L"このファイルを受信しますか？";
        currentDetails_ = IncomingFilesText(*incoming_);
        view_.SetControlText(TransferField::Status, currentStatus_);
        view_.SetControlText(TransferField::Details, currentDetails_);
        view_.SetControlText(TransferField::Target, currentSender_);
        return;
    }

    constexpr auto ready = L"AirDropでこのPCに送信できます。";
    if (WaitingForOffer()) {
        currentStatus_ = L"近くの端末からの受信依頼を待っています。\r\n動画は送信側で変換してから届くことがあります。";
        currentSender_.clear();
        currentFiles_.clear();
        currentDetails_.clear();
    } else if (receiveState_) {
        const auto& state = *receiveState_;
        if (state.phase == Phase::Receiving) {
            currentSender_ = state.sender;
            if (currentSender_.empty()) currentSender_ = L"";
            currentStatus_ = state.waitingForData ? L"相手からの受信データを待っています。" : L"受信中です。";
            currentDetails_ = ReceiveProgressText(state);
        } else if (state.phase == Phase::Completed) {
            currentSender_ = state.sender;
            currentStatus_ = supervisorPhase == supervisor::Phase::Restoring ? L"受信完了。Wi-Fiを復旧しています。" :
                state.idleDeadlineMs ? ready : L"受信が完了しました。";
            currentDetails_ = SavedPathsText(state);
        } else if (state.phase == Phase::Failed) {
            currentSender_.clear();
            currentFiles_.clear();
            currentStatus_ = L"受信できませんでした。";
            currentDetails_ = ReceiveFailureText(state.failureReason);
            const auto paths = SavedPathsText(state);
            if (!paths.empty()) currentDetails_ += (currentDetails_.empty() ? L"" : L"\r\n") + paths;
        } else if (state.phase == Phase::ApprovalPending) {
            currentStatus_ = L"受信の確認を準備しています。";
        } else if (state.phase == Phase::Listening) {
            currentSender_.clear();
            currentFiles_.clear();
            currentStatus_.clear();
            currentDetails_.clear();
            if (state.lastResult == tx10ub::receive_state::RejectedResult) {
                currentStatus_ = L"受信を見送りました。";
            } else if (state.lastResult == tx10ub::receive_state::ExpiredResult) {
                currentStatus_ = L"受信の確認が時間切れになりました。";
            } else if (state.lastResult == tx10ub::receive_state::FailedResult) {
                currentStatus_ = L"受信できませんでした。";
                currentDetails_ = ReceiveFailureText(state.failureReason);
                const auto paths = SavedPathsText(state);
                if (!paths.empty()) AppendLine(currentDetails_, paths);
            } else if (state.lastResult == tx10ub::receive_state::CancelledResult) {
                currentStatus_ = L"受信を停止しました。";
                currentDetails_ = SavedPathsText(state);
            }
            if (supervisorPhase == supervisor::Phase::Restoring) {
                currentStatus_ += L"受信待機を終了し、Wi-Fiを復旧しています。";
            } else {
                currentStatus_ += ready;
                if (!state.receiverName.empty())
                    AppendLine(currentStatus_, L"AirDrop一覧で「" + state.receiverName + L"」を選んでください。");
            }
        }
    } else if (supervisorPhase == supervisor::Phase::Listening) {
        currentSender_.clear();
        currentFiles_.clear();
        currentStatus_ = ready;
        currentDetails_.clear();
    } else if (supervisorPhase == supervisor::Phase::PreparingAdapter) currentStatus_ = L"受信の準備中です。";
    else if (supervisorPhase == supervisor::Phase::PreparingNetwork) currentStatus_ = L"Wi-Fiを切り替えています。";
    else if (supervisorPhase == supervisor::Phase::PreparingRadio) currentStatus_ = L"通信を準備しています。";
    else if (supervisorPhase == supervisor::Phase::Restoring) currentStatus_ = L"Wi-Fiを復旧しています。";
    else if (!statusText.empty()) currentStatus_ = L"受信処理中です。";
    if (receiveState_ && receiveState_->idleDeadlineMs && supervisorPhase == supervisor::Phase::Listening) {
        using namespace std::chrono;
        const auto now = GetTickCount64();
        const auto deadline = *receiveState_->idleDeadlineMs;
        if (deadline > now) {
            const auto remaining = milliseconds(deadline - now);
            const auto duration = remaining <= minutes(1)
                ? std::to_wstring(ceil<seconds>(remaining).count()) + L"秒"
                : std::to_wstring(ceil<minutes>(remaining).count()) + L"分";
            AppendLine(currentStatus_, L"あと" + duration + L"で受信待機を自動停止します。");
        }
    }
    view_.SetControlText(TransferField::Status, currentStatus_);
    view_.SetControlText(TransferField::Details, currentDetails_);
    view_.SetControlText(TransferField::Target, currentSender_);
}

void ReceiverController::RefreshControls() {
    const bool hasDownloads = !downloadsPath_.empty();
    view_.EnableControl(TransferField::ChooseFile, !running_ && !starting_ && !otherModeBusy_);
    view_.EnableControl(TransferField::OpenFolder, hasDownloads);
    const int selection = view_.SelectedSavedFile();
    view_.EnableControl(TransferField::OpenFile, !starting_ && selection >= 0 &&
        static_cast<std::size_t>(selection) < completedFiles_.size());
    if (!running_ && !starting_) {
        view_.SetControlText(TransferField::PrimaryAction, L"受信を開始");
        view_.SetControlText(TransferField::Cancel, L"停止");
        view_.EnableControl(TransferField::PrimaryAction, hasDownloads && !otherModeBusy_);
        view_.EnableControl(TransferField::Cancel, FALSE);
    } else if (starting_) {
        view_.SetControlText(TransferField::PrimaryAction, L"準備中");
        view_.SetControlText(TransferField::Cancel, L"停止");
        view_.EnableControl(TransferField::PrimaryAction, FALSE);
        view_.EnableControl(TransferField::Cancel, FALSE);
    } else if (cancellationRequested_) {
        view_.SetControlText(TransferField::PrimaryAction, L"受信中");
        view_.SetControlText(TransferField::Cancel, L"停止中");
        view_.EnableControl(TransferField::PrimaryAction, FALSE);
        view_.EnableControl(TransferField::Cancel, FALSE);
    } else if (incoming_) {
        view_.SetControlText(TransferField::PrimaryAction, L"受信する");
        view_.SetControlText(TransferField::Cancel, L"拒否");
        view_.EnableControl(TransferField::PrimaryAction, !decisionSubmitted_);
        view_.EnableControl(TransferField::Cancel, !decisionSubmitted_);
    } else {
        view_.SetControlText(TransferField::PrimaryAction, L"受信中");
        view_.SetControlText(TransferField::Cancel, L"停止");
        view_.EnableControl(TransferField::PrimaryAction, FALSE);
        view_.EnableControl(TransferField::Cancel, TRUE);
    }
}

void ReceiverController::SetOtherModeBusy(bool busy) {
    otherModeBusy_ = busy;
    if (!running_ && !starting_) {
        view_.SetControlText(TransferField::Status, busy ? L"送信処理中です。送信を停止すると受信できます。" : currentStatus_);
    }
    RefreshControls();
}

void ReceiverController::RequestHostClose() {
    if (starting_) {
        cancelAfterStart_ = true;
        if (!cancelFile_.empty()) (void)WriteCancelMarker(cancelFile_);
    }
    if (running_) RequestCancel();
}

void ReceiverController::PollChild() {
    if (!running_) return;
    if (!cancellationRequested_) RefreshFromFiles();
    RefreshControls();
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

void ReceiverController::FinishChild(DWORD exitCode) {
    liveResultVisible_=true;
    view_.StopPolling();
    childProcess_.reset();
    const auto stateText = ReadSmallTextFile(receiveStateFile_);
    receiveState_ = stateText ? ParseReceiveState(*stateText) : std::nullopt;
    running_ = false;
    cancellationRequested_ = false;
    decisionSubmitted_ = false;
    incoming_.reset();
    RefreshControls();
    bool canCloseAfterCompletion = false;
    const auto resultText = ReadSmallTextFile(resultFile_);
    if (!resultText) {
        (void)exitCode;
        constexpr auto checkSavedFiles = L"ファイルが届いているか、保存先フォルダーを確認してください。";
        currentStatus_ = ResultStatus(checkSavedFiles, Restoration::Unknown);
        result_={checkSavedFiles,L"",RestorationDetail(Restoration::Unknown)};
        currentDetails_.clear();
        AppendLine(currentDetails_, RestorationDetail(Restoration::Unknown));
    } else {
        const auto result = ParseKeyValues(*resultText);
        const bool received = IsOne(result, supervisor::TransferSucceededKey) && receiveState_ &&
            receiveState_->phase == Phase::Completed && !receiveState_->savedPaths.empty();
        const auto restoration = ClassifyRestoration(result);
        const auto finalStatus = supervisor::ParsePhase(Value(result, supervisor::StatusKey));
        const bool latestFailed = receiveState_ && receiveState_->lastResult == tx10ub::receive_state::FailedResult;
        const bool autoStopped = ReadSmallTextFile(cancelFile_) == session_markers::IdleTimeoutContent;
        constexpr auto autoStopText = L"受信待機を自動で終了しました。";
        const auto title = received ? L"受信しました。" : latestFailed ? L"受信できませんでした。" : autoStopped ? autoStopText :
            finalStatus == supervisor::Phase::Cancelled ? L"受信を停止しました。" : L"受信できませんでした。";
        currentStatus_ = ResultStatus(title, restoration);
        currentDetails_.clear();
        const auto reason = std::string_view(Value(result, supervisor::FailureReasonKey));
        if (!received && finalStatus == supervisor::Phase::Failed) currentDetails_ = AdapterFailureText(reason);
        if (!received && (finalStatus == supervisor::Phase::Failed || latestFailed) && currentDetails_.empty() && receiveState_)
            currentDetails_ = ReceiveFailureText(receiveState_->failureReason);
        result_={title, currentDetails_, RestorationDetail(restoration),
            !received && finalStatus == supervisor::Phase::Failed && reason == UnsupportedDriverReason};
        if (received && autoStopped) AppendLine(result_.detail, autoStopText);
        AppendLine(currentDetails_, RestorationDetail(restoration));
        canCloseAfterCompletion = !RestorationNeedsAttention(restoration);
    }
    view_.SetControlText(TransferField::Status, currentStatus_);
    view_.SetControlText(TransferField::Details, currentDetails_);
    view_.SetControlText(TransferField::Target, receiveState_ ? receiveState_->sender : L"");
    RefreshSavedFiles(receiveState_ ? receiveState_->savedPaths : std::vector<std::wstring>{});
    view_.OperationFinished(Operation::Receive, canCloseAfterCompletion);
}

void ReceiverController::SelectReceiveFolder(const std::filesystem::path& selected) {
    if(running_||starting_||otherModeBusy_) return;
    const DWORD attributes = GetFileAttributesW(selected.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        ReportUiError(L"保存先フォルダーが見つかりません。");
        return;
    }
    downloadsPath_ = selected.lexically_normal().wstring();
    result_={};liveResultVisible_=true;
    view_.SetControlText(TransferField::FilePath, downloadsPath_);
    const auto settings = ReceiveFolderSettingsFile();
    const bool persisted = !settings.empty() && PersistReceiveFolderPreference(settings, selected);
    currentStatus_ = persisted ? L"保存先を変更しました。" :
        L"保存先を変更しました。次回起動時の設定を保存できませんでした。";
    view_.SetControlText(TransferField::Status, currentStatus_);
    RefreshControls();
}
void ReceiverController::RefreshSavedFiles(const std::vector<std::wstring>& paths) {
    const int selection=view_.SelectedSavedFile();
    std::optional<std::filesystem::path> selected;
    if(selection>=0&&static_cast<std::size_t>(selection)<completedFiles_.size()) selected=completedFiles_[selection];
    std::vector<std::filesystem::path> next;
    for(const auto& path:paths) {
        auto resolved=ResolveOpenableSavedFile(path,sessionDestination_);
        if(resolved&&std::find(next.begin(),next.end(),*resolved)==next.end()) next.push_back(*resolved);
    }
    if(next==completedFiles_) return;
    completedFiles_=std::move(next);
    int index=-1;
    if(!selected && completedFiles_.size()==1) index=0;
    if(selected) for(std::size_t i=0;i<completedFiles_.size();++i) if(completedFiles_[i]==*selected) index=static_cast<int>(i);
    view_.ShowSavedFiles(completedFiles_,index);
    RefreshControls();
}
std::optional<std::filesystem::path> ReceiverController::SelectedFileToOpen() {
    if(starting_) return std::nullopt;
    const int index=view_.SelectedSavedFile();
    if(index<0||static_cast<std::size_t>(index)>=completedFiles_.size()) return std::nullopt;
    auto path=ResolveOpenableSavedFile(completedFiles_[index],sessionDestination_);
    if(!path) {ReportUiError(L"保存先にあるファイルが見つかりません。");RefreshControls();}
    return path;
}
std::optional<std::filesystem::path> ReceiverController::SavedFilesFolder() const {
    if(completedFiles_.empty()) return std::nullopt;
    return completedFiles_.front().parent_path();
}

}
