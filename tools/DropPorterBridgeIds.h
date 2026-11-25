#pragma once

// Keep these ABI values in sync with NativeBridgeIds.cs.
namespace dropporter {

enum class TransferMode : int
{
    Send = 0,
    Receive = 1,
};

enum class BridgeCommand : int
{
    Poll = 0,
    SelectPath = 1,
    Start = 2,
    Cancel = 3,
    SelectItem = 4,
    OpenFile = 5,
    OpenFolder = 6,
    ShowInFolder = 7,
    RefreshTargets = 8,
    RequestClose = 9,
    RespondToOffer = 10,
    SelectSendFiles = 11,
    RecordRecoveryCompleted = 12,
    DismissRecovery = 13,
    RecordRecoveryFailure = 14,
    SendToPeer = 15,
};

enum class ValueKind : int
{
    ControlEnabled = 0,
    ItemCount = 1,
    SelectedItem = 2,
    CloseReady = 3,
    ResultRevision = 4,
    ResultTab = 5,
    HasIncoming = 6,
    ConfirmClose = 7,
    ShowSearchHelp = 8,
    Activity = 9,
    CanRefreshTargets = 10,
    SendFileCount = 11,
    TransferActive = 12,
    ShowDriverHelp = 13,
    ShowRecoveryDriverHelp = 14,
    WifiConnected = 15,
    OfferFileCount = 16,
    SendCompleted = 17,
};

enum class TextField : int
{
    ChooseFile = 0,
    PrimaryAction = 1,
    Cancel = 2,
    FilePath = 3,
    Status = 4,
    Details = 5,
    Target = 6,
    Files = 7,
    OpenFile = 8,
    OpenFolder = 9,
    ItemLabel = 10,
    ResultTitle = 11,
    ResultDetail = 12,
    RestorationText = 13,
    OfferSize = 14,
    OfferToken = 15,
    OfferExpiration = 16,
    SendFilePath = 17,
    SendSelectionSize = 18,
    OfferPreviewPath = 19,
    RecoveryRequestPath = 20,
    RuntimePath = 21,
    RecoveryFailureMessage = 22,
    ItemPeerAddress = 23,
};

enum class OfferDecision : int
{
    Reject = 0,
    Accept = 1,
};

enum class TransferActivity : int
{
    None = 0,
    Transferring = 1,
    AwaitingCompletion = 2,
    Restoring = 3,
    Stopping = 4,
    SearchingTargets = 5,
    Working = 6,
};

}
