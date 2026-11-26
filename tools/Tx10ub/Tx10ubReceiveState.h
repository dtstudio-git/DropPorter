#pragma once

#include <cstdint>
#include <string_view>

#include "../DropPorter/DropPorterJson.h"

namespace tx10ub::receive_state {

inline constexpr wchar_t FileName[] = L"receive-state.json";
inline constexpr unsigned Version = 1;
inline constexpr char VersionField[] = "version";
inline constexpr char PhaseField[] = "phase";
inline constexpr char TokenField[] = "token";
inline constexpr char SenderField[] = "sender";
inline constexpr char ReceiverNameField[] = "receiverName";
inline constexpr char ExpiresAtUtcField[] = "expiresAtUtc";
inline constexpr char ReceivedBytesField[] = "receivedBytes";
inline constexpr char BodyReceiveUsField[] = "bodyReceiveUs";
inline constexpr char WaitingForDataField[] = "waitingForData";
inline constexpr char TotalBytesField[] = "totalBytes";
inline constexpr char TotalFilesField[] = "totalFiles";
inline constexpr char IdleDeadlineMsField[] = "idleDeadlineMs";
inline constexpr char DiscoveredAtMsField[] = "discoveredAtMs";
inline constexpr char LastResultField[] = "lastResult";
inline constexpr char ErrorField[] = "error";
inline constexpr char SavedPathsField[] = "savedPaths";
inline constexpr char FilesField[] = "files";
inline constexpr char FileNameField[] = "FileName";
inline constexpr char FileSizeField[] = "FileSize";
inline constexpr char RejectedResult[] = "rejected";
inline constexpr char ExpiredResult[] = "expired";
inline constexpr char FailedResult[] = "failed";
inline constexpr char CancelledResult[] = "cancelled";

enum class Phase { Unknown, Listening, ApprovalPending, Receiving, Completed, Failed };

inline constexpr std::string_view PhaseName(Phase phase) {
    switch (phase) {
    case Phase::Listening: return "listening";
    case Phase::ApprovalPending: return "approval_pending";
    case Phase::Receiving: return "receiving";
    case Phase::Completed: return "completed";
    case Phase::Failed: return FailedResult;
    default: return {};
    }
}

inline std::optional<Phase> ReadPhase(const dropporter::JsonValue& root) {
    const auto value = dropporter::JsonString(root, PhaseField);
    if (!value) return std::nullopt;
    for (const auto phase : {Phase::Listening, Phase::ApprovalPending, Phase::Receiving, Phase::Completed, Phase::Failed}) {
        if (*value == PhaseName(phase)) return phase;
    }
    return Phase::Unknown;
}

inline std::optional<Phase> ReadPhase(std::string_view text) {
    if (text.starts_with("\xef\xbb\xbf")) text.remove_prefix(3);
    dropporter::JsonValue root;
    if (!dropporter::JsonParser(text).Parse(root)) return std::nullopt;
    return ReadPhase(root);
}

// Values written to receive-state.json. Keep existing values stable.
enum class FailureReason : std::uint64_t {
    Other = 0,
    ConnectionClosed = 1,
    UploadTimedOut = 2,
    SaveFailed = 3,
};

inline constexpr char FailureReasonField[] = "failureReason";

}
