#pragma once

// Owns the shared send/receive operation and the close-after-restoration gate.
enum class Operation { None, Send, Receive, Restore };

struct ShareLifecycle {
    Operation active = Operation::None;
    bool closeRequested = false;

    bool TryBegin(Operation operation) noexcept {
        if (active != Operation::None || operation == Operation::None) return false;
        active = operation;
        return true;
    }

    bool Finish(bool restorationVerified) noexcept {
        active = Operation::None;
        const bool closeNow = closeRequested && restorationVerified;
        closeRequested = false;
        return closeNow;
    }
};
