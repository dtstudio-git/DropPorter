#pragma once

namespace tx10ub::tcp {
enum class UploadQueueState { queued, localBuffer, peerWindow, congestionWindow, bothWindows, other };
}
