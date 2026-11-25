#pragma once

#include "Tx10ubUsbClock.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace tx10ub::usb {

// Pure same-session estimator for generated Action -> first matching USB OUT
// submission. All times are supplied by the caller in the session's mapped
// monotonic clock domain; this type reads no clock and makes no RF claim.
class TxTiming {
public:
    using Time = awdlwin::discovery::MonotonicTime;
    using Delay = std::chrono::microseconds;

    static constexpr std::size_t pending_limit = 16;
    static constexpr std::size_t sample_limit = 8;
    static constexpr Delay maximum_delay{100'000};
    static constexpr Delay pending_lifetime=awdlwin::tx10ub::usb_clock::transport_pending_lifetime;
    static constexpr Delay sample_freshness{2'000'000};
    static constexpr Delay maximum_prediction_spread{32'768};

    struct Sample {
        Delay actual_delay;
        std::optional<Delay> predicted_delay;
        std::optional<Delay> prediction_error;
    };

    // generated_at is the actual Action generation time, not the projected
    // timestamp encoded in its Sync body and not a later registration time.
    bool register_action(const awdlwin::wire::MacAddress& source,
                         std::span<const std::uint8_t> body,
                         Time generated_at,
                         std::optional<Delay> predicted_delay = std::nullopt) {
        if (!valid_time(generated_at) || body.size() < 16 || body.size() > 265 ||
            (predicted_delay && !valid_delay(*predicted_delay))) return false;
        // Pending OUT identity is also a readiness fence. Age may fail a
        // caller's bounded wait, but cannot prove that the USB OUT occurred.
        if (latest_observation_ && generated_at < *latest_observation_) return false;
        // A repeated registration of the exact generated identity keeps its
        // original origin and prediction. It must not replace an older attempt.
        if (find_pending(source, body) != pending_.end()) return true;
        if (pending_.size() >= pending_limit) return false;
        pending_.push_back(Pending{source, {body.begin(), body.end()}, generated_at, predicted_delay});
        return true;
    }

    void cancel(const awdlwin::wire::MacAddress& source,
                std::span<const std::uint8_t> body) noexcept {
        pending_.erase(std::remove_if(pending_.begin(), pending_.end(),
            [&](const Pending& item) { return same_key(item, source, body); }), pending_.end());
    }

    // A USB OUT record consumes every pending copy of the exact key, so a
    // duplicate USB submission cannot train the estimate a second time.
    std::optional<Sample> observe(const awdlwin::wire::MacAddress& source,
                                  std::span<const std::uint8_t> body,
                                  Time observed_at) {
        if (!valid_time(observed_at)) return std::nullopt;
        const auto found = find_pending(source, body);
        if (found == pending_.end()) return std::nullopt;

        const auto generated_at = found->generated_at;
        const auto predicted_delay = found->predicted_delay;
        const bool expired = observed_at >= generated_at &&
            observed_at - generated_at > pending_lifetime;
        cancel(source, body);
        if (observed_at < generated_at) {
            invalidate_samples();
            return Sample{observed_at - generated_at, predicted_delay,
                          error_for(observed_at - generated_at, predicted_delay)};
        }

        const auto actual_delay = std::chrono::duration_cast<Delay>(observed_at - generated_at);
        const Sample receipt{actual_delay, predicted_delay, error_for(actual_delay, predicted_delay)};
        if (expired) {
            if (!latest_observation_ || observed_at >= *latest_observation_) latest_observation_ = observed_at;
            invalidate_samples();
            return receipt;
        }
        if (latest_observation_ && observed_at < *latest_observation_) {
            invalidate_samples();
            return receipt;
        }
        latest_observation_ = observed_at;
        if (!valid_delay(actual_delay)) {
            invalidate_samples();
            return receipt;
        }

        samples_.push_back(TimedSample{actual_delay, observed_at});
        if (samples_.size() > sample_limit) samples_.erase(samples_.begin());
        const auto spread = spread_of(samples_);
        if (spread > maximum_prediction_spread) invalidate_samples();
        return receipt;
    }

    std::optional<Delay> prediction(Time now) const {
        if(std::any_of(pending_.begin(),pending_.end(),[&](const Pending& item) {
            return now>=item.generated_at&&now-item.generated_at>pending_lifetime;
        }))return std::nullopt;
        const auto fresh = fresh_samples(now);
        if (fresh.size() < 3 || spread_of(fresh) > maximum_prediction_spread) return std::nullopt;
        std::array<Delay, sample_limit> ordered{};
        for (std::size_t i = 0; i < fresh.size(); ++i) ordered[i] = fresh[i].delay;
        std::sort(ordered.begin(), ordered.begin() + static_cast<std::ptrdiff_t>(fresh.size()));
        const auto middle = fresh.size() / 2;
        if (fresh.size() % 2 != 0) return ordered[middle];
        return Delay{(ordered[middle - 1].count() + ordered[middle].count()) / 2};
    }

    // Fresh-sample spread is useful for reporting stability even when it is
    // too wide for prediction or the ready-count has not yet reached three.
    std::optional<Delay> sample_spread(Time now) const {
        const auto fresh = fresh_samples(now);
        if (fresh.empty()) return std::nullopt;
        return spread_of(fresh);
    }

    std::size_t pending_count() const noexcept { return pending_.size(); }
    bool pending_timed_out(Time now) const noexcept {
        return std::any_of(pending_.begin(),pending_.end(),[&](const Pending& item) {
            return now>=item.generated_at&&now-item.generated_at>pending_lifetime;
        });
    }
    std::size_t sample_count() const noexcept { return samples_.size(); }

private:
    struct Pending {
        awdlwin::wire::MacAddress source;
        awdlwin::wire::Bytes body;
        Time generated_at;
        std::optional<Delay> predicted_delay;
    };
    struct TimedSample { Delay delay; Time observed_at; };
    using PendingIterator = std::vector<Pending>::iterator;

    static bool valid_time(Time value) noexcept { return value.time_since_epoch().count() >= 0; }
    static bool valid_delay(Delay value) noexcept { return value.count() >= 0 && value <= maximum_delay; }
    static std::optional<Delay> error_for(Delay actual, std::optional<Delay> predicted) noexcept {
        if (!predicted || !valid_delay(actual)) return std::nullopt;
        return actual - *predicted;
    }
    static bool same_key(const Pending& item, const awdlwin::wire::MacAddress& source,
                         std::span<const std::uint8_t> body) noexcept {
        return item.source == source && item.body.size() == body.size() &&
            std::equal(item.body.begin(), item.body.end(), body.begin());
    }
    PendingIterator find_pending(const awdlwin::wire::MacAddress& source,
                                 std::span<const std::uint8_t> body) noexcept {
        return std::find_if(pending_.begin(), pending_.end(),
            [&](const Pending& item) { return same_key(item, source, body); });
    }
    std::vector<TimedSample> fresh_samples(Time now) const {
        std::vector<TimedSample> fresh;
        if (!valid_time(now)) return fresh;
        fresh.reserve(samples_.size());
        for (const auto& sample : samples_) {
            if (now >= sample.observed_at && now - sample.observed_at <= sample_freshness)
                fresh.push_back(sample);
        }
        return fresh;
    }
    static Delay spread_of(const std::vector<TimedSample>& samples) noexcept {
        if (samples.empty()) return Delay::zero();
        auto minimum = samples.front().delay;
        auto maximum = samples.front().delay;
        for (const auto& sample : samples) {
            minimum = std::min(minimum, sample.delay);
            maximum = std::max(maximum, sample.delay);
        }
        return maximum - minimum;
    }
    void invalidate_samples() noexcept { samples_.clear(); }

    std::vector<Pending> pending_;
    std::vector<TimedSample> samples_;
    std::optional<Time> latest_observation_;
};

} // namespace tx10ub::usb
