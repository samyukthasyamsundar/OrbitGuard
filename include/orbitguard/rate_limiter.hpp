#pragma once
// Token-bucket rate limiter. The clock is passed in, so it is deterministic to test.
//
// Used to bound how much CPU a hostile sender can burn on the most expensive rejection path:
// a well-formed secure packet with a bad tag forces a full HMAC computation (~150x the cost of
// rejecting random junk). After the budget of such failures is spent, further ones are refused
// cheaply, before any HMAC runs, until tokens refill. Legitimate traffic that authenticates
// successfully does not draw on the budget, so a flood of bad packets cannot starve real ones of
// verification once the bucket has recovered.
//
// What it does NOT do: it cannot stop the kernel dropping datagrams when the socket buffer
// overflows, because that happens before the program sees them (see docs/THREAT_MODEL.md).
#include <cmath>
#include <cstdint>

namespace orbitguard {

class RateLimiter {
public:
    // `rate_per_s` tokens are added each second, up to `burst`. Both must be finite and > 0,
    // otherwise the limiter is created "open" (never refuses), which is the safe failure for
    // a misconfiguration of a defence that is optional.
    RateLimiter(double rate_per_s, double burst)
        : rate_(rate_per_s), burst_(burst), tokens_(burst),
          open_(!(std::isfinite(rate_per_s) && std::isfinite(burst) && rate_per_s > 0 && burst >= 1)) {}

    // Is a token available at time `now_ms`? Consumes one if so.
    bool allow(std::uint64_t now_ms) {
        if (open_) return true;
        refill(now_ms);
        if (tokens_ >= 1.0) { tokens_ -= 1.0; return true; }
        ++refused_;
        return false;
    }

    // Give a token back, e.g. the work turned out to be legitimate. Capped at the burst size.
    void refund() {
        if (open_) return;
        tokens_ += 1.0;
        if (tokens_ > burst_) tokens_ = burst_;
    }

    // Would a token be available? Does not consume.
    bool would_allow(std::uint64_t now_ms) {
        if (open_) return true;
        refill(now_ms);
        return tokens_ >= 1.0;
    }

    std::uint64_t refused() const { return refused_; }

private:
    void refill(std::uint64_t now_ms) {
        if (!started_) { started_ = true; last_ms_ = now_ms; return; }
        if (now_ms > last_ms_) {   // a clock that steps backwards never adds tokens
            tokens_ += rate_ * static_cast<double>(now_ms - last_ms_) / 1000.0;
            if (tokens_ > burst_) tokens_ = burst_;
            last_ms_ = now_ms;
        }
    }

    double rate_, burst_, tokens_;
    bool open_;
    bool started_ = false;
    std::uint64_t last_ms_ = 0;
    std::uint64_t refused_ = 0;
};

}  // namespace orbitguard
