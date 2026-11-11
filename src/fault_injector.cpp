#include "orbitguard/fault_injector.hpp"

namespace orbitguard {

bool FaultConfig::valid() const {
    auto ok = [](double p) { return p >= 0.0 && p <= 1.0; };  // false for NaN
    return ok(drop) && ok(corrupt) && ok(duplicate) && ok(reorder);
}

bool FaultInjector::roll(double p) {
    if (p <= 0.0) return false;  // exact: a zero probability never consumes randomness
    if (p >= 1.0) return true;
    return std::uniform_real_distribution<double>(0.0, 1.0)(rng_) < p;
}

void FaultInjector::corrupt_in_place(Datagram& d) {
    if (d.empty()) return;
    if (roll(0.5) && d.size() > 1) {
        // Truncation: the receiver sees a short datagram.
        d.resize(1 + rng_() % (d.size() - 1));
    } else {
        d[rng_() % d.size()] ^= static_cast<std::uint8_t>(1u << (rng_() % 8));
    }
}

std::vector<FaultInjector::Datagram> FaultInjector::process(Datagram packet) {
    std::vector<Datagram> out;
    if (roll(cfg_.drop)) {
        ++stats_.dropped;
        return out;
    }
    if (roll(cfg_.corrupt)) {
        corrupt_in_place(packet);
        ++stats_.corrupted;
    }
    if (!held_ && roll(cfg_.reorder)) {
        held_ = std::move(packet);
        ++stats_.reordered;
        return out;  // released behind the next packet that gets through
    }
    if (roll(cfg_.duplicate)) {
        out.push_back(packet);
        ++stats_.duplicated;
    }
    out.push_back(std::move(packet));
    if (held_) {
        out.push_back(std::move(*held_));
        held_.reset();
    }
    return out;
}

std::vector<FaultInjector::Datagram> FaultInjector::flush() {
    std::vector<Datagram> out;
    if (held_) {
        out.push_back(std::move(*held_));
        held_.reset();
    }
    return out;
}

}  // namespace orbitguard
