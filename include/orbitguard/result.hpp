#pragma once
// Minimal Result<T, E> (C++17 has no std::expected). Errors are values, not
// exceptions: a ground station must keep running when it receives garbage.
#include <cassert>
#include <utility>
#include <variant>

namespace orbitguard {

template <typename T, typename E>
class Result {
public:
    Result(T value) : v_(std::in_place_index<0>, std::move(value)) {}
    Result(E error) : v_(std::in_place_index<1>, std::move(error)) {}

    bool ok() const { return v_.index() == 0; }
    explicit operator bool() const { return ok(); }

    const T& value() const { assert(ok()); return std::get<0>(v_); }
    T& value() { assert(ok()); return std::get<0>(v_); }
    const E& error() const { assert(!ok()); return std::get<1>(v_); }

private:
    std::variant<T, E> v_;
};

}  // namespace orbitguard
