#pragma once
#include <functional>

class defer_t final {
public:
  template<typename F>
  explicit defer_t(F &&_func) : f_(std::forward<F>(_func)) {}
  defer_t(const defer_t &) = delete;
  defer_t &operator=(const defer_t &) = delete;
  defer_t(defer_t && _other) noexcept : f_(std::move(_other.f_)) {}
  defer_t &operator=(defer_t && _other) noexcept {
    if (this != &_other) f_ = std::move(_other.f_);
    return *this;
  }
  ~defer_t() {
    if (f_) f_();
  }

private:
  std::function<void()> f_;
};

class defer_maker_t final {
public:
  template<typename F>
  defer_t operator<<(F &&_func) {
    return defer_t(std::forward<F>(_func));
  }
};

#define DEFER_CAT_IMPL(x, y) x##y
#define DEFER_VAR_NAME(x, y) DEFER_CAT_IMPL(x, y)
#define defer auto DEFER_VAR_NAME(_defer_, __COUNTER__) = defer_maker_t() << [&]()
