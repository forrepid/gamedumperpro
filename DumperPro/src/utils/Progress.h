// DumperPro - console progress bar:  [########......] 45.2% | 12345/27300 | ETA 12s
#pragma once
#include "../framework.h"

namespace dumper {

class Progress {
public:
    Progress(std::string label, u64 total);
    ~Progress();

    void Add(u64 n = 1);
    void Set(u64 v);
    void Done(const std::string& note = "");

private:
    void Render();
    std::string label_;
    u64 total_ = 0;
    u64 cur_ = 0;
    std::chrono::steady_clock::time_point start_;
    bool finished_ = false;
    double lastRender_ = 0.0;
};

} // namespace dumper
