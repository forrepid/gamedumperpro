#include "utils/Progress.h"
#include "utils/StrUtil.h"
#include "utils/Logger.h"

namespace dumper {

std::string Hex(u64 v) {
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%012llX", (unsigned long long)v);
    return buf;
}

std::string Hex32(u32 v) {
    char buf[16];
    snprintf(buf, sizeof(buf), "0x%08X", v);
    return buf;
}

Progress::Progress(std::string label, u64 total)
    : label_(std::move(label)), total_(total), start_(std::chrono::steady_clock::now()) {}

Progress::~Progress() {
    if (!finished_) Done();
}

void Progress::Set(u64 v) { cur_ = v; Render(); }
void Progress::Add(u64 n) { cur_ += n; Render(); }

void Progress::Render() {
    if (finished_) return;

    double now = std::chrono::duration<double>(std::chrono::steady_clock::now() - start_).count();
    if (now - lastRender_ < 0.08 && cur_ < total_) return; // ~12 fps
    lastRender_ = now;

    double frac = total_ ? (double)cur_ / (double)total_ : 1.0;
    if (frac > 1.0) frac = 1.0;

    double eta = frac > 0.01 ? (now / frac) - now : 0.0;

    const int width = 24;
    int filled = (int)(frac * width);

    char bar[width + 1];
    for (int i = 0; i < width; i++) bar[i] = (i < filled) ? '#' : '-';
    bar[width] = 0;

    char line[192];
    snprintf(line, sizeof(line), "\r  %-14s [%s] %5.1f%% | %llu/%llu | ETA %.0fs   ",
             label_.c_str(), bar, frac * 100.0,
             (unsigned long long)cur_, (unsigned long long)total_, eta);
    fputs(line, stdout);
    fflush(stdout);
}

void Progress::Done(const std::string& note) {
    if (finished_) return;
    finished_ = true;
    double now = std::chrono::duration<double>(std::chrono::steady_clock::now() - start_).count();

    char line[256];
    snprintf(line, sizeof(line), "\r  %-14s %-24s 100.0%% | %-12llu | %.2fs%s%s",
             label_.c_str(), "done", (unsigned long long)total_, now,
             note.empty() ? "" : " | ", note.c_str());
    fputs(line, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

} // namespace dumper
