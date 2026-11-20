// DumperPro - runtime offset discovery (probe-based voting on live objects)
#pragma once
#include "../framework.h"
#include "ue/Offsets.h"

namespace dumper {

class UEContext;

struct ProbeResult {
    bool ok = false;
    int probed = 0;                       // objects sampled
    int applied = 0;                      // fields auto-detected & applied
    int confirmed = 0;                    // fields confirmed against profile
    std::vector<std::string> warnings;    // profile vs probe disagreements etc.
};

class OffsetProbe {
public:
    explicit OffsetProbe(UEContext& ctx) : ctx_(ctx) {}

    // Probes up to maxObjects live objects and fills fields the profile left at 0.
    // Profile values are never overwritten; disagreements produce a warning.
    // Fields with confidence < 65% are skipped (left missing).
    ProbeResult Run(int maxObjects = 400);

    // debug output: every field offset, its value and its source
    bool WriteOffsetsTxt(const fs::path& file);

private:
    UEContext& ctx_;

    void ApplyField(const std::string& key, u32 candidate, int confidencePct, ProbeResult& res);
    void ApplyFieldZeroable(const std::string& key, u32 candidate, int confidencePct, ProbeResult& res);
    bool Confirmed(const std::string& key, u32 candidate, int confidencePct, ProbeResult& res);

    void ProbeUObjectFields(ProbeResult& res);
    void ProbeUStructFields(ProbeResult& res);
    void ProbeClassCDO(ProbeResult& res);
    void ProbePropertyModel(ProbeResult& res);
    void ProbeTypedPropertyExtras(ProbeResult& res);
    void ProbeFunctionFields(ProbeResult& res);
    void ProbeEnumFields(ProbeResult& res);
};

} // namespace dumper
