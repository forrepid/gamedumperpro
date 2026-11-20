// ============================================================================
// DumperPro - OffsetProbe: runtime offset discovery by voting over live objects
//
// Every probe collects candidate offsets from evenly spread object samples and
// votes. Core rules applied by ApplyField / ApplyFieldZeroable / Confirmed:
//   - a field whose provenance is Profile is NEVER overwritten; a disagreeing
//     probe candidate produces a diagnostic warning ("... keeping profile")
//   - a field currently 0 ("missing") is auto-applied when confidence >= 65%
//   - a probe candidate equal to the current nonzero value marks a confirmation
//   - a profile entry explicitly left at 0 means "auto-detect" (see games.ini)
// ============================================================================

#include "ue/OffsetProbe.h"
#include "ue/UEObject.h"
#include "ue/ObjectArray.h"
#include "ue/NameArray.h"
#include "core/MemoryReader.h"
#include "utils/Logger.h"
#include "utils/StrUtil.h"

namespace dumper {

namespace {

constexpr int kMinApplyConfidence = 65;

// The header fixes the Probe* member signatures (they only take ProbeResult&),
// so the sample set built by Run() travels through this process-wide state.
// DumperPro instantiates a single OffsetProbe; Run() always resets it.
struct ProbeState {
    std::vector<UEObject> samples;
    int maxObjects = 400;
};

ProbeState& PState() {
    static ProbeState s;
    return s;
}

// ---- small helpers ---------------------------------------------------------

std::string Fmt(const char* fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return buf;
}

void AddWarning(ProbeResult& res, const std::string& w) {
    res.warnings.push_back(w);
    Log::Debug("probe: %s", w.c_str());
}

bool SrcIsProfile(const UEOffsets& off, const std::string& key) {
    const auto it = off.prov.find(key);
    return it != off.prov.end() && it->second.src == UEOffsets::Src::Profile;
}

// quick heap-pointer sanity: nonzero, 8-aligned, outside the module image
bool SaneHeap(UEContext& ctx, u64 p) {
    if (!p || (p & 7)) return false;
    if (ctx.mod && ctx.mod->Contains(p)) return false;   // UObject instances live on the heap
    return ctx.IsValidHeapPtr(p);
}

bool IsPow2(u64 v) { return v != 0 && (v & (v - 1)) == 0; }

// ---- voting ----------------------------------------------------------------

struct VoteMap {
    std::map<u32, i32> v;

    void Add(u32 x) { v[x]++; }

    i32 Total() const {
        i32 t = 0;
        for (const auto& kv : v) t += kv.second;
        return t;
    }

    // argmax; ties resolve to the lowest offset (std::map order) -> deterministic
    bool Best(u32& x, i32& votes) const {
        bool found = false;
        for (const auto& kv : v)
            if (kv.second > 0 && (!found || kv.second > votes)) {
                votes = kv.second;
                x     = kv.first;
                found = true;
            }
        return found;
    }

    bool BestExcluding(const std::vector<u32>& excl, u32& x, i32& votes) const {
        bool found = false;
        for (const auto& kv : v) {
            if (kv.second <= 0) continue;
            bool skip = false;
            for (u32 e : excl)
                if (e == kv.first) { skip = true; break; }
            if (skip) continue;
            if (!found || kv.second > votes) {
                votes = kv.second;
                x     = kv.first;
                found = true;
            }
        }
        return found;
    }
};

// ---- core apply rules (shared by ApplyField / ApplyFieldZeroable) ----------

void ApplyCommon(UEOffsets& off, const std::string& key, u32 candidate, int conf, ProbeResult& res, bool zeroable) {
    u32* slot = off.Bind(key);
    if (!slot) {
        Log::Debug("probe: unknown field key '%s'", key.c_str());
        return;
    }
    if (candidate == 0) return;   // a probe vote never yields 0; never write 0

    const u32 cur = *slot;
    const auto it = off.prov.find(key);
    const bool isProfile = it != off.prov.end() && it->second.src == UEOffsets::Src::Profile;

    if (isProfile && cur != 0) {
        // never overwrite a meaningful profile value
        if (candidate != cur) {
            AddWarning(res, Fmt("%s: profile=0x%X probe=0x%X (%d%%) - keeping profile",
                                key.c_str(), cur, candidate, conf));
        } else {
            Log::Debug("probe: %s profile value 0x%X confirmed by probe (%d%%)", key.c_str(), cur, conf);
        }
        return;
    }

    // Missing, previously auto-detected, or a profile entry explicitly left at
    // 0 (= "auto-detect" per games.ini) -> apply when confidence is sufficient
    if (cur == 0) {
        if (conf >= kMinApplyConfidence && (zeroable || candidate != 0)) {
            *slot = candidate;
            off.prov[key] = { UEOffsets::Src::AutoDetect, conf };
            res.applied++;
            Log::Debug("probe: %s auto-detected -> 0x%X (%d%%)", key.c_str(), candidate, conf);
        } else {
            Log::Debug("probe: %s candidate 0x%X not applied (confidence %d%%)",
                       key.c_str(), candidate, conf);
        }
        return;
    }

    if (candidate == cur) {
        off.prov[key] = { UEOffsets::Src::AutoDetect, conf };
        res.confirmed++;
        Log::Debug("probe: %s confirmed 0x%X (%d%%)", key.c_str(), cur, conf);
    } else {
        AddWarning(res, Fmt("%s: current=0x%X probe=0x%X (%d%%) - keeping current",
                            key.c_str(), cur, candidate, conf));
    }
}

// marks a confirmation only (value stays untouched)
bool MarkConfirmed(UEOffsets& off, const std::string& key, u32 candidate, int conf, ProbeResult& res) {
    u32* slot = off.Bind(key);
    if (!slot) return false;
    const u32 cur = *slot;
    if (cur == 0 || cur != candidate) return false;
    const auto it = off.prov.find(key);
    if (it != off.prov.end() && it->second.src == UEOffsets::Src::Profile) return false;
    off.prov[key] = { UEOffsets::Src::AutoDetect, conf };
    res.confirmed++;
    Log::Debug("probe: %s confirmed 0x%X (%d%%)", key.c_str(), cur, conf);
    return true;
}

// ---- sampling helpers ------------------------------------------------------

std::vector<UEObject> FilterKind(const std::vector<UEObject>& samples, const char* name, int cap = -1) {
    std::vector<UEObject> out;
    for (UEObject o : samples) {                    // by value: IsType() is non-const
        if (o.IsValid() && o.IsType(name)) {
            out.push_back(o);
            if (cap > 0 && (int)out.size() >= cap) break;
        }
    }
    return out;
}

std::vector<UEObject> FilterStructs(const std::vector<UEObject>& samples) {
    std::vector<UEObject> out;
    for (UEObject o : samples)
        if (o.IsValid() && (o.IsType("Class") || o.IsType("ScriptStruct")))
            out.push_back(o);
    return out;
}

// walk an FField/UField chain; returns up to maxFields heap-sane addresses
std::vector<u64> CollectFieldChain(UEContext& ctx, u64 head, u32 nextOff, int maxFields) {
    std::vector<u64> out;
    if (!SaneHeap(ctx, head)) return out;
    u64 cur = head;
    for (int i = 0; i < maxFields && SaneHeap(ctx, cur); i++) {
        out.push_back(cur);
        const u64 nxt = ctx.reader->ReadPtrOr(cur + nextOff, 0);
        if (!nxt || nxt == cur) break;
        cur = nxt;
    }
    return out;
}

// ---- probe implementations (header members forward into these) -------------

void ProbeUObjectFieldsImpl(UEContext& ctx, const std::vector<UEObject>& samples, ProbeResult& res) {
    UEOffsets&  off     = ctx.off;
    NameArray*  names   = ctx.names;
    ObjectArray* objects = ctx.objects;
    if (!names || !objects || !ctx.reader) return;

    const i32 total = (i32)samples.size();
    if (total < 10) {
        Log::Debug("probe uobject: %d samples (<10) - skipping", total);
        return;
    }

    static const u32 cands[] = {0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28};
    VoteMap vIndex, vClass, vName, vOuter, vFlags;

    // pass 1: index / class / name votes
    for (const UEObject& o : samples) {
        for (u32 X : cands) {
            const u64 at = o.addr + X;

            // index vote: i32@obj+X == expected array position
            const i32 iv = ctx.reader->ReadI32Or(at, -1);
            if (o.index >= 0 && iv == o.index) vIndex.Add(X);

            // class vote: self-referential UClass pointer (UClass::ClassPrivate == this)
            const u64 T = ctx.reader->ReadPtrOr(at, 0);
            if (T && T != o.addr && SaneHeap(ctx, T)) {
                if (ctx.reader->ReadPtrOr(T + X, 0) == T) vClass.Add(X);
            }

            // name vote: FName {i32 index in names, i32 number < 64}
            const i32 a = ctx.reader->ReadI32Or(at, -1);
            const i32 b = ctx.reader->ReadI32Or(at + 4, -1);
            if (a >= 0 && a < names->Num() && b >= 0 && b < 64) vName.Add(X);
        }
    }

    // pass 2: outer vote (skip offsets that already collected class votes) + weak flags vote
    for (const UEObject& o : samples) {
        for (u32 X : cands) {
            const auto cit = vClass.v.find(X);
            if (cit != vClass.v.end() && cit->second > 0) continue;

            const u64 T = ctx.reader->ReadPtrOr(o.addr + X, 0);
            if (!T || T == o.addr || !SaneHeap(ctx, T)) continue;
            if (ctx.reader->ReadPtrOr(T + X, 0) == T) continue;   // self-referential => class, not outer
            if (off.objIndexOff != 0) {
                const i32 ti = ctx.reader->ReadI32Or(T + off.objIndexOff, -1);
                if (ti < 0 || ti >= objects->Num()) continue;
            }
            vOuter.Add(X);
        }
        for (u32 X : cands) {
            const u32 val = ctx.reader->ReadU32Or(o.addr + X, 0);
            if (val != 0 && (val & 0xF0000000u) == 0) vFlags.Add(X);   // weak
        }
    }

    const auto confOf = [total](i32 votes) { return (int)((i64)votes * 100 / total); };
    std::vector<u32> winners;

    // uobject.index: only applies when currently 0
    u32 bx = 0;
    i32 bv = 0;
    if (vIndex.Best(bx, bv) && bv > 0) {
        winners.push_back(bx);
        if (off.objIndexOff == 0) {
            ApplyCommon(off, "uobject.index", bx, confOf(bv), res, true);
        } else {
            Log::Debug("probe uobject: index candidate 0x%X (%d%%) ignored - current 0x%X kept (index applies only when 0)",
                       bx, confOf(bv), off.objIndexOff);
        }
    }

    // uobject.class / name / outer: apply only when 0, else confirm or warn
    const auto handle = [&](const char* key, u32 curVal, const VoteMap& vm) {
        u32 b2 = 0;
        i32 v2 = 0;
        if (!vm.Best(b2, v2) || v2 <= 0) return;
        winners.push_back(b2);
        const int conf = confOf(v2);
        if (curVal == 0) {
            ApplyCommon(off, key, b2, conf, res, true);
        } else if (b2 == curVal) {
            MarkConfirmed(off, key, curVal, conf, res);
        } else {
            const bool prof = SrcIsProfile(off, key);
            AddWarning(res, Fmt("%s: %s=0x%X probe=0x%X (%d%%) - keeping %s",
                                key, prof ? "profile" : "current", curVal, b2, conf,
                                prof ? "profile" : "current"));
        }
    };
    handle("uobject.class", off.objClassOff, vClass);
    handle("uobject.name",  off.objNameOff,  vName);
    handle("uobject.outer", off.objOuterOff, vOuter);

    // uobject.flags: weak vote; offsets that won the strong votes are excluded
    u32 bf = 0;
    i32 vf = 0;
    if (vFlags.BestExcluding(winners, bf, vf) && vf > 0)
        ApplyCommon(off, "uobject.flags", bf, confOf(vf), res, false);

    Log::Debug("probe uobject: votes - index=%d class=%d name=%d outer=%d flags=%d (samples=%d)",
               vIndex.Total(), vClass.Total(), vName.Total(), vOuter.Total(), vFlags.Total(), total);
}

void ProbeUStructFieldsImpl(UEContext& ctx, const std::vector<UEObject>& samples, ProbeResult& res) {
    UEOffsets& off = ctx.off;
    if (!ctx.reader) return;

    const std::vector<UEObject> structs = FilterStructs(samples);
    if ((i32)structs.size() < 20) {
        Log::Debug("probe struct: %d struct samples (<20) - skipping", (int)structs.size());
        return;
    }
    const i32 total = (i32)structs.size();

    VoteMap vSuper, vChildren, vChildProps, vPSize;

    for (const UEObject& s : structs) {
        const u64 cls = ctx.reader->ReadPtrOr(s.addr + off.objClassOff, 0);

        for (u32 X = 0x28; X <= 0x50; X += 8) {
            const u64 T = ctx.reader->ReadPtrOr(s.addr + X, 0);
            if (!T || T == s.addr || !SaneHeap(ctx, T)) continue;

            // super vote: T's class pointer equals the sample's class pointer
            // (UClass::SuperStruct is again a UClass, UScriptStruct likewise)
            const u64 Tcls = ctx.reader->ReadPtrOr(T + off.objClassOff, 0);
            if (cls && Tcls == cls) vSuper.Add(X);

            // children vote: T's class name is "Function" (UField chain head)
            {
                UEObject t(&ctx, T, -1);
                if (t.IsType("Function")) vChildren.Add(X);
            }

            // childproperties vote: T's FFieldClass name contains "Property"
            if (off.useFFields) {
                const std::string fcn = ctx.FieldClassName(T);
                if (str::Contains(fcn, "Property")) vChildProps.Add(X);
            }
        }

        // propertiessize vote: plausible nonzero u32 sizes
        static const u32 pX[] = {0x3C, 0x40, 0x44, 0x48, 0x4C, 0x50};
        for (u32 X : pX) {
            const u32 v = ctx.reader->ReadU32Or(s.addr + X, 0);
            if (v != 0 && v <= 0x40000u) vPSize.Add(X);
        }
    }

    const auto apply1 = [&](const char* key, const VoteMap& vm) {
        u32 bx = 0;
        i32 bv = 0;
        if (!vm.Best(bx, bv) || bv <= 0) return;
        ApplyCommon(off, key, bx, (int)((i64)bv * 100 / total), res, false);   // confirm/warn; apply-when-0
    };

    apply1("struct.super", vSuper);
    apply1("struct.children", vChildren);
    if (off.useFFields) apply1("struct.childproperties", vChildProps);
    apply1("struct.propertiessize", vPSize);

    Log::Debug("probe struct: votes - super=%d children=%d childprops=%d psize=%d (samples=%d)",
               vSuper.Total(), vChildren.Total(), vChildProps.Total(), vPSize.Total(), total);
}

void ProbeClassCDOImpl(UEContext& ctx, const std::vector<UEObject>& samples, ProbeResult& res) {
    UEOffsets& off = ctx.off;
    if (!ctx.reader) return;

    const std::vector<UEObject> classes = FilterKind(samples, "Class");
    if ((i32)classes.size() < 20) {
        Log::Debug("probe cdo: %d class samples (<20) - skipping", (int)classes.size());
        return;
    }
    const i32 total = (i32)classes.size();

    VoteMap vCdo;
    for (const UEObject& c : classes) {
        for (u32 X = 0x50; X <= 0x1C0; X += 8) {
            const u64 T = ctx.reader->ReadPtrOr(c.addr + X, 0);
            if (!T || T == c.addr || !SaneHeap(ctx, T)) continue;
            const u32 fl = ctx.reader->ReadU32Or(T + off.objFlagsOff, 0);
            if (fl & UEOffsets::kCDOFlag) vCdo.Add(X);   // RF_ClassDefaultObject
        }
    }

    u32 bx = 0;
    i32 bv = 0;
    if (vCdo.Best(bx, bv) && bv > 0)
        ApplyCommon(off, "class.cdo", bx, (int)((i64)bv * 100 / total), res, true);   // only applies when 0

    Log::Debug("probe cdo: votes=%d (samples=%d)", vCdo.Total(), total);
}

void ProbePropertyModelImpl(UEContext& ctx, const std::vector<UEObject>& samples, ProbeResult& res) {
    UEOffsets& off   = ctx.off;
    NameArray* names = ctx.names;
    if (!off.useFFields || !names || !ctx.reader) return;

    const std::vector<UEObject> classes = FilterKind(samples, "Class", 30);
    if (classes.empty()) {
        Log::Debug("probe ffield: no class samples - skipping");
        return;
    }

    // ---- part 1: validate ffNextOff over ChildProperties chains ----
    static const u32 nextCands[] = {0x10, 0x18, 0x20};

    const auto validField = [&](u64 f) -> bool {
        if (!SaneHeap(ctx, f)) return false;
        const i32 nidx = ctx.reader->ReadI32Or(f + off.ffNameOff, -1);
        if (nidx < 0 || nidx >= names->Num()) return false;
        const std::string fcn = ctx.FieldClassName(f);
        return !fcn.empty() && str::EndsWith(fcn, "Property");
    };

    struct NextScore { i32 total = 0; i32 classesOk = 0; };
    std::map<u32, NextScore> sc;

    for (const UEObject& c : classes) {
        const u64 head = ctx.reader->ReadPtrOr(c.addr + off.stChildPropsOff, 0);
        if (!SaneHeap(ctx, head)) continue;
        for (u32 cn : nextCands) {
            i32 score = 0;
            u64 cur = head;
            for (int i = 0; i < 64 && SaneHeap(ctx, cur); i++) {
                if (validField(cur)) score++;
                const u64 nxt = ctx.reader->ReadPtrOr(cur + cn, 0);
                if (!nxt || nxt == cur) break;
                cur = nxt;
            }
            sc[cn].total += score;
            if (score > 0) sc[cn].classesOk++;
        }
    }

    std::vector<std::pair<u32, i32>> ranked;   // (candidate, total score)
    for (const auto& kv : sc)
        if (kv.second.total > 0) ranked.push_back({kv.first, kv.second.total});
    std::stable_sort(ranked.begin(), ranked.end(),
                     [](const std::pair<u32, i32>& a, const std::pair<u32, i32>& b) { return a.second > b.second; });
    if (!ranked.empty()) {
        // clear winner -> 95%, tie -> 70% (argmax picked the lowest offset)
        const int conf = (ranked.size() == 1 || ranked[0].second > ranked[1].second) ? 95 : 70;
        Log::Debug("probe ffield: ffNext candidate 0x%X score %d (conf %d%%)", ranked[0].first, ranked[0].second, conf);
        ApplyCommon(off, "ffield.next", ranked[0].first, conf, res, true);
    }

    // ---- part 2: common property offsets over sampled properties ----
    std::vector<u64> props;
    for (const UEObject& c : classes) {
        const u64 head = ctx.reader->ReadPtrOr(c.addr + off.stChildPropsOff, 0);
        for (u64 f : CollectFieldChain(ctx, head, off.ffNextOff, 64)) {
            props.push_back(f);
            if ((i32)props.size() >= 240) break;
        }
        if ((i32)props.size() >= 240) break;
    }
    if (props.empty()) {
        Log::Debug("probe property: no properties sampled - common offsets skipped");
        return;
    }
    const i32 nP = (i32)props.size();

    VoteMap vDim, vElem, vOffs, vFlags;
    for (u64 p : props) {
        for (u32 X = 0x28; X <= 0x58; X += 4) {
            const u32 d = ctx.reader->ReadU32Or(p + X, 0);
            if (d >= 1 && d <= 64) vDim.Add(X);                       // ArrayDim

            const u32 es = ctx.reader->ReadU32Or(p + X, 0);
            if (es >= 1 && es <= 0x1000u) vElem.Add(X);               // ElementSize

            const u32 po = ctx.reader->ReadU32Or(p + X, 0);
            if (po != 0 && po < 0x100000u && (po & 3u) == 0) vOffs.Add(X);   // Offset_Internal (plausible)

            if (X >= 0x30) {
                const u64 fl = ctx.reader->ReadU64Or(p + X, 0);
                if (fl != 0 && (fl & ~UEOffsets::kPropertyFlagMask) == 0) vFlags.Add(X);   // EPropertyFlags
            }
        }
    }

    const auto applyProp = [&](const char* key, const VoteMap& vm) {
        u32 bx = 0;
        i32 bv = 0;
        if (!vm.Best(bx, bv) || bv <= 0) return;
        ApplyCommon(off, key, bx, (int)((i64)bv * 100 / nP), res, false);   // apply-when-0 / confirm / warn
    };
    applyProp("property.arraydim", vDim);
    applyProp("property.elementsize", vElem);
    applyProp("property.offset", vOffs);
    applyProp("property.flags", vFlags);

    Log::Debug("probe property: votes - dim=%d elem=%d offset=%d flags=%d (props=%d)",
               vDim.Total(), vElem.Total(), vOffs.Total(), vFlags.Total(), nP);
}

void ProbeTypedPropertyExtrasImpl(UEContext& ctx, const std::vector<UEObject>& samples, ProbeResult& res) {
    UEOffsets& off = ctx.off;
    if (!off.useFFields || !ctx.reader) return;

    const std::vector<UEObject> classes = FilterKind(samples, "Class", 40);
    if (classes.empty()) {
        Log::Debug("probe typed-props: no class samples - skipping");
        return;
    }

    // bucket up to ~50 properties of each interesting kind from class chains
    static const char* kKinds[] = {
        "ObjectProperty", "ClassProperty", "StructProperty", "ArrayProperty",
        "SetProperty", "MapProperty", "EnumProperty", "BoolProperty",
    };
    std::map<std::string, std::vector<u64>> buckets;
    for (const UEObject& c : classes) {
        const u64 head = ctx.reader->ReadPtrOr(c.addr + off.stChildPropsOff, 0);
        for (u64 f : CollectFieldChain(ctx, head, off.ffNextOff, 96)) {
            const std::string kind = ctx.FieldClassName(f);
            if (kind.empty()) continue;
            for (const char* k : kKinds) {
                if (kind == k) {
                    std::vector<u64>& lst = buckets[k];
                    if ((int)lst.size() < 50) lst.push_back(f);
                    break;
                }
            }
        }
    }

    const auto ownerOf = [&](u64 p) { return ctx.reader->ReadPtrOr(p + off.ffOwnerOff, 0); };
    const auto isPropField = [&](u64 t) {
        const std::string s = ctx.FieldClassName(t);
        return !s.empty() && str::EndsWith(s, "Property");
    };
    const auto classNameOf = [&](u64 t) {
        UEObject o(&ctx, t, -1);
        return o.GetClassName();
    };
    const auto applyTyped = [&](const char* key, const VoteMap& vm, i32 totalSamples) {
        if (totalSamples <= 0) return;
        u32 bx = 0;
        i32 bv = 0;
        if (!vm.Best(bx, bv) || bv <= 0) return;
        ApplyCommon(off, key, bx, (int)((i64)bv * 100 / totalSamples), res, true);   // apply-when-0
    };

    VoteMap vObj, vStruct, vEnum, vArrIn, vSetIn, vMapKey;
    i32 nObj = 0, nStruct = 0, nEnum = 0, nArr = 0, nSet = 0, nMap = 0;

    // ObjectProperty / ClassProperty -> property.objectclass (target is a UClass)
    for (const char* kind : {"ObjectProperty", "ClassProperty"}) {
        for (u64 p : buckets[kind]) {
            nObj++;
            for (u32 X = 0x48; X <= 0x88; X += 8) {
                const u64 T = ctx.reader->ReadPtrOr(p + X, 0);
                if (!T || T == p || !SaneHeap(ctx, T)) continue;
                if (classNameOf(T) != "Class") continue;
                vObj.Add(X);
            }
        }
    }

    // StructProperty -> property.struct (target is a UScriptStruct)
    for (u64 p : buckets["StructProperty"]) {
        nStruct++;
        for (u32 X = 0x48; X <= 0x88; X += 8) {
            const u64 T = ctx.reader->ReadPtrOr(p + X, 0);
            if (!T || !SaneHeap(ctx, T)) continue;
            if (classNameOf(T) != "ScriptStruct") continue;
            vStruct.Add(X);
        }
    }

    // EnumProperty -> property.enum (target is a UEnum)
    for (u64 p : buckets["EnumProperty"]) {
        nEnum++;
        for (u32 X = 0x48; X <= 0x88; X += 8) {
            const u64 T = ctx.reader->ReadPtrOr(p + X, 0);
            if (!T || !SaneHeap(ctx, T)) continue;
            if (classNameOf(T) != "Enum") continue;
            vEnum.Add(X);
        }
    }

    // ArrayProperty / SetProperty -> inner (FField property owned by the same owner)
    for (const char* kind : {"ArrayProperty", "SetProperty"}) {
        VoteMap& vm = (kind[0] == 'A') ? vArrIn : vSetIn;
        i32&     n  = (kind[0] == 'A') ? nArr   : nSet;
        for (u64 p : buckets[kind]) {
            n++;
            const u64 owner = ownerOf(p);
            for (u32 X = 0x48; X <= 0x88; X += 8) {
                const u64 T = ctx.reader->ReadPtrOr(p + X, 0);
                if (!T || T == p || !SaneHeap(ctx, T)) continue;
                if (!isPropField(T)) continue;
                if (ownerOf(T) != owner) continue;
                vm.Add(X);
            }
        }
    }

    // MapProperty -> key/value pair (two FField properties, same owner, 8 bytes apart)
    for (u64 p : buckets["MapProperty"]) {
        nMap++;
        const u64 owner = ownerOf(p);
        for (u32 X = 0x48; X <= 0x88; X += 8) {
            const u64 T1 = ctx.reader->ReadPtrOr(p + X, 0);
            const u64 T2 = ctx.reader->ReadPtrOr(p + X + 8, 0);
            if (!T1 || !T2 || T1 == p || T2 == p) continue;
            if (!SaneHeap(ctx, T1) || !SaneHeap(ctx, T2)) continue;
            if (!isPropField(T1) || !isPropField(T2)) continue;
            if (ownerOf(T1) != owner || ownerOf(T2) != owner) continue;
            vMapKey.Add(X);
        }
    }

    applyTyped("property.objectclass", vObj, nObj);
    applyTyped("property.struct",      vStruct, nStruct);
    applyTyped("property.enum",        vEnum, nEnum);
    applyTyped("property.array_inner", vArrIn, nArr);
    applyTyped("property.set_inner",   vSetIn, nSet);

    u32 bx = 0;
    i32 bv = 0;
    if (vMapKey.Best(bx, bv) && bv > 0 && nMap > 0) {
        const int conf = (int)((i64)bv * 100 / nMap);
        ApplyCommon(off, "property.map_key",   bx,     conf, res, true);
        ApplyCommon(off, "property.map_value", bx + 8, conf, res, true);
    }

    // BoolProperty: bytemask (pow2 <= 0x80) + fieldmask (pow2, >= bytemask) 8 bytes... 4 bytes apart
    VoteMap vBool;
    i32 nBool = 0;
    for (u64 p : buckets["BoolProperty"]) {
        nBool++;
        for (u32 X = 0x48; X <= 0x98; X += 4) {
            const u32 bm = ctx.reader->ReadU32Or(p + X, 0);
            const u32 fm = ctx.reader->ReadU32Or(p + X + 4, 0);
            if (!IsPow2(bm) || bm > 0x80u) continue;
            if (!IsPow2(fm) || fm < bm) continue;
            vBool.Add(X);
        }
    }
    if (vBool.Best(bx, bv) && bv > 0 && nBool > 0) {
        const int conf = (int)((i64)bv * 100 / nBool);
        ApplyCommon(off, "property.bool_bytemask",  bx,     conf, res, true);
        ApplyCommon(off, "property.bool_fieldmask", bx + 4, conf, res, true);
    }

    Log::Debug("probe typed-props: obj=%d struct=%d enum=%d arr=%d set=%d map=%d bool=%d sample(s)",
               nObj, nStruct, nEnum, nArr, nSet, nMap, nBool);
}

void ProbeFunctionFieldsImpl(UEContext& ctx, const std::vector<UEObject>& samples, ProbeResult& res) {
    UEOffsets& off = ctx.off;
    if (!ctx.reader) return;

    std::vector<u64> fns;
    for (const UEObject& o : FilterKind(samples, "Function", 50))
        fns.push_back(o.addr);
    if ((i32)fns.size() < 10) {
        Log::Debug("probe function: %d samples (<10) - skipping", (int)fns.size());
        return;
    }
    const i32 total = (i32)fns.size();

    VoteMap vFunc, vParams, vFlags;
    for (u64 f : fns) {
        for (u32 X = 0x30; X <= 0x80; X += 8) {
            // func vote: a pointer into the module's executable section
            const u64 T = ctx.reader->ReadPtrOr(f + X, 0);
            if (T && ctx.mod && ctx.mod->Contains(T) && ctx.mod->InExecSection(T)) vFunc.Add(X);

            // paramssize vote: plausible byte size (0 excluded - a failed read would vote everywhere)
            const u32 ps = ctx.reader->ReadU32Or(f + X, 0);
            if (ps != 0 && ps < 0x2000u) vParams.Add(X);

            // flags vote: any nonzero u32 below 0x80
            if (X < 0x80) {
                const u32 fl = ctx.reader->ReadU32Or(f + X, 0);
                if (fl != 0) vFlags.Add(X);
            }
        }
    }

    u32 bx = 0;
    i32 bv = 0;
    if (vFunc.Best(bx, bv) && bv > 0)
        ApplyCommon(off, "function.func", bx, (int)((i64)bv * 100 / total), res, true);        // apply-when-0
    if (vParams.Best(bx, bv) && bv > 0)
        ApplyCommon(off, "function.paramssize", bx, (int)((i64)bv * 100 / total), res, false); // confirm/warn
    if (vFlags.Best(bx, bv) && bv > 0)
        ApplyCommon(off, "function.flags", bx, (int)((i64)bv * 100 / total), res, false);      // confirm/warn

    Log::Debug("probe function: votes - func=%d params=%d flags=%d (samples=%d)",
               vFunc.Total(), vParams.Total(), vFlags.Total(), total);
}

void ProbeEnumFieldsImpl(UEContext& ctx, const std::vector<UEObject>& samples, ProbeResult& res) {
    UEOffsets& off   = ctx.off;
    NameArray* names = ctx.names;
    if (!names || !ctx.reader) return;

    std::vector<u64> enums;
    for (const UEObject& o : FilterKind(samples, "Enum", 20))
        enums.push_back(o.addr);
    if ((i32)enums.size() < 3) {
        Log::Debug("probe enum: %d samples (<3) - skipping", (int)enums.size());
        return;
    }
    const i32 total = (i32)enums.size();

    static const u32 cands[] = {0x28, 0x30, 0x38, 0x40};
    VoteMap vNames;

    // TArray<TPair<FName, int8>>: 12-byte stride (UE4.25+/UE5); retry 9-byte packed layout
    for (int stride : {12, 9}) {
        vNames.v.clear();
        for (u64 e : enums) {
            for (u32 X : cands) {
                const u64 arr = ctx.reader->ReadPtrOr(e + X, 0);
                const i32 num = ctx.reader->ReadI32Or(e + X + 8, -1);
                if (!arr || !SaneHeap(ctx, arr)) continue;
                if (num < 1 || num > 4096) continue;

                // first pair: FName index must be a valid name
                const i32 n0 = ctx.reader->ReadI32Or(arr, -1);
                if (n0 < 0 || n0 >= names->Num()) continue;
                // stride check: second pair's name index must also be valid
                if (num >= 2) {
                    const i32 n1 = ctx.reader->ReadI32Or(arr + stride, -1);
                    if (n1 < 0 || n1 >= names->Num()) continue;
                }
                vNames.Add(X);
            }
        }
        if (vNames.Total() > 0) break;
    }

    u32 bx = 0;
    i32 bv = 0;
    if (vNames.Best(bx, bv) && bv > 0)
        ApplyCommon(off, "enum.names", bx, (int)((i64)bv * 100 / total), res, false);   // confirm / apply-when-0

    Log::Debug("probe enum: votes=%d (samples=%d)", vNames.Total(), total);
}

} // namespace

// ============================================================================
// OffsetProbe members
// ============================================================================

ProbeResult OffsetProbe::Run(int maxObjects) {
    ProbeResult res;
    PState().maxObjects = maxObjects > 0 ? maxObjects : 400;
    PState().samples.clear();

    ObjectArray* objects = ctx_.objects;
    NameArray*   names   = ctx_.names;
    if (!ctx_.reader || !objects || !objects->IsReady() || !names || !names->IsReady()) {
        Log::Warn("OffsetProbe: object/name arrays not ready - runtime probing skipped");
        return res;
    }
    res.ok = true;

    // evenly spread samples over the object array, skipping invalid entries
    const i32 total = objects->Num();
    const int want  = std::min(PState().maxObjects, (int)total);
    if (want <= 0 || total <= 0) {
        Log::Debug("OffsetProbe: no objects to sample");
        return res;
    }

    int kept = 0;
    for (int i = 0; i < want; i++) {
        const i32 idx = (i32)(((i64)total * i) / want);
        const ObjItem it = objects->At(idx);
        if (!it.objectAddr) continue;

        // class pointer validity filter (skipped when objClassOff is itself the probe target)
        if (ctx_.off.objClassOff != 0) {
            const u64 cls = ctx_.reader->ReadPtrOr(it.objectAddr + ctx_.off.objClassOff, 0);
            if (!cls || cls == it.objectAddr || !SaneHeap(ctx_, cls)) continue;
        }
        PState().samples.push_back(UEObject(&ctx_, it.objectAddr, idx));
        kept++;
    }
    res.probed = kept;
    Log::Debug("OffsetProbe: %d/%d samples valid (spread over %d objects, max %d)",
               kept, want, total, PState().maxObjects);

    // each probe skips itself when its sample set is empty/insufficient
    ProbeUObjectFields(res);
    ProbeUStructFields(res);
    ProbeClassCDO(res);
    ProbePropertyModel(res);
    ProbeTypedPropertyExtras(res);
    ProbeFunctionFields(res);
    ProbeEnumFields(res);

    Log::Debug("OffsetProbe summary: applied=%d confirmed=%d warnings=%llu (probed=%d)",
               res.applied, res.confirmed, (unsigned long long)res.warnings.size(), res.probed);
    return res;
}

void OffsetProbe::ApplyField(const std::string& key, u32 candidate, int confidencePct, ProbeResult& res) {
    ApplyCommon(ctx_.off, key, candidate, confidencePct, res, false);
}

void OffsetProbe::ApplyFieldZeroable(const std::string& key, u32 candidate, int confidencePct, ProbeResult& res) {
    ApplyCommon(ctx_.off, key, candidate, confidencePct, res, true);
}

bool OffsetProbe::Confirmed(const std::string& key, u32 candidate, int confidencePct, ProbeResult& res) {
    return MarkConfirmed(ctx_.off, key, candidate, confidencePct, res);
}

void OffsetProbe::ProbeUObjectFields(ProbeResult& res) {
    ProbeUObjectFieldsImpl(ctx_, PState().samples, res);
}

void OffsetProbe::ProbeUStructFields(ProbeResult& res) {
    ProbeUStructFieldsImpl(ctx_, PState().samples, res);
}

void OffsetProbe::ProbeClassCDO(ProbeResult& res) {
    ProbeClassCDOImpl(ctx_, PState().samples, res);
}

void OffsetProbe::ProbePropertyModel(ProbeResult& res) {
    ProbePropertyModelImpl(ctx_, PState().samples, res);
}

void OffsetProbe::ProbeTypedPropertyExtras(ProbeResult& res) {
    ProbeTypedPropertyExtrasImpl(ctx_, PState().samples, res);
}

void OffsetProbe::ProbeFunctionFields(ProbeResult& res) {
    ProbeFunctionFieldsImpl(ctx_, PState().samples, res);
}

void OffsetProbe::ProbeEnumFields(ProbeResult& res) {
    ProbeEnumFieldsImpl(ctx_, PState().samples, res);
}

bool OffsetProbe::WriteOffsetsTxt(const fs::path& file) {
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!out.good()) {
        Log::Err("OffsetProbe: cannot open %s for writing", file.string().c_str());
        return false;
    }

    out << "; DumperPro offsets.txt - every struct field offset, value and source\n";

    // merge u32 fields + bool flags into one key-sorted view
    std::map<std::string, std::pair<u64, bool>> entries;   // key -> (value, isBool)
    for (const auto& kv : ctx_.off.BindAllU32())
        entries[kv.first] = {(u64)*kv.second, false};
    for (const auto& kv : ctx_.off.BindAllBool())
        entries[kv.first] = {(u64)(*kv.second ? 1 : 0), true};

    int nProfile = 0, nAuto = 0, nMissing = 0;
    for (const auto& kv : entries) {
        const std::string& key = kv.first;
        const u64 val    = kv.second.first;
        const bool isBool = kv.second.second;

        std::string src = "MISSING";
        const auto it = ctx_.off.prov.find(key);
        if (it != ctx_.off.prov.end()) {
            if (it->second.src == UEOffsets::Src::Profile) {
                src = "Profile";
                nProfile++;
            } else if (it->second.src == UEOffsets::Src::AutoDetect) {
                src = "AutoDetect (" + std::to_string(it->second.confidence) + "%)";
                nAuto++;
            } else {
                nMissing++;
            }
        } else {
            nMissing++;
        }

        if (isBool)
            out << key << " = " << (val ? 1 : 0) << " ; src=" << src
                << " ; 0x" << std::hex << val << std::dec << "\n";
        else
            out << key << " = 0x" << std::hex << val << " ; src=" << src
                << " ; 0x" << val << std::dec << "\n";
    }

    out << "\n; summary: " << nProfile << " profile, " << nAuto << " autodetect, " << nMissing << " missing\n";
    out.flush();

    Log::Debug("OffsetProbe: offsets.txt written (%d entries: %d profile, %d autodetect, %d missing)",
               (int)entries.size(), nProfile, nAuto, nMissing);
    return true;
}

} // namespace dumper
