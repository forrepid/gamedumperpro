// DumperPro - GObjects / TUObjectArray parsing with layout auto-detection
#pragma once
#include "../framework.h"
#include "ue/Offsets.h"

namespace dumper {

class IMemoryReader;
class NameArray;

struct ObjItem {
    u64 objectAddr = 0;
    i32 flags = 0;
    i32 clusterRoot = 0;
    i32 serialNumber = 0;
    u64 itemAddr = 0;
    i32 index = -1;
};

class ObjectArray {
public:
    // names may be null (used by early validation); enables stronger validation when set
    bool TryInit(IMemoryReader& r, UEOffsets& off, const UEVersion& v,
                 const NameArray* names, std::string* err = nullptr);
    bool IsReady() const { return ready_; }

    i32 Num() const { return num_; }
    u64 GObjectsVA() const { return gObjectsVA_; }
    u32 ItemStride() const { return stride_; }
    u32 ChunkSize() const { return chunkSize_; }
    bool Flat() const { return flat_; }
    std::string LayoutInfo() const;

    ObjItem At(i32 index) const;          // reads item (safe on invalid index -> zeroed)
    u64 ObjectAt(i32 index) const;
    bool ValidateIndex(i32 index) const;

    // static validation used by SigFinder on candidate addresses
    static bool ValidateCandidate(IMemoryReader& r, UEOffsets& off, const UEVersion& v,
                                  u64 gObjectsVA, i32 nameCount, std::string* why = nullptr);

private:
    IMemoryReader* r_ = nullptr;
    UEOffsets* off_ = nullptr;
    UEVersion ver_;
    const NameArray* names_ = nullptr;

    u64 gObjectsVA_ = 0;
    i32 num_ = 0;
    bool flat_ = false;
    u32 stride_ = 0;
    u32 chunkSize_ = 0;
    i32 numChunks_ = 0;
    bool ready_ = false;
    std::vector<u64> chunks_;

    u64 ItemAddr(i32 index) const;
    bool DetectLayout(std::string* err);
    double SampleValid(u64 base, u32 stride, bool chunked, u32 chunkSize, i32 count);
};

} // namespace dumper
