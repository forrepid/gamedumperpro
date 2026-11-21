#include "dump/ResultExport.h"
#include "utils/Logger.h"
#include "utils/Progress.h"
#include "ue/ObjectArray.h"
#include "ue/NameArray.h"

#include <ctime>

namespace dumper {

namespace {

// JSON string kacis (Dumps.cpp JsonEscDump ile ayni sozlasmA)
std::string JsonEsc(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (unsigned char ch : in) {
        switch (ch) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (ch < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", ch); out += b; }
                else out += (char)ch;
        }
    }
    return out;
}

std::string HexW(u64 v, int width) {
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%0*llX", width, (unsigned long long)v);
    return buf;
}

std::string Hex64(u64 v) { return HexW(v, 12); }

std::string NowStamp() {
    std::time_t t = std::time(nullptr);
    std::tm tmv;
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    return buf;
}

void WriteParamCompact(std::ostream& os, const FuncJsonParam& p) {
    os << "{\"name\": \"" << JsonEsc(p.name)
       << "\", \"type\": \"" << JsonEsc(p.type)
       << "\", \"offset\": \"" << (p.offset < 0 ? std::string("0x0") : HexW((u64)p.offset, 2))
       << "\", \"size\": \"" << HexW((u64)(p.size < 0 ? 0 : p.size), 2)
       << "\", \"flags\": \"" << HexW(p.flags, 8)
       << "\", \"target\": \"" << JsonEsc(p.target) << "\"}";
}

} // namespace

// ============================================================================
// CollectFunctionsJson - GObjects -> UClass -> GetFunctions
// ============================================================================

bool CollectFunctionsJson(UEContext& ctx, std::vector<FuncJsonRec>& out) {
    ObjectArray* objs = ctx.objects;
    if (!objs || !objs->IsReady()) return false;
    const i32 num = objs->Num();
    if (num <= 0) return false;

    // paket adi cache: nesne adresi -> en ust Outer adi
    std::unordered_map<u64, std::string> pkgByAddr;
    pkgByAddr.reserve(4096);
    constexpr int kMaxHops = 64;

    Progress p("Functions", (u64)num);

    for (i32 i = 0; i < num; i++) {
        const u64 addr = objs->ObjectAt(i); // gecersiz indeks icin 0 doner
        p.Add();
        if (!addr) continue;

        UEObject obj(&ctx, addr, i);
        if (!obj.IsClassObj()) continue;
        const std::string cls = obj.GetName();
        if (cls.empty()) continue;

        // ---- paket adi: en ust Outer adi (SDKGenerator ile ayni kural) ----
        std::string pkg;
        const auto cached = pkgByAddr.find(addr);
        if (cached != pkgByAddr.end()) {
            pkg = cached->second;
        } else {
            std::vector<u64> chain;
            std::unordered_set<u64> visited;
            u64 cur = addr;
            std::string top;
            for (int hops = 0; cur != 0 && hops < kMaxHops; hops++) {
                if (!visited.insert(cur).second) break; // dongu korumasi
                chain.push_back(cur);
                const auto hit = pkgByAddr.find(cur);
                if (hit != pkgByAddr.end()) { top = hit->second; break; }
                UEObject node(&ctx, cur, -1);
                const u64 outer = node.GetOuter();
                if (!outer) { top = node.GetName(); break; }
                cur = outer;
            }
            if (top.empty()) top = "Core";
            for (u64 a : chain) pkgByAddr.emplace(a, top);
            pkg = top;
        }

        // ---- fonksiyonlar ----
        std::vector<UEObject::Func> fs = obj.GetFunctions();
        for (const UEObject::Func& f : fs) {
            FuncJsonRec r;
            r.cls = cls;
            r.pkg = pkg;
            r.name = f.name;
            r.native = f.nativeFunc;
            r.ufunc = f.addr;
            r.paramsSize = f.paramsSize;
            r.flags = f.flags;
            if (ctx.mod && f.nativeFunc && ctx.mod->Contains(f.nativeFunc)) {
                r.rvaOk = true;
                r.rva = ctx.mod->VaToRva(f.nativeFunc);
            }
            for (const UEObject::Prop& pr : f.params) {
                FuncJsonParam jp;
                jp.name = pr.name;
                jp.type = pr.type;
                jp.target = pr.auxName;
                jp.offset = pr.offset;
                jp.size = pr.elementSize;
                jp.flags = pr.flags;
                r.params.push_back(std::move(jp));
            }
            if (f.ret) {
                r.hasRet = true;
                const UEObject::Prop& pr = *f.ret;
                r.ret.name = pr.name;
                r.ret.type = pr.type;
                r.ret.target = pr.auxName;
                r.ret.offset = pr.offset;
                r.ret.size = pr.elementSize;
                r.ret.flags = pr.flags;
            }
            out.push_back(std::move(r));
        }
    }
    p.Done(std::to_string(out.size()) + " functions");
    return true;
}

// ============================================================================
// WriteFunctionsJson
// ============================================================================

bool WriteFunctionsJson(const fs::path& file,
                        const std::vector<FuncJsonRec>& funcs,
                        const std::string& game,
                        const std::string& ueVer,
                        const std::string& moduleName,
                        u64 moduleBase) {
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!out.good()) {
        Log::Err("cannot open %s for writing", file.string().c_str());
        return false;
    }

    out << "{\n  \"format\": \"dumperpro-functions\",\n  \"version\": 1,\n";
    out << "  \"tool\": \"DumperPro " << kDumperProVersion << "\",\n";
    out << "  \"count\": " << funcs.size() << ",\n";
    out << "  \"game\": \"" << JsonEsc(game) << "\",\n";
    out << "  \"ue\": \"" << JsonEsc(ueVer) << "\",\n";
    out << "  \"module\": { \"name\": \"" << JsonEsc(moduleName)
        << "\", \"base\": \"" << Hex64(moduleBase) << "\" },\n";
    out << "  \"functions\": [\n";

    for (size_t i = 0; i < funcs.size(); i++) {
        const FuncJsonRec& r = funcs[i];
        out << "    {\n";
        out << "      \"cls\": \"" << JsonEsc(r.cls) << "\",\n";
        out << "      \"pkg\": \"" << JsonEsc(r.pkg) << "\",\n";
        out << "      \"name\": \"" << JsonEsc(r.name) << "\",\n";
        out << "      \"rva\": \"" << (r.rvaOk ? HexW(r.rva, 6) : std::string("0x0")) << "\",\n";
        out << "      \"va\": \"" << Hex64(r.native) << "\",\n";
        out << "      \"ufunction\": \"" << Hex64(r.ufunc) << "\",\n";
        out << "      \"native\": \"" << Hex64(r.native) << "\",\n";
        out << "      \"paramsSize\": \"" << HexW(r.paramsSize, 4) << "\",\n";
        out << "      \"flags\": \"" << HexW(r.flags, 8) << "\",\n";

        if (r.params.empty()) {
            out << "      \"params\": []";
        } else {
            out << "      \"params\": [\n";
            for (size_t k = 0; k < r.params.size(); k++) {
                out << "        ";
                WriteParamCompact(out, r.params[k]);
                out << (k + 1 < r.params.size() ? "," : "") << "\n";
            }
            out << "      ]";
        }
        if (r.hasRet) {
            out << ",\n      \"ret\": ";
            WriteParamCompact(out, r.ret);
        }
        out << "\n    }" << (i + 1 < funcs.size() ? "," : "") << "\n";
    }

    out << "  ]\n}\n";
    out.flush();
    if (!out.good()) {
        Log::Err("write failed: %s", file.string().c_str());
        return false;
    }
    Log::Ok("functions.json written (%llu functions)", (unsigned long long)funcs.size());
    return true;
}

// ============================================================================
// WriteResultManifest
// ============================================================================

bool WriteResultManifest(const fs::path& file, const ResultManifest& m) {
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!out.good()) {
        Log::Err("cannot open %s for writing", file.string().c_str());
        return false;
    }

    out << "{\n  \"format\": \"dumperpro-result\",\n  \"version\": 1,\n";
    out << "  \"tool\": \"DumperPro " << kDumperProVersion << "\",\n";
    out << "  \"generated\": \"" << NowStamp() << "\",\n";
    out << "  \"target\": { \"mode\": \"" << JsonEsc(m.mode)
        << "\", \"detail\": \"" << JsonEsc(m.target) << "\" },\n";
    out << "  \"game\": \"" << JsonEsc(m.game) << "\",\n";
    out << "  \"ue\": \"" << JsonEsc(m.ueVer) << "\",\n";
    out << "  \"module\": { \"name\": \"" << JsonEsc(m.moduleName)
        << "\", \"base\": \"" << Hex64(m.moduleBase)
        << "\", \"size\": \"" << HexW(m.moduleSize, 8) << "\" },\n";
    out << "  \"status\": \"" << JsonEsc(m.status) << "\",\n";
    out << "  \"counts\": { \"names\": " << m.namesCount
        << ", \"objects\": " << m.objectsCount
        << ", \"functions\": " << m.functionsCount << " },\n";
    out << "  \"artifacts\": [";
    for (size_t i = 0; i < m.artifacts.size(); i++) {
        out << (i ? ", " : "") << "\"" << JsonEsc(m.artifacts[i]) << "\"";
    }
    out << "]\n}\n";
    out.flush();
    if (!out.good()) {
        Log::Err("write failed: %s", file.string().c_str());
        return false;
    }
    return true;
}

} // namespace dumper
