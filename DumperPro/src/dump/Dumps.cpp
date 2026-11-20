#include "dump/Dumps.h"
#include "utils/Logger.h"
#include "utils/Progress.h"
#include "ue/ObjectArray.h"
#include "ue/NameArray.h"

#include <iomanip>

namespace dumper {

namespace {

// JSON string kacis (dump ciktilari icin ortak)
std::string JsonEscDump(const std::string& in) {
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

} // namespace

void DumpNames(UEContext& ctx, const fs::path& file) {
    if (!ctx.names) return;
    i32 n = ctx.names->Num();

    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!out.good()) {
        Log::Err("cannot open %s for writing", file.string().c_str());
        return;
    }

    Progress p("Names", (u64)n);
    for (i32 i = 0; i < n; i++) {
        out << "0x" << std::hex << std::setw(6) << std::setfill('0') << i << std::dec
            << ": " << ctx.names->Get(i) << "\n";
        p.Add();
    }
    p.Done(ctx.names->ModeInfo());
    out.flush();
    Log::Ok("Names.txt written (%llu names)", (unsigned long long)n);
}

void DumpObjects(UEContext& ctx, const fs::path& file) {
    if (!ctx.objects) return;
    i32 n = ctx.objects->Num();

    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!out.good()) {
        Log::Err("cannot open %s for writing", file.string().c_str());
        return;
    }

    Progress p("Objects", (u64)n);
    for (i32 i = 0; i < n; i++) {
        ObjItem it = ctx.objects->At(i);
        UEObject o(&ctx, it.objectAddr, i);
        if (it.objectAddr) {
            std::string cls = o.GetClassName();
            std::string nm = o.GetName();
            std::string path = o.GetPathName();
            out << "[" << std::setw(6) << std::setfill('0') << i << "] "
                << std::left << std::setw(28) << cls << " "
                << std::left << std::setw(40) << nm << " "
                << std::left << std::setw(48) << path << " 0x"
                << std::hex << it.objectAddr << std::dec << "\n";
        } else {
            out << "[" << std::setw(6) << std::setfill('0') << i << "] <invalid>\n";
        }
        p.Add();
    }
    p.Done();
    out.flush();
    Log::Ok("Objects.txt written (%llu objects)", (unsigned long long)n);
}

// ---------------------------------------------------------------------------
// JSON semalari (--json)
// ---------------------------------------------------------------------------

void DumpNamesJson(UEContext& ctx, const fs::path& file) {
    if (!ctx.names) return;
    i32 n = ctx.names->Num();

    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!out.good()) {
        Log::Err("cannot open %s for writing", file.string().c_str());
        return;
    }

    out << "{\n  \"format\": \"dumperpro-names\",\n  \"count\": " << n << ",\n  \"names\": [\n";
    // Progress yok: JSON yazimi tek akis, ilerleme cubugu ara bosluklar bozar
    for (i32 i = 0; i < n; i++) {
        out << "    {\"index\": " << i << ", \"name\": \"" << JsonEscDump(ctx.names->Get(i)) << "\"}";
        out << (i + 1 < n ? "," : "") << "\n";
    }
    out << "  ]\n}\n";
    out.flush();
    Log::Ok("names.json written (%llu names)", (unsigned long long)n);
}

void DumpObjectsJson(UEContext& ctx, const fs::path& file) {
    if (!ctx.objects) return;
    i32 n = ctx.objects->Num();

    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!out.good()) {
        Log::Err("cannot open %s for writing", file.string().c_str());
        return;
    }

    out << "{\n  \"format\": \"dumperpro-objects\",\n  \"count\": " << n << ",\n  \"objects\": [\n";
    for (i32 i = 0; i < n; i++) {
        ObjItem it = ctx.objects->At(i);
        if (it.objectAddr) {
            UEObject o(&ctx, it.objectAddr, i);
            std::string cls = o.GetClassName();
            std::string nm = o.GetName();
            std::string path = o.GetPathName();
            char addr[32];
            snprintf(addr, sizeof(addr), "0x%llX", (unsigned long long)it.objectAddr);
            out << "    {\"index\": " << i
                << ", \"class\": \"" << JsonEscDump(cls)
                << "\", \"name\": \"" << JsonEscDump(nm)
                << "\", \"path\": \"" << JsonEscDump(path)
                << "\", \"address\": \"" << addr << "\"}";
        } else {
            out << "    {\"index\": " << i << ", \"invalid\": true}";
        }
        out << (i + 1 < n ? "," : "") << "\n";
    }
    out << "  ]\n}\n";
    out.flush();
    Log::Ok("objects.json written (%llu objects)", (unsigned long long)n);
}

} // namespace dumper
