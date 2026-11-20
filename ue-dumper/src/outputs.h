// ============================================================================
//  UnrealDumperX - outputs.h
//  Output writers: Names.txt / Objects.txt / offsets.txt / signatures.txt
//  and the per-game <Game>_sigs.txt signature archive.
// ============================================================================
#pragma once
#include "finder.h"

namespace udx {
namespace vt { struct ResolvedFunc; }
namespace out {

bool writeNamesTxt(const std::string& path, const ue::NameDb& names);
bool writeObjectsTxt(const std::string& path, Process& proc,
                     const ue::Offsets& off, const ue::ObjectDb& objects,
                     const ue::NameDb& names);
bool writeOffsetsTxt(const std::string& path, const ue::Offsets& off,
                     UEVersion ver, const std::string& gameName,
                     const std::string& layoutNote);
bool writeSignaturesTxt(const std::string& path,
                        const std::vector<ue::SigRecord>& sigs,
                        const std::string& title,
                        const std::vector<vt::ResolvedFunc>* funcs = nullptr);

} // namespace out
} // namespace udx
