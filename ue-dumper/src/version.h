// ============================================================================
//  UnrealDumperX - version.h
//  UE version detection (Module 3 helper).
//
//  IMPORTANT NOTE #13: UE builds embed a release string inside their data
//  sections ("++UE4+Release-4.27.2-0+++..." / "++UE5+Release-5.2.1-...").
//  The scanner reads .rdata/.data and extracts the engine generation.
// ============================================================================
#pragma once
#include "ue_types.h"

namespace udx {
class Process;
struct ModuleInfo;
}

namespace udx::ue {

// Detection pipeline: games.ini -> embedded release string -> "Unknown".
UEVersion detectVersion(Process& proc, const ModuleInfo& mainModule,
                        std::string* methodOut = nullptr);

// "Release-4.27" | "++UE5+Release-5.2.1" | "4.27" | "UE5.2" -> parsed value.
std::optional<UEVersion> versionFromReleaseString(const std::string& s);
std::optional<UEVersion> versionFromIniValue(const std::string& s);

} // namespace udx::ue
