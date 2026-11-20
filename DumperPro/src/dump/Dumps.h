// DumperPro - Names.txt / Objects.txt dumps (+ JSON schema outputs)
#pragma once
#include "../framework.h"
#include "ue/UEObject.h"

namespace dumper {

class UEContext;

void DumpNames(UEContext& ctx, const fs::path& file);     // "0x0000: Name"
void DumpObjects(UEContext& ctx, const fs::path& file);   // "[0x0000] Class Name Path VA"

// Makine-okur JSON semalari (roadmap 2.1: JSON cikti secenekleri):
//   names.json   : [{"index":N,"name":"..."}, ...]
//   objects.json : [{"index":N,"class":"...","name":"...","path":"...","address":"0x..."}, ...]
void DumpNamesJson(UEContext& ctx, const fs::path& file);
void DumpObjectsJson(UEContext& ctx, const fs::path& file);

} // namespace dumper
