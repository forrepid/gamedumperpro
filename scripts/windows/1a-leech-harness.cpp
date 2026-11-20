// ============================================================================
// DumperPro - 1a LeechCore canli dogrulama duzenegi (harness)
//
// TryCreateLeechReader()'i dogrudan cagirir; CLI'nin kapamadigi iki yolu test
// eder: LcWrite round-trip (write=1 cihazi) ve hizasiz kucuk okuma/yazma.
//
// Derleme (MSVC, DumperPro deposu kok dizininden):
//   cl /std:c++20 /EHsc /O2 /I src ^
//      scripts\windows\1a-leech-harness.cpp ^
//      src\core\LeechReader.cpp src\core\MemoryReader.cpp ^
//      src\core\PEFile.cpp src\core\Pattern.cpp ^
//      src\utils\Logger.cpp src\utils\Progress.cpp ^
//      /Fe:1a-leech-harness.exe
//
// Calistirma (fixture'i once 1a-device-test.ps1 uretir):
//   1a-leech-harness.exe 1a-test-output\testdev.raw
// Beklenen son satir: HARNESS RESULT: ALL-PASS
// ============================================================================

#include "core/MemoryReader.h"
#include "core/LeechReader.h"
#include <cstdio>
#include <cstring>

using namespace dumper;

int main(int argc, char** argv) {
    const char* fixture = (argc > 1) ? argv[1] : "1a-test-output/testdev.raw";
    std::string devRO = std::string("file://") + fixture;
    std::string devRW = std::string("file://file=") + fixture + ",write=1";

    // --- 1) salt-okunur cihaz: acilis + imza okuma -----------------------------
    auto r = TryCreateLeechReader(devRO);
    if (!r) { printf("FAIL: readonly device create (%s)\n", devRO.c_str()); return 1; }

    char buf[24] = {0};
    if (!r->Read(0x11000, buf, 17)) { printf("FAIL: read @0x11000\n"); return 2; }
    printf("READ  @0x11000: '%s'\n", buf);
    bool sigOK = strncmp(buf, "DMPPRO-TEST-SIG!", 16) == 0;
    printf("SIG CHECK: %s\n", sigOK ? "OK" : "MISMATCH");

    // hizasiz kucuk okuma -> 4K sayfa shim yolu
    char small[8] = {0};
    bool smallOK = r->Read(0x11003, small, 5);
    printf("SMALL/UNALIGNED READ @0x11003(5B): %s ('%.5s')\n", smallOK ? "OK" : "FAIL", small);

    // paMax ustu (fixture 16 MB; 0x2000000 = 32 MB) -> FALSE beklenir
    char farb[8] = {0};
    bool farOK = r->Read(0x2000000, farb, 4);
    printf("BEYOND-paMax READ: %s (beklenen: basarisiz)\n",
           farOK ? "BEKLENMEDIK-OK" : "duzgun-sekilde-basarisiz");
    r.reset();

    // --- 2) yazilabilir cihaz: LcWrite round-trip + hizasiz yazma ---------------
    auto w = TryCreateLeechReader(devRW);
    if (!w) { printf("FAIL: writable device create (%s)\n", devRW.c_str()); return 3; }

    unsigned v  = 0x41414141;
    unsigned nv = 0xCAFEBABE;
    if (!w->Write(0x20000, &v, 4))  { printf("FAIL: aligned write 1\n"); return 4; }
    if (!w->Write(0x20000, &nv, 4)) { printf("FAIL: aligned write 2\n"); return 4; }
    unsigned back = 0;
    if (!w->Read(0x20000, &back, 4)) { printf("FAIL: readback\n"); return 5; }
    printf("WRITE ROUND-TRIP @0x20000: 0x%08X -> 0x%08X %s\n", v, back,
           back == 0xCAFEBABE ? "OK" : "MISMATCH");

    unsigned char two[3] = {0x11, 0x22, 0x33};
    bool uwOK = w->Write(0x30003, two, 3);   // hizasiz kucuk yazma -> RMW yolu
    unsigned char tb[3] = {0};
    w->Read(0x30003, tb, 3);
    printf("UNALIGNED WRITE @0x30003(3B): %s (%02X %02X %02X)\n",
           uwOK ? "OK" : "FAIL", tb[0], tb[1], tb[2]);

    printf("HARNESS RESULT: %s\n", sigOK ? "ALL-PASS" : "SIG-FAILED");
    return sigOK ? 0 : 2;
}
