// ============================================================================
// DumperPro - HttpServer.h
//
// DumperPro.exe --serve [port]
//
// "Online dosya yukleme" modu: arac yerel bir web sunucusu baslatir,
// tarayicidan http://127.0.0.1:<port> acilir, exe/dll/apk/so/dex dosyalari
// surukle-birak ile yuklenir ve aninda statik analiz edilir.
//
// - Tamamen kendi kendine yeterli (herhangi bir kutuphane yok):
//     * portable TCP soket katmani (WinSock2 / POSIX)
//     * minimal HTTP/1.0-1.1 istek cozumleme (GET / POST)
//     * multipart/form-data dosya yukleme (RFC 7578) + raw octet-stream
// - Analiz StaticAnalyzer ile yapilir (PE/ELF/DEX/ZIP-APK).
// - Rapor DumperPro_Out/serve/ altina kaydedilir.
//
// Guvenlik notlari:
//   - Varsayilan baglama adresi 127.0.0.1'dir (harici erisim yok).
//   - Yukleme boyutu limiti 512 MiB'dir; istek govdesi disk disi
//     tamponda tutulup islenir (LFS/yazma yok).
//   - Bu sunucu halka acik bir servis DEGILDIR; yalnizca yerel analiz icin.
// ============================================================================
#pragma once
#include "../framework.h"

namespace dumper {

class HttpServer {
public:
    explicit HttpServer(u16 port = 8420, const fs::path& outDir = "DumperPro_Out/serve");

    bool Start();  // binds + listens; false on error (LastError)
    void Run();    // blocking accept loop (Ctrl+C ile kesilir)
    std::string LastError() const { return lastErr_; }

private:
    void HandleClient(u64 socket);
    std::string HandleUpload(const std::vector<u8>& body, const std::string& contentType,
                             const std::string& fileName, size_t bodyOffset, size_t bodyLen);

    u16 port_;
    fs::path outDir_;
    std::string lastErr_;
};

} // namespace dumper
