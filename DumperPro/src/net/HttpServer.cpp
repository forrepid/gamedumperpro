// ============================================================================
// DumperPro - HttpServer.cpp
//
// Portable minimal HTTP server for the --serve upload mode.
// Windows: WinSock2 (ws2_32) | Linux/macOS: POSIX sockets (no extra deps).
//
// Routes:
//   GET  /        -> embedded drag&drop upload page (Turkish)
//   GET  /health  -> "ok"
//   POST /upload  -> multipart/form-data (field "file") ya da raw octet-stream
//                    -> StaticAnalyzer -> HTML rapor + TXT/JSON kaydi
//
// Eszamanlilik (roadmap 2.1): baglanti basina ayri thread; analiz ayni anda
// en fazla 4 istemci icin kosar, fazlasi kisaca siraya girer (bounded pool).
// ONEMLI NOT: sunucu yalnizca 127.0.0.1'e baglanir (harici erisim yok).
// ============================================================================

#include "net/HttpServer.h"
#include "file/StaticAnalyzer.h"
#include "il2cpp/Il2CppDummyDll.h"
#include "utils/StrUtil.h"

#include <cstring>
#include <thread>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using SocketT = SOCKET;
constexpr SocketT kInvalidSocket = INVALID_SOCKET;
static bool CloseSocket(SocketT s) { closesocket(s); return true; }
static std::string SocketErr() {
    char buf[64];
    snprintf(buf, sizeof(buf), "WSA error %d", WSAGetLastError());
    return buf;
}
static void SocketInit() {
    static bool done = false;
    if (!done) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        done = true;
    }
}
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <signal.h>
using SocketT = int;
constexpr SocketT kInvalidSocket = -1;
static bool CloseSocket(SocketT s) { ::close(s); return true; }
static std::string SocketErr() { return strerror(errno); }
static void SocketInit() { signal(SIGPIPE, SIG_IGN); }
#endif

namespace dumper {

namespace {

constexpr size_t kMaxUpload = 512ull * 1024 * 1024; // 512 MiB
constexpr size_t kMaxHeader = 64 * 1024;

std::string HumanSize(u64 b) {
    char buf[64];
    if (b < 1024) snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)b);
    else if (b < 1024ull * 1024) snprintf(buf, sizeof(buf), "%.1f KB", (double)b / 1024);
    else if (b < 1024ull * 1024 * 1024) snprintf(buf, sizeof(buf), "%.1f MB", (double)b / (1024 * 1024));
    else snprintf(buf, sizeof(buf), "%.2f GB", (double)b / (1024 * 1024 * 1024));
    return buf;
}

void HtmlEscape(const std::string& in, std::string& out) {
    for (char c : in) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out += c;
        }
    }
}

std::string SanitizeFilePartName(std::string s) {
    // path traversal guard: keep base name only
    const size_t bs = s.find_last_of("/\\");
    if (bs != std::string::npos) s = s.substr(bs + 1);
    std::string out;
    for (char c : s) out += (isalnum((u8)c) || c == '.' || c == '_' || c == '-') ? c : '_';
    if (out.empty()) out = "dosya.bin";
    return out.substr(0, 120);
}

bool SendAll(SocketT s, const char* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        const int n = (int)send(s, data + sent, (int)std::min<size_t>(len - sent, 1 << 20), 0);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

void SendResponse(SocketT s, const std::string& status, const std::string& contentType,
                  const std::string& body) {
    char head[512];
    snprintf(head, sizeof(head),
             "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
             "Connection: close\r\nCache-Control: no-store\r\n\r\n",
             status.c_str(), contentType.c_str(), body.size());
    SendAll(s, head, strlen(head));
    SendAll(s, body.data(), body.size());
}

void SendHtml(SocketT s, const std::string& body) {
    SendResponse(s, "200 OK", "text/html; charset=utf-8", body);
}

const char* kUploadPage = R"HTML(<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DumperPro - Dosya Analizi</title>
<style>
:root{color-scheme:dark}
body{margin:0;font-family:ui-monospace,Consolas,monospace;background:#0a0f0d;color:#d4d4d8;min-height:100vh;display:flex;flex-direction:column}
header{border-bottom:1px solid #1f2937;padding:18px 24px;background:#0d1512}
h1{margin:0;font-size:20px;color:#34d399}
h1 span{color:#a7f3d0}
p.sub{margin:6px 0 0;color:#6b7280;font-size:13px}
main{flex:1;max-width:960px;width:100%;margin:0 auto;padding:24px 16px;box-sizing:border-box}
#drop{border:2px dashed #1f4037;border-radius:14px;padding:44px 20px;text-align:center;background:#0d1512;cursor:pointer;transition:border-color .2s}
#drop.hot{border-color:#34d399;background:#0f2018}
#drop b{color:#34d399;font-size:15px}
#drop small{display:block;margin-top:8px;color:#6b7280}
input[type=file]{display:none}
#bar{height:6px;background:#1f2937;border-radius:99px;margin:18px 0;overflow:hidden;display:none}
#bar>div{height:100%;width:0;background:#34d399;transition:width .2s}
#st{font-size:13px;color:#9ca3af;margin-bottom:10px;min-height:18px}
pre{background:#0a0f0d;border:1px solid #1f2937;border-radius:10px;padding:16px;font-size:12px;line-height:1.55;white-space:pre-wrap;word-break:break-word;color:#a7f3d0;display:none;max-height:70vh;overflow:auto}
footer{border-top:1px solid #1f2937;padding:12px 24px;color:#4b5563;font-size:11px;text-align:center}
</style>
</head>
<body>
<header>
  <h1>Dumper<span>Pro</span> - Dosya Analizi</h1>
  <p class="sub">exe / dll / sys / apk / so / dex / metadata / vdex / oat yukleyin - PE/ELF/DEX/APK/IL2CPP statik analizi</p>
</header>
<main>
  <div id="drop">
    <b>Dosyayi surukleyip birakin</b>
    <small>ya da tiklayip secin - .exe .dll .sys .apk .so .dex .zip .dat .vdex .odex</small>
    <input id="f" type="file" accept=".exe,.dll,.sys,.apk,.so,.dex,.zip,.bin,.pak,.obb,.dat,.vdex,.odex,.oat,.cs">
  </div>
  <div id="bar"><div></div></div>
  <div id="st"></div>
  <pre id="out"></pre>
</main>
<footer>yalnizca yerel analiz - raporlar DumperPro_Out/serve/ altina kaydedilir</footer>
<script>
const drop=document.getElementById('drop'),f=document.getElementById('f'),
      bar=document.getElementById('bar'),fill=bar.firstElementChild,
      st=document.getElementById('st'),out=document.getElementById('out');
drop.onclick=()=>f.click();
drop.ondragover=e=>{e.preventDefault();drop.classList.add('hot')};
drop.ondragleave=()=>drop.classList.remove('hot');
drop.ondrop=e=>{e.preventDefault();drop.classList.remove('hot');
  if(e.dataTransfer.files.length) upload(e.dataTransfer.files[0]);};
f.onchange=()=>{if(f.files.length) upload(f.files[0]);};
async function upload(file){
  bar.style.display='block';fill.style.width='8%';
  st.textContent='Yukleniyor: '+file.name+' ('+file.size+' bayt)';
  out.style.display='none';out.textContent='';
  const fd=new FormData();fd.append('file',file,file.name);
  try{
    fill.style.width='45%';
    const r=await fetch('/upload',{method:'POST',body:fd});
    if(!r.ok){const t=await r.text();st.textContent='Hata: '+t;fill.style.width='0%';return;}
    fill.style.width='100%';
    st.textContent='Analiz tamamlandi: '+file.name;
    out.textContent=await r.text();out.style.display='block';
  }catch(err){st.textContent='Hata: '+err;}
  setTimeout(()=>{bar.style.display='none';fill.style.width='0%';},600);
}
</script>
</body>
</html>)HTML";

} // namespace

// ---------------------------------------------------------------------------
HttpServer::HttpServer(u16 port, const fs::path& outDir)
    : port_(port), outDir_(outDir) {}

bool HttpServer::Start() {
    SocketInit();
    SocketT srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == kInvalidSocket) {
        lastErr_ = "socket() basarisiz: " + SocketErr();
        return false;
    }
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // yalnizca yerel baglanti
    addr.sin_port = htons(port_);

    if (bind(srv, (sockaddr*)&addr, sizeof(addr)) != 0) {
        lastErr_ = "bind(" + std::to_string(port_) + ") basarisiz: " + SocketErr();
        CloseSocket(srv);
        return false;
    }
    if (listen(srv, 8) != 0) {
        lastErr_ = "listen() basarisiz: " + SocketErr();
        CloseSocket(srv);
        return false;
    }

    // socket'i HandleClient icin uye degiskeni olmadan aktarmak:
    // accept loop Run() icinde yeniden socket olusturulur - burada sadece dogrulama.
    CloseSocket(srv);
    return true;
}

void HttpServer::Run() {
    SocketInit();
    SocketT srv = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port_);
    if (bind(srv, (sockaddr*)&addr, sizeof(addr)) != 0 || listen(srv, 8) != 0) {
        lastErr_ = "bind/listen basarisiz: " + SocketErr();
        return;
    }

    // -- eszamanli yukleme havuzu (roadmap 2.1) --
    // Baglanti basina thread; ayni anda en fazla 4 analiz (saturasyon: yeni
    // kabul kisaca bekler). Analiz CPU/IO agir oldugu icin sinir dusuk tutuldu.
    std::atomic<int> active{0};
    constexpr int kMaxConcurrent = 4;
    for (;;) {
        SocketT cli = accept(srv, nullptr, nullptr);
        if (cli == kInvalidSocket) continue;
        while (active.load(std::memory_order_acquire) >= kMaxConcurrent)
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
        active.fetch_add(1, std::memory_order_relaxed);
        SocketT sock = cli;
        std::thread([this, sock, &active]() {
            HandleClient((u64)(intptr_t)sock);
            CloseSocket(sock);
            active.fetch_sub(1, std::memory_order_release);
        }).detach();
    }
}

void HttpServer::HandleClient(u64 sock) {
    SocketT s = (SocketT)(intptr_t)sock;

    // --- istek oku: header + govde tek akista (sadece Content-Length tabanli) ---
    char buf[65536];
    std::vector<u8> raw;
    size_t headerEnd = std::string::npos;
    size_t searchFrom = 0;

    // ilk once header'i topla (kMaxHeader cap)
    while (raw.size() <= kMaxHeader) {
        const int n = (int)recv(s, buf, sizeof(buf), 0);
        if (n <= 0) return;
        raw.insert(raw.end(), buf, buf + (size_t)n);

        // \r\n\r\n ara (yeni baytlardan geriye 4 bayt pay ile)
        if (raw.size() >= 4) {
            const size_t from = searchFrom > 3 ? searchFrom - 3 : 0;
            for (size_t i = from; i + 4 <= raw.size(); i++) {
                if (raw[i] == '\r' && raw[i + 1] == '\n' && raw[i + 2] == '\r' && raw[i + 3] == '\n') {
                    headerEnd = i + 4;
                    break;
                }
            }
            if (headerEnd != std::string::npos) break;
            searchFrom = raw.size();
        }
    }
    if (headerEnd == std::string::npos) {
        SendResponse(s, "431 Request Header Fields Too Large", "text/plain; charset=utf-8",
                     "istek basligi cok buyuk");
        return;
    }

    // --- istek satiri + headerlar ---
    std::string header(reinterpret_cast<const char*>(raw.data()), headerEnd);
    const size_t lineEnd = header.find("\r\n");
    const std::string reqLine = header.substr(0, lineEnd);
    const size_t sp = reqLine.find(' ');
    const std::string method = sp == std::string::npos ? "" : reqLine.substr(0, sp);
    std::string path = "";
    if (sp != std::string::npos) {
        const size_t sp2 = reqLine.find(' ', sp + 1);
        path = reqLine.substr(sp + 1, sp2 == std::string::npos ? std::string::npos : sp2 - sp - 1);
        const size_t q = path.find('?');
        if (q != std::string::npos) path = path.substr(0, q);
    }

    std::map<std::string, std::string> hdrs;
    {
        size_t pos = lineEnd + 2;
        while (pos < header.size()) {
            const size_t e = header.find("\r\n", pos);
            const std::string line = e == std::string::npos ? header.substr(pos) : header.substr(pos, e - pos);
            if (line.empty()) break;
            const size_t c = line.find(':');
            if (c != std::string::npos)
                hdrs[str::Lower(str::Trim(line.substr(0, c)))] = str::Trim(line.substr(c + 1));
            pos = (e == std::string::npos) ? header.size() : e + 2;
        }
    }

    // --- govde uzunlugu ---
    size_t contentLength = 0;
    {
        auto it = hdrs.find("content-length");
        if (it != hdrs.end()) contentLength = (size_t)strtoull(it->second.c_str(), nullptr, 10);
    }
    if (contentLength > kMaxUpload) {
        SendResponse(s, "413 Payload Too Large", "text/plain; charset=utf-8",
                     "dosya cok buyuk (limit: " + HumanSize(kMaxUpload) + ")");
        return;
    }

    // --- govde: header ile birlikte gelen kisim + kalanini recv ile doldur ---
    std::vector<u8> body(raw.begin() + headerEnd, raw.end());
    if (body.size() > contentLength) body.resize(contentLength);
    while (body.size() < contentLength) {
        const int n = (int)recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;
        const size_t take = std::min<size_t>((size_t)n, contentLength - body.size());
        body.insert(body.end(), buf, buf + take);
    }
    if (body.size() < contentLength) {
        SendResponse(s, "400 Bad Request", "text/plain; charset=utf-8", "govde yarim geldi");
        return;
    }

    // --- yonlendirme ---
    if (method == "GET" && (path == "/" || path == "/index.html")) {
        SendHtml(s, kUploadPage);
    } else if (method == "GET" && path == "/health") {
        SendResponse(s, "200 OK", "text/plain; charset=utf-8", "ok");
    } else if (method == "POST" && (path == "/upload" || path == "/raw")) {
        std::string ct;
        auto it = hdrs.find("content-type");
        if (it != hdrs.end()) ct = it->second;

        std::string fileName = "dosya.bin";
        size_t bodyOffset = 0, bodyLen = body.size();

        if (str::Lower(ct).find("multipart/form-data") == 0) {
            // boundary cikar
            std::string boundary;
            const size_t bpos = ct.find("boundary=");
            if (bpos != std::string::npos) boundary = ct.substr(bpos + 9);
            if (!boundary.empty() && boundary.front() == '"') {
                boundary = boundary.substr(1, boundary.size() - 2);
            }
            if (boundary.empty()) {
                SendResponse(s, "400 Bad Request", "text/plain; charset=utf-8", "boundary eksik");
                return;
            }
            const std::string delim = "--" + boundary;

            // ilk dosya parcasini bul
            std::string bodyStr(reinterpret_cast<const char*>(body.data()), body.size());
            const size_t p1 = bodyStr.find(delim);
            if (p1 == std::string::npos) {
                SendResponse(s, "400 Bad Request", "text/plain; charset=utf-8", "multipart parca bulunamadi");
                return;
            }
            // parca header'lari
            const size_t hdrStart = p1 + delim.size();
            const size_t partHdrEnd = bodyStr.find("\r\n\r\n", hdrStart);
            if (partHdrEnd == std::string::npos) {
                SendResponse(s, "400 Bad Request", "text/plain; charset=utf-8", "parca basligi bozuk");
                return;
            }
            const std::string partHdr = bodyStr.substr(hdrStart, partHdrEnd - hdrStart);
            // filename="..."
            const size_t fn = partHdr.find("filename=\"");
            if (fn != std::string::npos) {
                const size_t fe = partHdr.find('"', fn + 10);
                if (fe != std::string::npos) fileName = partHdr.substr(fn + 10, fe - fn - 10);
            }
            const size_t dataStart = partHdrEnd + 4;
            const size_t dataEnd = bodyStr.find("\r\n" + delim, dataStart);
            if (dataEnd == std::string::npos) {
                SendResponse(s, "400 Bad Request", "text/plain; charset=utf-8", "parca sonu bulunamadi");
                return;
            }
            bodyOffset = dataStart;
            bodyLen = dataEnd - dataStart;
            fileName = SanitizeFilePartName(fileName);
        }

        if (bodyLen == 0) {
            SendResponse(s, "400 Bad Request", "text/plain; charset=utf-8", "bos yukleme");
            return;
        }
        SendHtml(s, HandleUpload(body, ct, fileName, bodyOffset, bodyLen));
    } else {
        SendResponse(s, "404 Not Found", "text/plain; charset=utf-8", "bulunamadi: " + path);
    }
}

std::string HttpServer::HandleUpload(const std::vector<u8>& body, const std::string& /*ct*/,
                                     const std::string& fileName, size_t offset, size_t len) {
    const u8* data = body.data() + offset;
    const size_t size = len;

    const StaticReport rep = StaticAnalyzer::Analyze(data, size, fileName);

    // raporu diske yaz (TXT + JSON; IL2CPP ise tam cikti seti)
    std::error_code ec;
    fs::create_directories(outDir_, ec);
    std::time_t t = std::time(nullptr);
    std::tm tmv;
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char stamp[32];
    strftime(stamp, sizeof(stamp), "%Y%m%d_%H%M%S", &tmv);
    const std::string base = std::string(stamp) + "_" + SanitizeFilePartName(fileName);
    const fs::path reportFile = outDir_ / (base + "_report.txt");
    {
        std::ofstream out(reportFile, std::ios::binary | std::ios::trunc);
        out << rep.text;
        if (!rep.gamesIni.empty()) {
            std::ofstream ini(reportFile.parent_path() / "games.ini.oneri.txt", std::ios::binary | std::ios::trunc);
            ini << rep.gamesIni;
        }
        std::ofstream jr(outDir_ / (base + "_report.json"), std::ios::binary | std::ios::trunc);
        jr << StaticAnalyzer::BuildJsonReport(rep, fileName, size);
    }
    if (rep.il2cppMeta && rep.il2cppMeta->valid) {
        Il2CppMetadataParser::WriteOutputs(*rep.il2cppMeta, outDir_ / (base + "_il2cpp"), fileName);
    }
    // IL2CPP binary es cifti (APK yuklemesinde otomatik eslestirildi)
    if (rep.il2cppBinary && rep.il2cppMeta) {
        Il2CppBinaryMatch::WriteOutputs(*rep.il2cppMeta, *rep.il2cppBinary,
                                        outDir_ / (base + "_il2cpp"),
                                        rep.il2cppSoName.empty() ? "binary" : rep.il2cppSoName,
                                        "global-metadata.dat",
                                        rep.il2cppBinaryData ? rep.il2cppBinaryData->data() : nullptr,
                                        rep.il2cppBinaryData ? rep.il2cppBinaryData->size() : 0);
        // DummyDll: image basina derlenebilir C# kaynak stub'lar
        Il2CppDummyDll::WriteOutputs(*rep.il2cppMeta, *rep.il2cppBinary,
                                     outDir_ / (base + "_il2cpp"),
                                     rep.il2cppBinaryData ? rep.il2cppBinaryData->data() : nullptr,
                                     rep.il2cppBinaryData ? rep.il2cppBinaryData->size() : 0);
    }

    // HTML sonuc sayfasi
    std::string escName;
    HtmlEscape(fileName, escName);
    std::string escReport;
    HtmlEscape(rep.text, escReport);

    std::string html;
    html.reserve(escReport.size() + 2048);
    html += "<!doctype html><html lang=\"tr\"><head><meta charset=\"utf-8\">";
    html += "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">";
    html += "<title>DumperPro - Rapor: " + escName + "</title>";
    html += "<style>body{margin:0;font-family:ui-monospace,Consolas,monospace;background:#0a0f0d;color:#d4d4d8}"
            "header{border-bottom:1px solid #1f2937;padding:16px 24px;background:#0d1512;display:flex;gap:12px;align-items:center;flex-wrap:wrap}"
            "h1{margin:0;font-size:18px;color:#34d399}"
            "a{color:#34d399;font-size:13px;text-decoration:none;border:1px solid #1f4037;padding:6px 12px;border-radius:8px}"
            "pre{margin:20px;padding:16px;background:#0a0f0d;border:1px solid #1f2937;border-radius:10px;"
            "font-size:12px;line-height:1.55;white-space:pre-wrap;word-break:break-word;color:#a7f3d0;"
            "max-height:75vh;overflow:auto}</style></head><body>";
    html += "<header><h1>" + escName + "</h1><a href=\"/\">Yeni yukleme</a></header>";
    html += "<pre>" + escReport + "</pre></body></html>";
    return html;
}

} // namespace dumper
