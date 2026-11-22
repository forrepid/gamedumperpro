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
#include "core/MemoryReader.h"   // ListLiveProcesses (canli hedefler, 0.5.2)
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
#include <windows.h>            // GetModuleFileNameW + CreateProcessA (self-spawn dump)
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

// ---------------------------------------------------------------------------
// Canli hedefler (0.5.2): JSON yardimcilari + self-spawn dump
// ---------------------------------------------------------------------------

std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if ((u8)c < 0x20) {
                    char b[8];
                    snprintf(b, sizeof(b), "\\u%04X", (unsigned)(u8)c);
                    out += b;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

// minimal JSON govde alanlarini cikarar (tek seviye; govde kendi urettigimiz
// sayfa JS'inden geliyor, tum JSON parser gerekmez)
long ExtractJsonNumber(const std::string& body, const char* key) {
    const std::string pat = "\"" + std::string(key) + "\"";
    const size_t k = body.find(pat);
    if (k == std::string::npos) return 0;
    const size_t colon = body.find(':', k + pat.size());
    if (colon == std::string::npos) return 0;
    return strtol(body.c_str() + colon + 1, nullptr, 10);
}

bool ExtractJsonBool(const std::string& body, const char* key) {
    const std::string pat = "\"" + std::string(key) + "\"";
    const size_t k = body.find(pat);
    if (k == std::string::npos) return false;
    const size_t colon = body.find(':', k + pat.size());
    if (colon == std::string::npos) return false;
    const std::string rest = str::Lower(str::Trim(body.substr(colon + 1, 8)));
    return rest.rfind("true", 0) == 0;
}

std::string ExtractJsonString(const std::string& body, const char* key) {
    const std::string pat = "\"" + std::string(key) + "\"";
    const size_t k = body.find(pat);
    if (k == std::string::npos) return {};
    // pat" zaten kapanis tirnagini icerir; ilk tirnak degerin acilisi
    const size_t q1 = body.find('"', k + pat.size());
    if (q1 == std::string::npos) return {};
    // escape'li degeri tara
    std::string out;
    for (size_t i = q1 + 1; i < body.size(); i++) {
        char c = body[i];
        if (c == '\\' && i + 1 < body.size()) {
            const char n = body[i + 1];
            switch (n) {
                case '"':  out += '"';  break;
                case '\\': out += '\\'; break;
                case '/':  out += '/';  break;
                case 'n':  out += '\n'; break;
                case 't':  out += '\t'; break;
                case 'r':  out += '\r'; break;
                default:   out += '\\'; out += n; break;
            }
            i++;
            continue;
        }
        if (c == '"') break;
        out += c;
    }
    return out;
}

#ifdef _WIN32
// kendi kendini yeniden baslatan dump: komut satirini yurut, stdout/stderr'i
// yakala, timeout'u asarsa oldur. Windows-only (canli proses erisimi Win32 API).
bool SpawnSelfCapture(const std::string& cmdLine, std::string& outLog, DWORD timeoutMs, DWORD& exitCode) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return false;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0); // okuma ucu cocuga kalmasin

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi{};

    // CreateProcessA komut satirini DEGISTIREBILIR - mutable kopya sart
    std::vector<char> mutableCmd(cmdLine.begin(), cmdLine.end());
    mutableCmd.push_back('\0');

    const BOOL ok = CreateProcessA(nullptr, mutableCmd.data(), nullptr, nullptr, TRUE,
                                   CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(wr);
    if (!ok) {
        CloseHandle(rd);
        return false;
    }

    constexpr size_t kLogCap = 256 * 1024;
    DWORD elapsed = 0;
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(rd, nullptr, 0, nullptr, &avail, nullptr)) break;
        if (avail) {
            char buf[4096];
            DWORD n = 0;
            if (ReadFile(rd, buf, sizeof(buf), &n, nullptr) && n) {
                if (outLog.size() < kLogCap) outLog.append(buf, (size_t)std::min<DWORD>(n, 4096));
                continue;
            }
        }
        if (WaitForSingleObject(pi.hProcess, 200) == WAIT_OBJECT_0) break;
        elapsed += 200;
        if (elapsed >= timeoutMs) {
            TerminateProcess(pi.hProcess, (UINT)1);
            outLog += "\n[timeout] dump 10 dakikayi asti - process olduruldu";
            break;
        }
    }
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(rd);
    return true;
}
#endif

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
section#live{margin-top:30px;border-top:1px solid #1f2937;padding-top:20px}
section#live h2{font-size:15px;color:#34d399;margin:0 0 4px}
p.livesub{margin:0 0 12px;color:#6b7280;font-size:12px}
.liverow{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px}
button{background:#0f2018;border:1px solid #1f4037;color:#34d399;font-family:inherit;font-size:12px;padding:7px 14px;border-radius:8px;cursor:pointer}
button:hover{background:#14342a}
button:disabled{opacity:.5;cursor:wait}
#pinfo{font-size:11px;color:#6b7280}
#pwrap{max-height:340px;overflow:auto;border:1px solid #1f2937;border-radius:10px;background:#0d1512}
table{width:100%;border-collapse:collapse;font-size:12px}
th{color:#6b7280;text-align:left;padding:6px 10px;border-bottom:1px solid #1f2937;font-weight:500;position:sticky;top:0;background:#0d1512}
td{padding:5px 10px;border-bottom:1px solid #141c19;color:#d4d4d8;white-space:nowrap}
tr.hint td{color:#a7f3d0}
td button.dump{padding:3px 12px;font-size:11px}
#pst{font-size:12px;color:#9ca3af;margin:10px 0;min-height:16px}
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
  <section id="live">
    <h2>Canli Hedefler</h2>
    <p class="livesub">calisan prosesleri listele - motor ipucu sutununda UE / Unity IL2CPP / Unity Mono gorunur; Dump butonu canli proses uzerinde GNames + GObjects + SDK cikarir (ayni UE hatti, --pid ile yeniden baslatim)</p>
    <div class="liverow">
      <button id="prefresh">Listeyi Yenile</button>
      <button id="pdeep">Derin Tara (UE surumu)</button>
      <span id="pinfo"></span>
    </div>
    <div id="pwrap">
      <table id="ptab">
        <thead><tr><th>PID</th><th>Ad</th><th>Modul</th><th>Motor</th><th>Detay</th><th></th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
    <div id="pst"></div>
    <pre id="pout"></pre>
  </section>
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
const ptab=document.querySelector('#ptab tbody'),pinfo=document.getElementById('pinfo'),
      pst=document.getElementById('pst'),pout=document.getElementById('pout');
async function refreshProcs(deep){
  pst.textContent=deep?'Derin tarama... (UE surum dizesi her aday prosesin bellek imajindan okunuyor - 10-30 sn)':'Liste aliniyor...';
  document.getElementById('prefresh').disabled=true;document.getElementById('pdeep').disabled=true;
  try{
    const r=await fetch('/api/processes'+(deep?'?deep=1':''));
    const j=await r.json();
    ptab.innerHTML='';
    let hinted=0;
    (j.processes||[]).forEach(p=>{
      if(p.hint)hinted++;
      const tr=document.createElement('tr');if(p.hint)tr.className='hint';
      const td=t=>{const d=document.createElement('td');d.textContent=t==null?'':String(t);return d};
      tr.appendChild(td(p.pid));tr.appendChild(td(p.name));tr.appendChild(td(p.modules??0));
      tr.appendChild(td(p.hint||'-'));
      tr.appendChild(td((p.detail||'')+(p.attachable?'':' [korumali]')));
      const act=document.createElement('td');const b=document.createElement('button');
      b.className='dump';b.textContent='Dump';b.disabled=!p.attachable;
      b.onclick=()=>dumpPid(p.pid,p.name,b);act.appendChild(b);tr.appendChild(act);
      ptab.appendChild(tr);
    });
    pinfo.textContent=j.count+' proses ('+hinted+' motor ipucli)'+(deep?' [deep]':'');
    pst.textContent='';
  }catch(err){pst.textContent='Hata: '+err;}
  document.getElementById('prefresh').disabled=false;document.getElementById('pdeep').disabled=false;
}
async function dumpPid(pid,name,btn){
  btn.disabled=true;
  pst.textContent='Canli dump aliniyor: '+name+' (pid '+pid+') - 1-2 dakika surebilir, sayfayi kapatmayin...';
  pout.style.display='none';pout.textContent='';
  try{
    const r=await fetch('/api/dump',{method:'POST',headers:{'Content-Type':'application/json'},
                                     body:JSON.stringify({pid:pid})});
    const j=await r.json();
    if(j.ok)pst.textContent='TAMAMLANDI -> '+j.outDir;
    else pst.textContent='DUMP BASARISIZ (exit '+(j.exitCode!=null?j.exitCode:'?')+'): '+(j.error||'ayrinti icin loga bakin');
    let txt='DumperPro dump logu (pid '+pid+'):\n'+(j.log||'(log bos)');
    if(j.result)txt+='\n\nresult.json:\n'+JSON.stringify(j.result,null,2);
    pout.textContent=txt;pout.style.display='block';
  }catch(err){pst.textContent='Hata: '+err;}
  btn.disabled=false;
}
document.getElementById('prefresh').onclick=()=>refreshProcs(false);
document.getElementById('pdeep').onclick=()=>refreshProcs(true);
window.addEventListener('load',()=>refreshProcs(false));
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
    std::string query = "";
    if (sp != std::string::npos) {
        const size_t sp2 = reqLine.find(' ', sp + 1);
        path = reqLine.substr(sp + 1, sp2 == std::string::npos ? std::string::npos : sp2 - sp - 1);
        const size_t q = path.find('?');
        if (q != std::string::npos) {
            query = path.substr(q + 1);
            path = path.substr(0, q);
        }
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
    } else if (method == "GET" && path == "/api/processes") {
        // canli proses listesi; ?deep=1 ile UE surum dizesi bellekte dogrulanir
        HandleProcesses((u64)(intptr_t)s, query.find("deep=1") != std::string::npos);
    } else if (method == "POST" && path == "/api/dump") {
        // canli dump tetikleme: {"pid":N,"module":"...","noSdk":bool,"metadata":"..."}
        HandleDump((u64)(intptr_t)s, body);
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

// ---------------------------------------------------------------------------
// GET /api/processes[?deep=1] - canli proses listesi (motor ipuclari + JSON)
// ---------------------------------------------------------------------------
void HttpServer::HandleProcesses(u64 sock, bool deep) {
    SocketT s = (SocketT)(intptr_t)sock;
    const std::vector<ProcessListEntry> procs = ListLiveProcesses(deep);

    std::string js;
    js.reserve(256 + procs.size() * 96);
    js += "{\"format\":\"dumperpro-processes\",\"version\":1,\"deep\":";
    js += (deep ? "true" : "false");
    js += ",\"count\":";
    js += std::to_string(procs.size());
    js += ",\"processes\":[";
    for (size_t i = 0; i < procs.size(); i++) {
        const ProcessListEntry& e = procs[i];
        js += i ? ",\n{" : "\n{";
        js += "\"pid\":" + std::to_string(e.pid);
        js += ",\"name\":\"" + JsonEscape(e.name) + "\"";
        js += ",\"modules\":" + std::to_string(e.moduleCount);
        js += ",\"hint\":\"" + JsonEscape(e.hint) + "\"";
        js += ",\"detail\":\"" + JsonEscape(e.hintDetail) + "\"";
        js += e.attachable ? ",\"attachable\":true" : ",\"attachable\":false";
        js += e.deep ? ",\"deep\":true}" : ",\"deep\":false}";
    }
    js += "\n]}";
    SendResponse(s, "200 OK", "application/json; charset=utf-8", js);
}

// ---------------------------------------------------------------------------
// POST /api/dump - canli dump tetikleme (0.5.2)
// Govde: {"pid":N, "module":"...", "noSdk":bool, "metadata":"..."}
// DumperPro.exe kendini --pid ile subprocess olarak yeniden baslatir (self-
// spawn); UE hattinin TAMAMI (GNames/GObjects/SDK/result.json) ayni kod yoluyla
// kosar. Sonuc: exit code + stdout logu + result.json icerigi.
// ---------------------------------------------------------------------------
void HttpServer::HandleDump(u64 sock, const std::vector<u8>& body) {
    SocketT s = (SocketT)(intptr_t)sock;
#ifndef _WIN32
    (void)body;
    SendResponse(s, "400 Bad Request", "application/json; charset=utf-8",
                 "{\"ok\":false,\"error\":\"canli proses dump yalnizca Windows yapida desteklenir (--pid Win32 API)\"}");
#else
    const std::string bodyStr(reinterpret_cast<const char*>(body.data()), body.size());
    const long pid = ExtractJsonNumber(bodyStr, "pid");
    if (pid <= 0) {
        SendResponse(s, "400 Bad Request", "application/json; charset=utf-8",
                     "{\"ok\":false,\"error\":\"pid eksik veya gecersiz\"}");
        return;
    }
    const std::string module   = ExtractJsonString(bodyStr, "module");
    const std::string metadata = ExtractJsonString(bodyStr, "metadata");
    const bool noSdk = ExtractJsonBool(bodyStr, "noSdk");
    if (module.find('"') != std::string::npos || metadata.find('"') != std::string::npos) {
        SendResponse(s, "400 Bad Request", "application/json; charset=utf-8",
                     "{\"ok\":false,\"error\":\"module/metadata alaninda tirnak olamaz\"}");
        return;
    }

    // kendi exe yolu + cikti klasoru: DumperPro_Out/serve/live_<stamp>_pid<N>
    wchar_t exePathW[1024] = {};
    GetModuleFileNameW(nullptr, exePathW, 1024);
    const fs::path exePath(exePathW);

    const std::string pidStr = std::to_string(pid);
    std::time_t t = std::time(nullptr);
    std::tm tmv;
    localtime_s(&tmv, &t);
    char stamp[32];
    strftime(stamp, sizeof(stamp), "%Y%m%d_%H%M%S", &tmv);
    const fs::path outDir = outDir_ / (std::string("live_") + stamp + "_pid" + pidStr);
    std::error_code ec;
    fs::create_directories(outDir, ec);

    // komut satiri: ayni UE hatti --json ile (result.json + functions.json her zaman)
    std::string cmd = "\"" + exePath.string() + "\" --pid " + pidStr +
                      " --json --out \"" + outDir.string() + "\"";
    if (!module.empty())   cmd += " --module \"" + module + "\"";
    if (noSdk)             cmd += " --no-sdk";
    if (!metadata.empty()) cmd += " --metadata \"" + metadata + "\"";

    std::string log;
    DWORD exitCode = (DWORD)-1;
    const bool spawned = SpawnSelfCapture(cmd, log, 600000, exitCode); // 10 dk tavan

    // result.json oku (varsa yanita gom)
    std::string resultJson;
    {
        std::ifstream rf(outDir / "result.json", std::ios::binary);
        if (rf.good()) {
            std::stringstream ss;
            ss << rf.rdbuf();
            resultJson = ss.str();
        }
    }

    std::string js = "{\"ok\":";
    js += (spawned && exitCode == 0) ? "true" : "false";
    js += spawned ? ",\"exitCode\":" + std::to_string((unsigned long)exitCode)
                  : ",\"error\":\"process olusturulamadi (CreateProcessA)\"";
    js += ",\"outDir\":\"" + JsonEscape(outDir.string()) + "\"";
    js += ",\"cmd\":\"" + JsonEscape(cmd) + "\"";
    js += ",\"result\":";
    js += resultJson.empty() ? "null" : resultJson;
    js += ",\"log\":\"" + JsonEscape(log) + "\"";
    js += "}";
    SendResponse(s, "200 OK", "application/json; charset=utf-8", js);
#endif
}

} // namespace dumper
