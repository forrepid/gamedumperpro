# ============================================================================
# DumperPro - leechcore.dll indirme/kurulum scripti (Windows x64)
#
# Ne yapar:
#   Resmi MemProcFS surumunden (github.com/ufrisk/MemProcFS/releases) yalnizca
#   Windows x64 zip'ini indirir ve icindeki leechcore.dll'i bu scriptin
#   bulundugu klasore (varsayilan: DumperPro.exe'nin yani) cikarir.
#
#   DumperPro leechcore.dll'i calisma zamaninda LoadLibraryA ile baglar
#   (docs/LEECH.md bolum 2-3); import library/header gerekmez. DumperPro
#   hicbir GPL/AGPL ikilisini DAGITMAZ - DLL'i kullanici bu scriptle veya
#   elle kendi kurar.
#
# Kullanim:
#   powershell -ExecutionPolicy Bypass -File get-leechcore.ps1
#   powershell -ExecutionPolicy Bypass -File get-leechcore.ps1 -Destination C:\dpp\bin
#   powershell -ExecutionPolicy Bypass -File get-leechcore.ps1 -IncludeVmm
#
# Notlar:
#   - file:// testi (test-device.bat TEST 1) DONANIM GEREKTIRMEZ; yalnizca
#     leechcore.dll yeterlidir.
#   - FPGA (fpga) / USB3380 (usb3380:) canli DMA icin ek suruculer gerekir
#     (FTDI D2XX / FTD3XX.dll zip'te var; surucu imzasi + yonetici erisimi).
#     Ayrinti: docs/LEECH.md bolum 6 ve LeechCore wiki.
#   - GitHub API'si rate-limit'e duserseniz script otomatik olarak
#     "releases/latest" yonlendirmesinden tag'i cozip
#     MemProcFS_files_and_binaries-win_x64-latest.zip alias'ini dener.
# ============================================================================

#Requires -Version 5.1
param(
    # DLL'in konacagi klasor. Varsayilan: scriptin bulundugu klasor
    # (DumperPro.exe ile ayni yer - LoadLibraryA once exe klasorune bakar).
    [string]$Destination = $PSScriptRoot,
    # Opsiyonel: vmm.dll'i de kopyala (MemProcFS seviyesi modul bilgisi,
    # VMMDLL_* entegrasyonu yol haritasi icin; DumperPro v0.3.0 su an
    # yalnizca leechcore.dll kullanir).
    [switch]$IncludeVmm
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # PS5.1: indirme ilerleme cubugunu kapat (hiz)
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$ApiUrl    = 'https://api.github.com/repos/ufrisk/MemProcFS/releases/latest'
$LatestUrl = 'https://github.com/ufrisk/MemProcFS/releases/latest'
$AssetRe   = 'MemProcFS_files_and_binaries.*win_x64.*\.zip$'
$TmpZip    = Join-Path $env:TEMP ('MemProcFS_win_x64_' + [IO.Path]::GetRandomFileName() + '.zip')
$TmpDir    = Join-Path $env:TEMP ('MemProcFS_extract_' + [IO.Path]::GetRandomFileName())

function Write-Step([string]$m) { Write-Host "[*] $m" }
function Write-Warn2([string]$m) { Write-Host "[!] $m" -ForegroundColor Yellow }

function Resolve-Asset {
    # 1) GitHub API: en dogru yontem (sahip olunan asset adi + tag).
    try {
        Write-Step "GitHub API sorgulaniyor: $ApiUrl"
        $rel = Invoke-RestMethod -Uri $ApiUrl -UserAgent 'DumperPro-get-leechcore' -TimeoutSec 30
        $asset = $rel.assets |
            Where-Object { $_.name -match $AssetRe } |
            Select-Object -First 1
        if ($asset) {
            Write-Host ("    surum: {0}  asset: {1}" -f $rel.tag_name, $asset.name)
            return @{ url = $asset.browser_download_url; tag = $rel.tag_name; name = $asset.name }
        }
        Write-Warn2 "API cevabinda win_x64 zip asset'i bulunamadi - yedek yonteme geciliyor."
    } catch {
        Write-Warn2 ("GitHub API erisilemedi (rate limit 403 olabilir): {0}" -f $_.Exception.Message)
        Write-Warn2 "Yedek yontem deneniyor (releases/latest redirect)."
    }

    # 2) Yedek: releases/latest 302 redirect -> tag -> win_x64 'latest' alias zip.
    #    (API rate limit'inden bagimsiz, hicbir anahtar gerektirmez.)
    try {
        Write-Step "Yedek: tag cozumleme via $LatestUrl"
        $req = [Net.WebRequest]::Create($LatestUrl)
        $req.AllowAutoRedirect = $false
        $req.Timeout = 30000
        $req.UserAgent = 'DumperPro-get-leechcore'
        $resp = $req.GetResponse()
        $loc = $resp.Headers['Location']
        $resp.Close()
        if ($loc -match '/tag/(v[0-9][\w.]*)$') {
            $tag = $Matches[1]
            $name = 'MemProcFS_files_and_binaries-win_x64-latest.zip'
            $url = "https://github.com/ufrisk/MemProcFS/releases/download/$tag/$name"
            Write-Host ("    surum: {0}  asset: {1} (alias)" -f $tag, $name)
            return @{ url = $url; tag = $tag; name = $name }
        }
        Write-Warn2 "Redirect konumundan tag cikarilamadi: $loc"
    } catch {
        Write-Warn2 ("Tag cozumleme basarisiz: {0}" -f $_.Exception.Message)
    }
    return $null
}

function Main {
    Write-Host "=== DumperPro get-leechcore.ps1 ==="

    $info = Resolve-Asset
    if (-not $info) {
        Write-Host ""
        Write-Host "[X] MemProcFS surumu cozumlenemedi. Elle kurulum:"
        Write-Host "    1) https://github.com/ufrisk/MemProcFS/releases sayfasini acin"
        Write-Host "    2) 'MemProcFS_files_and_binaries_vX.Y-win_x64-....zip' (Windows x64) indirin"
        Write-Host "    3) Zip icindeki leechcore.dll'i DumperPro.exe'nin YANINA kopyalayin"
        Write-Host "    4) Bu scripti tekrar calistirarak dogrulayin"
        exit 2
    }

    Write-Step ("Indiriliyor: {0}" -f $info.url)
    try {
        Invoke-WebRequest -Uri $info.url -OutFile $TmpZip -UserAgent 'DumperPro-get-leechcore' -TimeoutSec 600
    } catch {
        Write-Host "[X] Indirme basarisiz: $($_.Exception.Message)"
        Write-Host "    Internet erisimi/proxy/antivirus ayarlarini kontrol edin; elle kurulum icin yukaridaki adimlar."
        exit 3
    }

    $zipLen = (Get-Item $TmpZip).Length
    if ($zipLen -lt 1MB) {
        Write-Host "[X] Indirilen dosya cok kucuk ($zipLen bayt) - muhtemelen hata sayfasi indirildi."
        exit 3
    }
    Write-Host ("    indirildi: {0} ({1:N0} bayt)" -f $TmpZip, $zipLen)

    Write-Step "Zip aciliyor (gecici klasor)..."
    if (Test-Path $TmpDir) { Remove-Item $TmpDir -Recurse -Force }
    Expand-Archive -Path $TmpZip -DestinationPath $TmpDir -Force

    $lc = Join-Path $TmpDir 'leechcore.dll'
    if (-not (Test-Path $lc)) {
        # Asset yapisindan bagimsizlik icin alt klasorlerde de ara (x64\ gibi).
        $lc = Get-ChildItem -Path $TmpDir -Recurse -Filter 'leechcore.dll' |
              Where-Object { $_.FullName -notmatch '\\x86\\' } |
              Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $lc) {
        Write-Host "[X] Zip icinde leechcore.dll bulunamadi - asset yapisi degismis olabilir."
        Write-Host "    Icerigi kontrol edip DLL'i elle kopyalayin: $TmpDir"
        exit 4
    }

    if (-not (Test-Path $Destination)) { New-Item -ItemType Directory -Force -Path $Destination | Out-Null }
    Copy-Item $lc (Join-Path $Destination 'leechcore.dll') -Force
    Write-Host ("[OK] leechcore.dll yerlesti: {0}" -f (Join-Path $Destination 'leechcore.dll'))

    if ($IncludeVmm) {
        $vmm = Get-ChildItem -Path $TmpDir -Recurse -Filter 'vmm.dll' | Select-Object -First 1
        if ($vmm) {
            Copy-Item $vmm.FullName (Join-Path $Destination 'vmm.dll') -Force
            Write-Host ("[OK] vmm.dll yerlesti: {0}" -f (Join-Path $Destination 'vmm.dll'))
        } else {
            Write-Warn2 "vmm.dll zip'te bulunamadi (opsiyonel istek)."
        }
    }

    Remove-Item $TmpZip -Force -ErrorAction SilentlyContinue
    Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "Donanim notlari (yalnizca canli DMA icin; file:// testi gerekmez):"
    Write-Host "  - FPGA  (fpga)    : FTDI D2XX surucusu + kart; zip'teki FTD3XX.dll yardimci olabilir."
    Write-Host "  - USB3380 (usb3380:): kart takili + yonetici komut istemi; surucu imzasi gerekir."
    Write-Host "  - PMEM  (pmem://) : winpmem_x64.sys surucusu (zip'te mevcut)."
    Write-Host "  - Zip icinde vcruntime140.dll de vardir; DLL yine de hata verirse"
    Write-Host "    vc_redist.x64.exe kurun: https://aka.ms/vs/17/release/vc_redist.x64.exe"
    Write-Host ""
    Write-Host "Sonraki adim:  test-device.bat"
    Write-Host "(Ayrıntili dokuman: DumperPro\docs\LEECH.md)"
}

Main
