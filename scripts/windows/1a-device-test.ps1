# ============================================================================
# DumperPro - 1a LeechCore --device Windows canli test kiti
#
# Amaclari:
#   1) leechcore.dll kurulumunu dogrulamak (DumperPro.exe yaninda / PATH)
#   2) file:// salt-okunur cihaz acma + imza taramasi (LcCreate/LcRead)
#   3) file://file=...,write=1 yazilabilir acilis (LcWrite izni)
#   4) olmayan cihazda zarif (graceful) hata yolu
#   5) (opsiyonel -Fpga) FPGA DMA karti canli acilis
#
# Kullanim:
#   powershell -ExecutionPolicy Bypass -File 1a-device-test.ps1 [-DumperPro .\DumperPro.exe] [-Fpga]
#
# Beklenen: tum testler [PASS]; sonunda "SONUC: N PASS / 0 FAIL"
# Ayrıntili dokuman: docs/1A-WINDOWS-DEVICE-TEST.md
# ============================================================================

#Requires -Version 5.1
param(
    [string]$DumperPro = ".\DumperPro.exe",
    [string]$OutDir    = ".\1a-test-output",
    [switch]$Fpga
)

$script:Pass = 0
$script:Fail = 0
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$script:LogPath = Join-Path $OutDir "1a-test-log.txt"
Set-Content -Path $script:LogPath -Value "DumperPro 1a LeechCore device test - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

function Write-Step([string]$msg) {
    Write-Host "[*] $msg"
    Add-Content -Path $script:LogPath -Value "[*] $msg"
}
function Write-Pass([string]$name) {
    $script:Pass++
    Write-Host "[PASS] $name" -ForegroundColor Green
    Add-Content -Path $script:LogPath -Value "[PASS] $name"
}
function Write-Fail([string]$name, [string]$why) {
    $script:Fail++
    Write-Host "[FAIL] $name  ($why)" -ForegroundColor Red
    Add-Content -Path $script:LogPath -Value "[FAIL] $name  ($why)"
}

# --- 0) DumperPro.exe kontrolu ------------------------------------------------
if (-not (Test-Path $DumperPro)) {
    Write-Host "[X] DumperPro.exe bulunamadi: $DumperPro"
    Write-Host "    -DumperPro parametresiyle yolu verin (MSVC derlemesi: README.md)."
    exit 2
}
$exeDir = Split-Path -Parent (Resolve-Path $DumperPro)
Write-Step "DumperPro: $DumperPro"

# --- 1) leechcore.dll kontrolu -------------------------------------------------
Write-Step "leechcore.dll araniyor (exe klasoru + PATH)..."
$lcDll = $null
$cands = @((Join-Path $exeDir "leechcore.dll"), (Join-Path (Get-Location).Path "leechcore.dll"))
foreach ($dir in ($env:PATH -split ';')) {
    if ($dir) { $cands += (Join-Path $dir "leechcore.dll") }
}
foreach ($c in $cands) { if (Test-Path $c) { $lcDll = $c; break } }

if ($lcDll) {
    Write-Host "    leechcore.dll: $lcDll"
} else {
    Write-Host "[!] leechcore.dll bulunamadi -> canli acilis testleri atlanacak." -ForegroundColor Yellow
    Write-Host "    Kurulum: MemProcFS release zip'i (github.com/ufrisk/MemProcFS/releases) icindeki"
    Write-Host "    leechcore.dll'i DumperPro.exe'nin YANINA kopyalayin, bu scripti tekrar calistirin."
    Write-Host "    (VC++ redistributable gerekebilir: vc_redist.x64.exe)"
}

# --- 2) test duzeni (fixture) uretimi ------------------------------------------
$fixture = Join-Path $OutDir "testdev.raw"
Write-Step "Test duzeni uretiliyor: $fixture (16 MB)"
$buf = [byte[]]::new(16MB)
function PutStr([byte[]]$b, [long]$off, [string]$s) {
    $d = [Text.Encoding]::ASCII.GetBytes($s)
    [Array]::Copy($d, 0, $b, $off, $d.Length)
}
PutStr $buf 0x11000 "DMPPRO-TEST-SIG!`0"                # LcRead imza hedefi
PutStr $buf 0x30000 "++UE5+Release-5.1.1-0-Test`0"      # UE surum kokleyici hedefi
[IO.File]::WriteAllBytes($fixture, $buf)
Write-Host "    fixture hazir: imza@0x11000, ++UE5+Release-5.1.1@0x30000"

# --- yardimci: cihaz testi ------------------------------------------------------
function Run-Test {
    param([string]$Name, [string[]]$CliArgs, [string[]]$MustContain,
          [string[]]$MustNotContain = @(), [switch]$ExpectFail)
    Write-Step "TEST $Name"
    Add-Content -Path $script:LogPath -Value "---- $Name : $($CliArgs -join ' ')"
    $out = & $DumperPro @CliArgs 2>&1 | ForEach-Object { "$_" }
    $out | Add-Content -Path $script:LogPath
    $joined = $out -join "`n"
    $exit   = $LASTEXITCODE
    $why    = @()
    foreach ($m in $MustContain)    { if ($joined -notmatch [regex]::Escape($m)) { $why += "beklenen yok: '$m'" } }
    foreach ($m in $MustNotContain) { if ($joined -match    [regex]::Escape($m)) { $why += "istenmeyen var: '$m'" } }
    if ($ExpectFail) { if ($exit -eq 0)                            { $why += "basarisizlik beklenirdi (exit=0)" } }
    else             { if ($exit -ne 0)                            { $why += "exit=$exit" } }
    if ($why.Count -eq 0) { Write-Pass $Name } else { Write-Fail $Name ($why -join "; ") }
}

# --- 3) test baterisi -----------------------------------------------------------
if (-not $lcDll) {
    # leechcore.dll yoksa: zarif hata yolu TEK gecerli testtir
    Run-Test -Name "T0-zarif-hata (dll yok)" `
        -CliArgs @("--device", "file://$fixture", "--out", (Join-Path $OutDir "t0")) `
        -MustContain @("cannot open LeechCore device", "Hint:") -ExpectFail
    Write-Host ""
    Write-Host "===== SONUC: $script:Pass PASS / $script:Fail FAIL (leechcore.dll eksikti) ====="
    Write-Host "Log: $script:LogPath"
    if ($script:Fail -eq 0) { exit 0 } else { exit 1 }
}

# T1: salt-okunur acilis + paMax raporu + UE kokleyici + tarama
Run-Test -Name "T1-file-readonly" `
    -CliArgs @("--device", "file://$fixture", "--out", (Join-Path $OutDir "t1")) `
    -MustContain @(
        "LeechCore device ready: 'file://$fixture' -> file (writable=no, maxPA=0x000001000000)",
        "Device mode:",
        "Detected UE version: UE5.1",
        "Device window:"
    )

# T2: yazilabilir acilis (write=1) - fWritable=yes raporlanmali
Run-Test -Name "T2-file-writable-flag" `
    -CliArgs @("--device", "file://file=$fixture,write=1", "--out", (Join-Path $OutDir "t2")) `
    -MustContain @("writable=yes")

# T3: olmayan cihaz dosyasi -> zarif hata + ipucu (crash YOK)
Run-Test -Name "T3-zarif-hata (olmayan dosya)" `
    -CliArgs @("--device", "file://file=$OutDir\no_such_dump.raw", "--out", (Join-Path $OutDir "t3")) `
    -MustContain @("cannot open LeechCore device", "Hint:") -ExpectFail

# T4: (opsiyonel) FPGA canli DMA - kart yoksa zarif hata normaldir
if ($Fpga) {
    Run-Test -Name "T4-fpga (opsiyonel)" `
        -CliArgs @("--device", "fpga", "--out", (Join-Path $OutDir "t4")) `
        -MustContain @("LeechCore device ready: 'fpga'")
} else {
    Write-Step "TEST T4-fpga ATLANDI (kart testi icin: -Fpga anahtari)"
}

# --- 4) ozet ----------------------------------------------------------------------
Write-Host ""
Write-Host "===== SONUC: $script:Pass PASS / $script:Fail FAIL ====="
Write-Host "Log: $script:LogPath"
Write-Host "Not: LcWrite round-trip ve hizasiz okuma/yazma testleri icin"
Write-Host "     1a-leech-harness.cpp'i derleyin (docs/1A-WINDOWS-DEVICE-TEST.md bolum 6)."
if ($script:Fail -eq 0) { exit 0 } else { exit 1 }
