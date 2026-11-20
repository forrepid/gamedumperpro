# ============================================================================
# DumperPro - 1b Gercek UE5 oyunu: canli surec SDK uretimi (Windows)
#
# Oyunu KENDI Windows makinenizde calistirin (ana menu yeterli), sonra bu
# scripti verin: sureci bulur, DumperPro --process ile tam pipeline'i
# (GNames + GObjects + SDK) kosar ve cikti dosyalarini denetler.
#
# Kullanim:
#   powershell -ExecutionPolicy Bypass -File 1b-live-dump.ps1 `
#       -Process FutureFaxOperator-Win64-Shipping.exe -Out C:\out\demon-sdk
#
# Beklenen sonuc: "Objects parsed" + "SDK generated" + SDK klasoru (*.h)
# Arka plan: docs/1B-UE5-SDK-TEST.md
# ============================================================================

#Requires -Version 5.1
param(
    [Parameter(Mandatory=$true)][string]$Process,
    [string]$DumperPro = ".\DumperPro.exe",
    [string]$Out       = ".\1b-sdk-output",
    [switch]$Json
)

$script:Pass = 0
$script:Fail = 0
function Write-Pass([string]$name) {
    $script:Pass++
    Write-Host "[PASS] $name" -ForegroundColor Green
}
function Write-Fail([string]$name, [string]$why) {
    $script:Fail++
    Write-Host "[FAIL] $name  ($why)" -ForegroundColor Red
}

if (-not (Test-Path $DumperPro)) {
    Write-Host "[X] DumperPro.exe bulunamadi: $DumperPro (-DumperPro ile yolu verin)"
    exit 2
}
Write-Host "[*] DumperPro: $DumperPro"

# --- 1) surec kontrolu -------------------------------------------------------
$proc = Get-Process -Name $Process -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $proc) {
    $short = $Process -replace '-Win64-Shipping$', ''
    $proc = Get-Process -Name $short -ErrorAction SilentlyContinue | Select-Object -First 1
}
if (-not $proc) {
    Write-Host "[X] Surec bulunamadi: $Process"
    Write-Host "    Oyunu calistirin (ana menu yeterli) ve scripti tekrar verin."
    Write-Host "    Calisan sureclerde arama: Get-Process *shipping*"
    exit 3
}
Write-Host "[PASS] Surec bulundu: $($proc.ProcessName) (PID $($proc.Id))"
$script:Pass++

# --- 2) tam pipeline ----------------------------------------------------------
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$log = Join-Path $Out "1b-run-log.txt"
Write-Host "[*] DumperPro --process $($proc.ProcessName) -> $Out"
$args = @("--process", $proc.ProcessName, "--out", $Out)
if ($Json) { $args += "--json" }
& $DumperPro @args 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $log | ForEach-Object {
    if ($_ -match "Names parsed")          { Write-Host "  [OK] $_" -ForegroundColor Green }
    elseif ($_ -match "Objects parsed")    { Write-Host "  [OK] $_" -ForegroundColor Green }
    elseif ($_ -match "SDK generated|Done in") { Write-Host "  [OK] $_" -ForegroundColor Green }
    elseif ($_ -match "^\[X\]|not found|failed") { Write-Host "  [!!] $_" -ForegroundColor Yellow }
}

# --- 3) cikti denetimi ---------------------------------------------------------
$checks = @(
    @{ File = "Names.txt";    Name = "Names.txt (FName dump)" },
    @{ File = "Objects.txt";  Name = "Objects.txt (UObject dump)" },
    @{ File = "offsets.txt";  Name = "offsets.txt (runtime offset probe)" }
)
foreach ($c in $checks) {
    $p = Join-Path $Out $c.File
    if ((Test-Path $p) -and ((Get-Item $p).Length -gt 0)) {
        Write-Pass "$($c.Name) - $([math]::Round((Get-Item $p).Length/1KB,1)) KB"
    } else {
        Write-Fail "$($c.Name)" "dosya yok/bose - pipeline ciktisini logdan kontrol edin: $log"
    }
}
$sdkDir = Join-Path $Out "SDK"
if (Test-Path $sdkDir) {
    $headers = Get-ChildItem $sdkDir -Filter *.h -ErrorAction SilentlyContinue
    if ($headers.Count -gt 0) {
        Write-Pass "SDK uretimi: $($headers.Count) baslik dosyasi ($sdkDir)"
    } else {
        Write-Fail "SDK klasoru var ama .h yok" "$sdkDir"
    }
} else {
    Write-Fail "SDK klasoru" "$sdkDir yok - GObjects bulunamamis olabilir (oyun menuye ulasmali)"
}

# --- 4) ozet --------------------------------------------------------------------
Write-Host ""
Write-Host "===== SONUC: $script:Pass PASS / $script:Fail FAIL ====="
Write-Host "Log: $log"
if ($script:Fail -eq 0) {
    Write-Host "1b canli ayagi TAMAM: gercek UE5 surecinde GNames+GObjects+SDK uretildi."
} else {
    Write-Host "Ipucu: oyun ana menude olmali; SDK icin GObjects gerekir (runtime veri)."
}
if ($script:Fail -eq 0) { exit 0 } else { exit 1 }
