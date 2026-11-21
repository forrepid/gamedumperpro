@echo off
rem ============================================================================
rem DumperPro - Windows (MSVC) derleme scripti  [surum 0.4.2.1 - VS 2026 destekli]
rem
rem NASIL CALISTIRILIR (iki yontem):
rem   1) Baslat menusunden "x64 Native Tools Command Prompt for VS 2026" (veya
rem      "for VS 2022") acin -> cd DumperPro\windows -> build.bat
rem      cl.exe zaten yoldadir; script dogrudan derler.
rem   2) Normal cmd / Dosya Gezgini cift tik: script Visual Studio'yu vswhere +
rem      bilinen kurulum yollari uzerinden kendisi bulur ve vcvarsall.bat x64
rem      ile MSVC ortamini kurar.
rem
rem Gereksinim: VS 2026 (v18) ya da VS 2022 / Build Tools + "Desktop development
rem with C++" workload. VS 2019 yedek olarak denenir.
rem
rem NOT: Bu script goto-akislidir; blok icindeki echo metinlerinde parantez
rem      YOKTUR (cmd.exe kacispsz parantezde 'was unexpected' hatasi verir).
rem
rem TEKNIK NOTLAR (docs/LEECH.md):
rem   - Kaynaklar platform-kosullu derlenir; Windows'ta LeechReader / ProcessReader
rem     / KernelReader nativ _WIN32 daliyla derlenir. EKSTRA define GEREKMEZ.
rem   - leechcore.dll calisma zamaninda LoadLibraryA + GetProcAddress ile baglanir;
rem     DLL yoksa da exe acilir, --device kullanilinca kurulum ipucu verir.
rem   - ws2_32.lib HttpServer.cpp icindeki #pragma comment ile otomatik baglanir.
rem   - /utf-8 Turkce yorumlu kaynaklar icin; /MP paralel derleme.
rem
rem Cikti: DumperPro\windows\DumperPro.exe
rem ============================================================================
setlocal EnableExtensions
cd /d "%~dp0"

echo DumperPro build.bat v0.4.2.1 - VS 2026 / 2022 otomatik tespitli

rem --- 1) cl.exe zaten yolda mi? ----------------------------------------------
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
where cl >nul 2>nul
if not errorlevel 1 goto :EnvReady
call :LocateVsEnv
where cl >nul 2>nul
if not errorlevel 1 goto :EnvReady

rem --- 2) cl bulunamadi: tani + kural -----------------------------------------
echo.
echo [X] cl.exe bulunamadi - MSVC derleyici yolda degil ve Visual Studio
echo     kurulumu otomatik bulunamadi. Iki secenek:
echo.
echo     [1] Baslat menusunden "x64 Native Tools Command Prompt for VS 2026"
echo         veya "for VS 2022" penceresini acip scripti orada calistirin.
echo     [2] VS Installer'da "Desktop development with C++" workload kurulu mu
echo         kontrol edin: https://visualstudio.microsoft.com/downloads/
echo.
echo     Tespit gunlugu:
if exist "%VSWHERE%" (
    echo     - vswhere mevcut; VC.Tools workload'lu kurulum donmedi. Kurulumlar:
    "%VSWHERE%" -latest -products * -property installationPath
) else (
    echo     - vswhere bulunamadi: "%VSWHERE%"
)
echo     Beklenen kurulum yollari:
echo       VS 2026 : C:\Program Files\Microsoft Visual Studio\18\Community
echo       VS 2022 : C:\Program Files\Microsoft Visual Studio\2022\Community
exit /b 1

rem --- ortam hazir: kaynak agaci + derleme ------------------------------------
:EnvReady
if exist "..\src\main.cpp" goto :SrcOk
echo [X] ..\src bulunamadi - bu script DumperPro\windows\ klasorunden
echo     calistirilmalidir. cd DumperPro\windows yapip tekrar deneyin.
exit /b 1

:SrcOk
if exist obj goto :ObjOk
mkdir obj
:ObjOk
echo.
echo [*] Derleniyor: MSVC x64, /std:c++20 /EHsc /O2 /MP ...
cl /nologo /std:c++20 /EHsc /O2 /MP /utf-8 /W3 /D_CRT_SECURE_NO_WARNINGS ^
   /I..\src ^
   ..\src\*.cpp ^
   ..\src\core\*.cpp ..\src\sig\*.cpp ..\src\ue\*.cpp ..\src\il2cpp\*.cpp ^
   ..\src\binfold\*.cpp ^
   ..\src\file\*.cpp ..\src\dump\*.cpp ..\src\hex\*.cpp ..\src\net\*.cpp ^
   ..\src\config\*.cpp ..\src\utils\*.cpp ^
   /Fo:obj\ /Fe:DumperPro.exe
if errorlevel 1 goto :BuildFailed

echo.
echo [OK] DumperPro.exe derlendi: %CD%\DumperPro.exe
echo.
echo Sonraki adimlar:
echo   1) leechcore.dll kurulumu  : powershell -ExecutionPolicy Bypass -File get-leechcore.ps1
echo   2) otomatik test baterisi  : test-device.bat
echo   3) manuel deneme           : DumperPro.exe --device "file://%CD%\test_dump.bin"
echo.
endlocal
exit /b 0

:BuildFailed
echo.
echo [X] Derleme/link BASARISIZ - yukaridaki hata satirlarini inceleyin.
echo     Not: Kaynaklar /std:c++20 ister; VS 2026 veya VS 2022 kurulu olmali.
echo     Hatalar duzeltilmezse ciktiyi aynen iletin.
exit /b 1

rem ============================================================================
rem Alt rutin: Visual Studio'yu bul + vcvarsall.bat x64 ile ortami kur
rem ============================================================================
:LocateVsEnv
set "VSPATH="
if not exist "%VSWHERE%" goto :TryKnownPaths
echo [*] Visual Studio tespiti: vswhere sorgulaniyor...
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    if not defined VSPATH set "VSPATH=%%i"
)
if not defined VSPATH goto :TryKnownPaths
if not exist "%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat" goto :TryKnownPaths
call :SetupEnv
goto :eof

:TryKnownPaths
if defined VSPATH goto :eof
echo [*] vswhere sonuc vermedi - bilinen kurulum yollari deneniyor...
for %%P in (
    "C:\Program Files\Microsoft Visual Studio\18\Community"
    "C:\Program Files\Microsoft Visual Studio\18\Professional"
    "C:\Program Files\Microsoft Visual Studio\18\Enterprise"
    "C:\Program Files\Microsoft Visual Studio\18\BuildTools"
    "C:\Program Files\Microsoft Visual Studio\2026\Community"
    "C:\Program Files\Microsoft Visual Studio\2026\Professional"
    "C:\Program Files\Microsoft Visual Studio\2026\Enterprise"
    "C:\Program Files\Microsoft Visual Studio\2026\BuildTools"
    "C:\Program Files\Microsoft Visual Studio\2022\Community"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional"
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
    "C:\Program Files\Microsoft Visual Studio\2022\BuildTools"
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community"
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools"
) do (
    if not defined VSPATH if exist "%%~P\VC\Auxiliary\Build\vcvarsall.bat" set "VSPATH=%%~P"
)
if not defined VSPATH goto :eof
call :SetupEnv
goto :eof

:SetupEnv
echo [*] Visual Studio bulundu: %VSPATH%
echo [*] MSVC ortami hazirlaniyor: vcvarsall.bat x64
call "%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat" x64
goto :eof
