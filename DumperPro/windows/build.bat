@echo off
rem ============================================================================
rem DumperPro - Windows (MSVC) derleme scripti
rem
rem NASIL CALISTIRILIR (iki yontem):
rem   1) Baslat menusunden "x64 Native Tools Command Prompt for VS 2026" (veya
rem      "for VS 2022") acin -> cd DumperPro\windows -> build.bat
rem      (cl.exe zaten yoldadir, script dogrudan derler.)
rem   2) Normal cmd penceresi / Dosya Gezgini'nden cift tik: script Visual
rem      Studio'yu vswhere + bilinen kurulum yollari uzerinden kendisi bulur
rem      ve vcvarsall.bat x64 ile MSVC ortamini kurar.
rem
rem Gereksinim: **VS 2026 (v18)** ya da VS 2022 / Build Tools + "Desktop
rem development with C++" workload. (VS 2019 yollarý da yedek olarak denenir.)
rem
rem TEKNIK NOTLAR (kod gercegine dayanir - docs/LEECH.md):
rem   - Kaynaklar platform-kosullu derlenir. Windows'ta LeechReader.cpp /
rem     ProcessReader.cpp / KernelReader.cpp nativ _WIN32 daliyla derlenir;
rem     EKSTRA bir define GEREKMEZ (USE_LEECH gibi bir sey yoktur).
rem   - leechcore.dll import library / header istemez: LeechReader.cpp DLL'i
rem     calisma zamaninda LoadLibraryA + GetProcAddress ile baglar. DLL yoksa
rem     bile DumperPro.exe acilir; --device kullanilinca kurulum ipucu verir.
rem   - ws2_32.lib otomatik baglanir (src/net/HttpServer.cpp icinde
rem     #pragma comment(lib, "ws2_32.lib") bulunur); baska ek kutuphane gerekmez.
rem   - /utf-8: kaynak dosyalar UTF-8 kodlanmistir (Turkce yorumlar); MSVC
rem     varsayilan kod sayfasinda C4819/bozulma olmamasi icin aciktir.
rem   - /MP: tum .cpp'ler paralel derlenir (cok cekirdekte belirgin hizlanir).
rem   - Cikti nesneleri obj\ klasorune toplanir; kaynak klasorler temiz kalir.
rem
rem Cikti: DumperPro\windows\DumperPro.exe
rem ============================================================================
setlocal EnableExtensions
cd /d "%~dp0"

rem --- 1) cl.exe zaten yolda mi? (Native Tools penceresi) ---------------------
where cl >nul 2>nul
if errorlevel 1 call :LocateVsEnv

rem --- 2) son kontrol ---------------------------------------------------------
where cl >nul 2>nul
if errorlevel 1 (
    echo [X] cl.exe bulunamadi - MSVC derleyici yolda degil ve Visual Studio
    echo     kurulumu otomatik bulunamadi. Iki secenek:
    echo.
    echo     1) Baslat menusunden "x64 Native Tools Command Prompt for VS 2026"
    echo        (veya "for VS 2022") acip bu scripti orada calistirin, ya da
    echo     2) VS Installer'da "Desktop development with C++" workload'unun
    echo        kurulu oldugunu dogrulayin:
    echo        https://visualstudio.microsoft.com/downloads/
    echo        ^(VS 2026 Community uzerinden "C++ ile masaustu gelistirme"^)
    exit /b 1
)

rem --- kaynak agaci kontrolu -------------------------------------------------
if not exist "..\src\main.cpp" (
    echo [X] ..\src bulunamadi - bu script DumperPro\windows\ klasorunden
    echo     calistirilmalidir. cd DumperPro\windows yapip tekrar deneyin.
    exit /b 1
)

if not exist obj mkdir obj

echo [*] Derleniyor: MSVC x64, /std:c++20 /EHsc /O2 /MP ...
cl /nologo /std:c++20 /EHsc /O2 /MP /utf-8 /W3 /D_CRT_SECURE_NO_WARNINGS ^
   /I..\src ^
   ..\src\*.cpp ^
   ..\src\core\*.cpp ..\src\sig\*.cpp ..\src\ue\*.cpp ..\src\il2cpp\*.cpp ^
   ..\src\binfold\*.cpp ^
   ..\src\file\*.cpp ..\src\dump\*.cpp ..\src\hex\*.cpp ..\src\net\*.cpp ^
   ..\src\config\*.cpp ..\src\utils\*.cpp ^
   /Fo:obj\ /Fe:DumperPro.exe

if errorlevel 1 (
    echo [X] Derleme/link BASARISIZ - yukaridaki hata satirlarini inceleyin.
    echo     Not: Kaynaklar /std:c++20 ister; VS 2026 ^(v18^) veya VS 2022
    echo     kurulu olmali. Hatalar duzeltilmezse sorun bildirin.
    exit /b 1
)

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

rem ============================================================================
rem Alt rutinler: Visual Studio'yu bul + vcvarsall.bat x64 ile ortami kur
rem ============================================================================

:LocateVsEnv
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VSPATH="
rem 1. yol: vswhere (VS Installer ile birlikte her kurulumda bulunur)
if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        if not defined VSPATH set "VSPATH=%%i"
    )
)
if defined VSPATH if not exist "%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat" set "VSPATH="
rem 2. yol: bilinen kurulum yollari (VS 2026 = "\18\", VS 2022 = "\2022\")
if not defined VSPATH call :TryKnownPaths
if defined VSPATH (
    echo [*] Visual Studio bulundu: %VSPATH%
    call "%VSPATH%\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>nul
)
goto :eof

:TryKnownPaths
for %%P in (
    "C:\Program Files\Microsoft Visual Studio\18\Community"
    "C:\Program Files\Microsoft Visual Studio\18\Professional"
    "C:\Program Files\Microsoft Visual Studio\18\Enterprise"
    "C:\Program Files\Microsoft Visual Studio\18\BuildTools"
    "C:\Program Files\Microsoft Visual Studio\2022\Community"
    "C:\Program Files\Microsoft Visual Studio\2022\Professional"
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
    "C:\Program Files\Microsoft Visual Studio\2022\BuildTools"
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community"
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools"
) do (
    if not defined VSPATH if exist "%%~P\VC\Auxiliary\Build\vcvarsall.bat" set "VSPATH=%%~P"
)
goto :eof
