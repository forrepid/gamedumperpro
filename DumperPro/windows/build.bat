@echo off
rem ============================================================================
rem DumperPro - Windows (MSVC) derleme scripti
rem
rem NASIL CALISTIRILIR:
rem   1) Baslat menusunden "x64 Native Tools Command Prompt for VS 2022" acin.
rem      (VS 2022 veya Build Tools for VS 2022 + "Desktop development with C++"
rem       workload kurulu olmalidir.)
rem   2) cd DumperPro\windows
rem   3) build.bat
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
rem   - Cikti nesneleri obj\ klasorune toplanir; kaynak klasorler temiz kalir.
rem
rem Cikti: DumperPro\windows\DumperPro.exe
rem ============================================================================
setlocal EnableExtensions
cd /d "%~dp0"

rem --- cl.exe kontrolu -------------------------------------------------------
where cl >nul 2>nul
if errorlevel 1 (
    echo [X] cl.exe bulunamadi - MSVC derleyici yolda degil.
    echo     Bu scripti "x64 Native Tools Command Prompt for VS 2022" icinden
    echo     calistirin: Baslat - Visual Studio 2022 - x64 Native Tools Command Prompt.
    echo.
    echo     VS 2022 Build Tools kurulu degilse:
    echo       https://visualstudio.microsoft.com/downloads/
    echo       "Build Tools for Visual Studio 2022" + "Desktop development with C++"
    echo       workload'unu kurun, sonra bu pencereyi tekrar acin.
    exit /b 1
)

rem --- kaynak agaci kontrolu -------------------------------------------------
if not exist "..\src\main.cpp" (
    echo [X] ..\src bulunamadi - bu script DumperPro\windows\ klasorunden
    echo     calistirilmalidir. cd DumperPro\windows yapip tekrar deneyin.
    exit /b 1
)

if not exist obj mkdir obj

echo [*] Derleniyor: MSVC x64, /std:c++20 /EHsc /O2 ...
cl /nologo /std:c++20 /EHsc /O2 /utf-8 /W3 ^
   /I..\src ^
   ..\src\*.cpp ^
   ..\src\core\*.cpp ..\src\sig\*.cpp ..\src\ue\*.cpp ..\src\il2cpp\*.cpp ^
   ..\src\file\*.cpp ..\src\dump\*.cpp ..\src\hex\*.cpp ..\src\net\*.cpp ^
   ..\src\config\*.cpp ..\src\utils\*.cpp ^
   /Fo:obj\ /Fe:DumperPro.exe

if errorlevel 1 (
    echo [X] Derleme/link BASARISIZ - yukaridaki hata satirlarini inceleyin.
    echo     Not: Kaynaklar /std:c++20 ister; eski bir VS surumu kullaniyorsaniz
    echo     VS 2022 kurulu olmali. Hatalar duzeltilmezse sorun bildirin.
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
