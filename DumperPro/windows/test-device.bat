@echo off
rem ============================================================================
rem DumperPro - LeechCore --device otomatik test baterisi (Windows x64)
rem
rem On kosul: build.bat ile DumperPro.exe derlenmis olmali. TEST 1 icin
rem leechcore.dll gerekir (get-leechcore.ps1 ile yerlestirin). TEST 2 ve 3
rem gercek DMA donanim ister; donanim yokken ZARIF HATA normal ve PASS'tir.
rem
rem Testler (docs/LEECH.md ile tutarli):
rem   TEST 1/4 : file:// sentetik 16 MB dump -> LcCreate + LcRead tam tarama
rem              Beklenen cikis kodu 4 (GNames not found - sentetik veride
rem              GNames olmamasi NORMALDIR; motorun cihaz hatti calismis sayilir)
rem   TEST 2/4 : fpga canli DMA probe (donanim yok -> cikis 2, zarif hata)
rem   TEST 3/4 : usb3380: canli DMA probe (donanim yok -> cikis 2, zarif hata)
rem   TEST 4/4 : baz cizgisi: --help (cikis 0) + --file notepad.exe (PE okuma)
rem
rem Kullanim: test-device.bat          (bu klasorden; loglar testlog_*.log)
rem
rem NOT (yol-guvenli): klasor adinda parantez olan yerlesimlerde de calisir
rem      (orn. "UnrealDumperX_src (4)"). Kural: %CD% / %LCDLL% gibi parantez
rem      icerebilen degerler yalnizca blok DIKinda echo'lanir; blok icinde
rem      %ERRORLEVEL% genisletilmez (parse-zamani tuzagi). TEST 4 PE alt testi
rem      goto-akislidir.
rem ============================================================================
setlocal EnableExtensions
cd /d "%~dp0"

set "EXE=DumperPro.exe"
set /a PASS=0
set /a FAIL=0

echo ============================================================
echo  DumperPro - LeechCore device test baterisi
echo ============================================================
echo.

rem --- on kontrol: DumperPro.exe ----------------------------------------------
if not exist "%EXE%" (
    echo [X] %EXE% bulunamadi. Once build.bat calistirin:
    echo       x64 Native Tools Command Prompt icinde:  build.bat
    exit /b 2
)

rem --- on kontrol: leechcore.dll ----------------------------------------------
set "LCDLL="
if exist "leechcore.dll" set "LCDLL=%CD%\leechcore.dll"
if not defined LCDLL for %%i in (leechcore.dll) do if not "%%~$PATH:i"=="" set "LCDLL=%%~$PATH:i"
rem YOL-GUVENLI: tek satirlik if - %LCDLL% (parantezli yol olabilir) blok icinde
rem genisletilirse "(4)" gibi bir klasor adi bloku erken kapatir ve
rem "was unexpected at this time" hatasi verir. Tek satir = blok yok = guvenli.
if defined LCDLL echo [*] leechcore.dll: %LCDLL%
if not defined LCDLL (
    echo [!] leechcore.dll bulunamadi - TEST 1 basarisiz olacak.
    echo     Kurulum: powershell -ExecutionPolicy Bypass -File get-leechcore.ps1
)
echo.

rem ---------------------------------------------------------------------------
rem TEST 1/4 : file:// sentetik dump - LcCreate + LcRead tarama hatti
rem ---------------------------------------------------------------------------
echo [TEST 1/4] file:// sentetik 16 MB dump uzerinde LcCreate + LcRead taramasi
echo   -> fixture uretiliyor: test_dump.bin  (desen + DMPPRO-TEST-SIG!@0x11000 + UE5.1 marker@0x30000)
powershell -NoProfile -ExecutionPolicy Bypass -Command "$b=[byte[]]::new(16777216); $pat=[byte[]]((0..255)*1024); for($o=0;$o -lt $b.Length;$o+=$pat.Length){[Buffer]::BlockCopy($pat,0,$b,$o,$pat.Length)}; [IO.File]::WriteAllBytes('test_dump.bin',$b)"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$f=[IO.File]::Open('test_dump.bin','Open','ReadWrite'); try { $s=[Text.Encoding]::ASCII.GetBytes('DMPPRO-TEST-SIG!'); $f.Position=0x11000; $f.Write($s,0,$s.Length); $u=[Text.Encoding]::ASCII.GetBytes('++UE5+Release-5.1.1-0-Test'+[char]0); $f.Position=0x30000; $f.Write($u,0,$u.Length) } finally { $f.Close() }"
if not exist "test_dump.bin" (
    echo [X] fixture uretilemedi - PowerShell calistirilamadi mi?
    echo   [FAIL] TEST 1
    set "T1=FAIL"
    set /a FAIL+=1
    goto Test2
)
for %%A in ("test_dump.bin") do set "FSZ=%%~zA"
echo   -> fixture hazir (%FSZ% bayt). Calistiriliyor:
echo      %EXE% --device "file://%CD%\test_dump.bin" --out out_t1
"%EXE%" --device "file://%CD%\test_dump.bin" --out "out_t1" > "testlog_t1.log" 2>&1
set "RC1=%ERRORLEVEL%"
set "T1=PASS"
echo   -> cikis kodu: %RC1%  (beklenen: 4 = GNames not found; sentetik dump'ta GNames olmamasi normal)
if not "%RC1%"=="4" if not "%RC1%"=="5" set "T1=FAIL"
findstr /C:"LeechCore device ready" "testlog_t1.log" >nul 2>nul || set "T1=FAIL"
findstr /C:"Device window:" "testlog_t1.log" >nul 2>nul || set "T1=FAIL"
findstr /C:"Detected UE version: UE5.1" "testlog_t1.log" >nul 2>nul || set "T1=FAIL"
if "%T1%"=="PASS" goto T1Done
echo   -> cikti incelemesi icin: testlog_t1.log
if not defined LCDLL echo   -> ipucu: leechcore.dll yok; kurulum icin get-leechcore.ps1 calistirin.
:T1Done
if "%T1%"=="PASS" (
    echo   [PASS] TEST 1
    set /a PASS+=1
) else (
    echo   [FAIL] TEST 1
    set /a FAIL+=1
)
echo.

rem ---------------------------------------------------------------------------
rem TEST 2/4 : fpga canli DMA probe
rem ---------------------------------------------------------------------------
:Test2
echo [TEST 2/4] fpga probe - canli FPGA DMA karti acilisi
echo   -> donanim YOKSA zarif hata beklenir; kart TAKILISA cihaz acilir ve tarama cosar.
echo      Calistiriliyor: %EXE% --device "fpga" --out out_t2
"%EXE%" --device "fpga" --out "out_t2" > "testlog_t2.log" 2>&1
set "RC2=%ERRORLEVEL%"
set "T2=FAIL"
set "T2NOTE="
if "%RC2%"=="2" set "T2=PASS"
if "%RC2%"=="2" set "T2NOTE=DMA donanim yok - zarif hata (normal); kart yokken calismayan donanim yolu"
if "%RC2%"=="4" set "T2=PASS"
if "%RC2%"=="4" set "T2NOTE=FPGA donanim algilandi - cihaz acildi, tarama tamam (GNames yok: canli RAM'de normal)"
if not "%RC2%"=="2" if not "%RC2%"=="4" set "T2=FAIL"
if "%T2%"=="PASS" findstr /C:"LeechCore device ready" "testlog_t2.log" >nul 2>nul && goto T2HasDev
if "%T2%"=="PASS" findstr /C:"cannot open LeechCore device" "testlog_t2.log" >nul 2>nul || set "T2=FAIL"
:T2HasDev
echo   -> cikis kodu: %RC2%  (%T2NOTE%)
if "%T2%"=="PASS" (
    echo   [PASS] TEST 2
    set /a PASS+=1
) else (
    echo   [FAIL] TEST 2  - ayrinti: testlog_t2.log
    set /a FAIL+=1
)
echo.

rem ---------------------------------------------------------------------------
rem TEST 3/4 : usb3380: canli DMA probe
rem ---------------------------------------------------------------------------
echo [TEST 3/4] usb3380: probe - USB3380 tabanli DMA karti acilisi
echo   -> TEST 2 ile ayni semantik; donanim yoksa zarif hata beklenir.
echo      Calistiriliyor: %EXE% --device "usb3380:" --out out_t3
"%EXE%" --device "usb3380:" --out "out_t3" > "testlog_t3.log" 2>&1
set "RC3=%ERRORLEVEL%"
set "T3=FAIL"
set "T3NOTE="
if "%RC3%"=="2" set "T3=PASS"
if "%RC3%"=="2" set "T3NOTE=DMA donanim yok - zarif hata (normal)"
if "%RC3%"=="4" set "T3=PASS"
if "%RC3%"=="4" set "T3NOTE=USB3380 donanim algilandi - cihaz acildi, tarama tamam (GNames yok: normal)"
if not "%RC3%"=="2" if not "%RC3%"=="4" set "T3=FAIL"
if "%T3%"=="PASS" findstr /C:"LeechCore device ready" "testlog_t3.log" >nul 2>nul && goto T3HasDev
if "%T3%"=="PASS" findstr /C:"cannot open LeechCore device" "testlog_t3.log" >nul 2>nul || set "T3=FAIL"
:T3HasDev
echo   -> cikis kodu: %RC3%  (%T3NOTE%)
if "%T3%"=="PASS" (
    echo   [PASS] TEST 3
    set /a PASS+=1
) else (
    echo   [FAIL] TEST 3  - ayrinti: testlog_t3.log
    set /a FAIL+=1
)
echo.

rem ---------------------------------------------------------------------------
rem TEST 4/4 : baz cizgisi - --help ve --file (PE taban hatti)
rem ---------------------------------------------------------------------------
echo [TEST 4/4] baz cizgisi: --help cikis kodu 0 olmali + --file PE okuma
"%EXE%" --help > "testlog_t4_help.log" 2>&1
set "RC4=%ERRORLEVEL%"
set "T4=PASS"
echo   -> --help cikis kodu: %RC4%  (beklenen: 0)
if not "%RC4%"=="0" set "T4=FAIL"

rem YOL-GUVENLI goto-akisi: blok icinde %ERRORLEVEL% genisletilirse deger
rem blokun PARSE anindan gelir (exe calismadan onceki deger) - yanlis cikis
rem kodu okunur. Bu yuzden PE alt testi bloksuz, duz akisla yazildi.
set "T4PE=SKIPPED"
copy /y "%SystemRoot%\System32\notepad.exe" "notepad_test.exe" >nul 2>nul
if not exist "notepad_test.exe" goto T4NoPE
echo   -> Calistiriliyor: %EXE% --file notepad_test.exe --out out_t4
"%EXE%" --file "notepad_test.exe" --out "out_t4" > "testlog_t4_pe.log" 2>&1
set "RC4PE=%ERRORLEVEL%"
set "T4PE=PASS"
if not "%RC4PE%"=="0" if not "%RC4PE%"=="4" if not "%RC4PE%"=="5" set "T4PE=FAIL"
findstr /C:"File mode:" "testlog_t4_pe.log" >nul 2>nul || set "T4PE=FAIL"
echo   --file cikis kodu: %RC4PE%  (beklenen: 4 = GNames not found; notepad UE oyunu degildir)
goto T4PEDone
:T4NoPE
echo   -> notepad.exe kopyalanamadi (izin/antivirus) - PE alt testi atlandi, --help yeterli
:T4PEDone
if "%T4PE%"=="FAIL" set "T4=FAIL"
if "%T4%"=="PASS" (
    echo   [PASS] TEST 4
    set /a PASS+=1
) else (
    echo   [FAIL] TEST 4  - ayrinti: testlog_t4_help.log / testlog_t4_pe.log
    set /a FAIL+=1
)
echo.

rem --- ozet -------------------------------------------------------------------
del "notepad_test.exe" >nul 2>nul
echo ============================================================
echo  SONUC: %PASS% PASS / %FAIL% FAIL
echo ============================================================
echo Loglar   : testlog_t1.log, testlog_t2.log, testlog_t3.log, testlog_t4_*.log
echo Ciktilar : out_t1\ .. out_t4\  ^(DumperPro cikti klasorleri^)
echo Not      : TEST 2/3 donanimli kart ile de PASS sayilir; donanim yokken
echo            zarif hata yolunun calismasi testin kendisidir. Derin testler:
echo            docs\LEECH.md (bolum 9) ve scripts\windows\ altindaki kitler.
echo.
if "%FAIL%"=="0" exit /b 0
exit /b 1
