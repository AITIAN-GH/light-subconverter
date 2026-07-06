@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul
cd /d "%~dp0"
color 0B
title Subscription Tool (main.py)

set "SCRIPT_DIR=%~dp0"
set "MAIN=%SCRIPT_DIR%main.py"
set "START_INPUT=%~1"
set "PY="
set "HOST=127.0.0.1"
set "PORT=25500"

call :preflight
if errorlevel 1 goto end

:menu
cls
call :banner
echo  Choose mode:
echo.
echo    1. Convert once (choose Clash / v2rayN / Advanced)
echo    [Enter] Start local subscription service (default)
echo    Q. Quit
echo.
set "MODE="
set /p "MODE=  Enter 1 for convert, or press Enter for service: "
if "%MODE%"=="1" goto convert_mode
if /I "%MODE%"=="Q" goto end
goto serve_mode

rem ============================================================
rem  Convert mode
rem ============================================================
:convert_mode
call :choose_target
if errorlevel 1 goto menu

:input_step
call :ask_input
if errorlevel 2 goto menu
if errorlevel 1 goto end

call :confirm_run
if errorlevel 3 goto input_step
if errorlevel 2 goto menu
if errorlevel 1 goto end

call :run_convert
call :continue_prompt
if errorlevel 1 goto end
goto menu

rem ============================================================
rem  Service mode
rem ============================================================
:serve_mode
cls
echo.
echo ============================================================
echo              Local Subscription Service
echo ============================================================
echo  Listen  : http://%HOST%:%PORT%/
echo  Python  : %PY%
echo.
echo  Subscription URLs:
echo.
echo    clash : http://%HOST%:%PORT%/sub?target=clash^&url=^<source^>
echo    v2rayN: http://%HOST%:%PORT%/sub?target=v2ray^&url=^<source^>
echo.
echo  Advanced targets are still available manually:
echo    target=base64 / target=links
echo.
echo  ^<source^> can be a local file (b.txt) or a remote URL.
echo.
echo  Press Ctrl+C to stop the service.
echo ============================================================
echo.
%PY% "%MAIN%" serve --host %HOST% --port %PORT%
echo.
echo [Service stopped]
echo.
pause
goto end

rem ============================================================
rem  Subroutines
rem ============================================================
:preflight
if not exist "%MAIN%" (
    echo.
    echo [ERROR] main.py was not found in the current folder.
    echo Current folder: "%CD%"
    echo.
    pause
    exit /b 1
)
set "PY="
python --version >nul 2>nul && set "PY=python"
if not defined PY (
    py -3 --version >nul 2>nul && set "PY=py -3"
)
if not defined PY (
    python3 --version >nul 2>nul && set "PY=python3"
)
if not defined PY (
    echo.
    echo [ERROR] No working Python found.
    echo Install Python 3 from https://www.python.org and tick "Add to PATH".
    echo.
    pause
    exit /b 1
)
exit /b 0

:banner
echo.
echo ============================================================
echo                 Subscription Tool  (main.py)
echo ============================================================
echo  Working folder : %CD%
echo  Python         : %PY%
echo.
echo  Types : VLESS / VMess / Trojan / Shadowsocks / Socks / HTTP
echo          Mieru / Hysteria
echo  Common targets : Clash / v2rayN
echo.
if defined START_INPUT (
    echo  [Detected startup file] "%START_INPUT%"
    echo  It will be pre-filled at the input step.
    echo.
)
exit /b 0

:choose_target
echo.
echo  Choose conversion target:
echo.
echo    1. Clash / Mihomo YAML      best compatibility
echo    2. v2rayN subscription      share links in base64
echo    3. Advanced exports         base64 / plain links
echo.
set "SEL="
set /p "SEL=  Enter number [default 1]: "
if "%SEL%"=="" set "SEL=1"
if "%SEL%"=="1" set "TARGET=clash"& exit /b 0
if "%SEL%"=="2" set "TARGET=v2ray"& exit /b 0
if "%SEL%"=="3" goto choose_advanced_target
if /I "%SEL%"=="Q" exit /b 1
echo.
echo [TIP] Enter 1, 2 or 3. Enter Q to go back.
echo.
goto choose_target

:choose_advanced_target
echo.
echo  Advanced export target:
echo.
echo    1. base64      base64 share-link subscription
echo    2. links       plain share-link list
echo.
echo  Note: protocols without common share links may be skipped.
echo.
set "SEL="
set /p "SEL=  Enter number [default 1, M=main target menu]: "
if "%SEL%"=="" set "SEL=1"
if "%SEL%"=="1" set "TARGET=base64"& exit /b 0
if "%SEL%"=="2" set "TARGET=links"& exit /b 0
if /I "%SEL%"=="M" goto choose_target
if /I "%SEL%"=="Q" exit /b 1
echo.
echo [TIP] Enter 1 or 2. Enter M to go back.
echo.
goto choose_advanced_target

:ask_input
echo.
if not defined START_INPUT goto ask_input_manual
if not exist "%START_INPUT%" (
    set "START_INPUT="
    goto ask_input_manual
)
echo  Dragged / startup file detected:
echo  "%START_INPUT%"
echo.
:ask_input_start_prompt
set "ANS="
set /p "ANS=  Use this input file? [Y/N, default Y]: "
if "%ANS%"=="" set "ANS=Y"
if /I "%ANS%"=="N" set "START_INPUT=" & goto ask_input_manual
if /I "%ANS%"=="Y" (
    for %%F in ("%START_INPUT%") do set "INPUT_FILE=%%~fF"
    set "START_INPUT="
    exit /b 0
)
echo [TIP] Enter Y or N.
goto ask_input_start_prompt

:ask_input_manual
echo  Enter input file path:
echo    - You can drag a file into this window
echo    - You can type a.txt or C:\path\file.yaml
echo    - Enter M to go back to menu, Q to quit
echo.
echo  Common files in current folder:
dir /b *.txt *.yaml *.yml 2>nul
echo.
set "INPUT_FILE="
set /p "INPUT_FILE=  Input file path: "
if "%INPUT_FILE%"=="" (
    echo.
    echo [TIP] Input path cannot be empty.
    goto ask_input_manual
)
if /I "%INPUT_FILE%"=="M" exit /b 2
if /I "%INPUT_FILE%"=="Q" exit /b 1
set "INPUT_FILE=%INPUT_FILE:"=%"
if not exist "%INPUT_FILE%" (
    echo.
    echo [ERROR] File does not exist: "%INPUT_FILE%"
    goto ask_input_manual
)
for %%F in ("%INPUT_FILE%") do set "INPUT_FILE=%%~fF"
exit /b 0

:confirm_run
call :build_subscription_urls
set "URL_RC=%ERRORLEVEL%"
call :set_output_file
echo.
echo ============================================================
echo  Confirm conversion
echo ============================================================
echo  Target : %TARGET%
echo  Input  : "%INPUT_FILE%"
echo  Output : "%OUTPUT_FILE%"
echo.
echo  Service subscription links:
if "%URL_RC%"=="0" (
    echo  clash : http://%HOST%:%PORT%/sub?target=clash^&url=%ENC_INPUT_FILE%
    echo  v2rayN: http://%HOST%:%PORT%/sub?target=v2ray^&url=%ENC_INPUT_FILE%
    if /I not "%TARGET%"=="clash" if /I not "%TARGET%"=="v2ray" (
        echo  advanced selected : http://%HOST%:%PORT%/sub?target=%TARGET%^&url=%ENC_INPUT_FILE%
    )
) else (
    echo  [WARN] Could not build subscription URL.
)
echo.
echo  Command:
echo  %PY% "%MAIN%" convert "%INPUT_FILE%" --to %TARGET%
echo.
:confirm_prompt
set "ANS="
set /p "ANS=  Start? [Y=start / N=menu / R=re-enter input, default Y]: "
if "%ANS%"=="" set "ANS=Y"
if /I "%ANS%"=="Y" exit /b 0
if /I "%ANS%"=="N" exit /b 2
if /I "%ANS%"=="R" exit /b 3
echo [TIP] Enter Y, N or R.
goto confirm_prompt

:build_subscription_urls
set "ENC_INPUT_FILE="
for /f "usebackq delims=" %%U in (`powershell -NoProfile -Command "[System.Uri]::EscapeDataString($env:INPUT_FILE)" 2^>nul`) do set "ENC_INPUT_FILE=%%U"
if not defined ENC_INPUT_FILE exit /b 1
exit /b 0

:set_output_file
for %%F in ("%INPUT_FILE%") do set "IN_DIR=%%~dpF"
set "OUT_EXT=.yaml"
if /I "%TARGET%"=="clash" set "OUT_EXT=.yaml"
if /I "%TARGET%"=="v2ray" set "OUT_EXT=.txt"
if /I "%TARGET%"=="base64" set "OUT_EXT=.txt"
if /I "%TARGET%"=="links" set "OUT_EXT=.txt"
set "OUTPUT_FILE=%IN_DIR%sub%OUT_EXT%"
exit /b 0

:run_convert
echo.
echo ============================================================
echo  Converting...
echo ============================================================
%PY% "%MAIN%" convert "%INPUT_FILE%" --to %TARGET%
set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" (
    echo [FAILED] Conversion failed. Exit code: %RC%
    echo Check the input format, or run the command above for details.
    echo.
    exit /b 0
)
echo [OK] Conversion succeeded.

rem --- Locate the produced file (sub.<ext>) next to the input, then open Explorer ---
call :set_output_file

if exist "%OUTPUT_FILE%" (
    for %%F in ("%OUTPUT_FILE%") do echo Output file: "%OUTPUT_FILE%"  ^(%%~zF bytes^)
    echo.
    echo ------------------------- preview --------------------------
    set "_PV=0"
    for /f "usebackq delims=" %%L in ("%OUTPUT_FILE%") do (
        if !_PV! lss 6 (
            echo %%L
            set /a _PV+=1
        )
    )
    if !_PV! equ 0 echo (empty output)
    echo ------------------------------------------------------------
    echo.
    explorer /select,"%OUTPUT_FILE%"
) else (
    echo Output file: sub%OUT_EXT% ^(check the input folder^)
)
echo.
exit /b 0

:continue_prompt
set "ANS="
set /p "ANS=  Convert another file? [Y/N, default N]: "
if "%ANS%"=="" exit /b 1
if /I "%ANS%"=="Y" exit /b 0
if /I "%ANS%"=="N" exit /b 1
echo [TIP] Enter Y or N.
goto continue_prompt

:end
endlocal
exit /b 0
