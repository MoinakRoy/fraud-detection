@echo off
REM Validate Python code syntax

echo Validating Python code syntax...

setlocal enabledelayedexpansion

set "files=ingest\feed_fetcher.py ingest\ip_lookup.py enrich\signal_deriver.py engine\rule_engine.py stream\processor.py tests\test_signals_and_rules.py main.py"

for %%f in (%files%) do (
    echo Checking %%f...
    python -m py_compile "%%f" 2>nul
    if !errorlevel! neq 0 (
        echo ERROR in %%f
        exit /b 1
    )
)

echo.
echo All files validated successfully!
