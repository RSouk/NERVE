@echo off
REM NERVE GHOST - Automated Scraper Runner
REM This batch file runs the GitHub and PasteBin scrapers

echo ========================================
echo NERVE GHOST - Automated Scraper Runner
echo ========================================
echo.

REM Change to the NERVE project directory
cd /d C:\Projects\NERVE

REM Activate virtual environment (if it exists)
if exist venv\Scripts\activate.bat (
    echo Activating virtual environment...
    call venv\Scripts\activate.bat
) else (
    echo WARNING: Virtual environment not found at venv\Scripts\activate.bat
    echo Continuing without virtual environment...
)

echo.
echo Running scrapers...
echo.

REM Run the master scheduler script
python backend\run_all_scrapers.py

echo.
echo ========================================
echo Scraper run completed!
echo Check data\scraper_logs.txt for details
echo ========================================
echo.

REM Uncomment the line below if running manually (keeps window open)
REM pause
