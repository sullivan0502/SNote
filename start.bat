@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ===============================================
echo   Plateforme prof / eleve - demarrage
echo ===============================================

REM --- Environnement virtuel Python (isolé, cree une seule fois) ---
if not exist venv (
    echo [1/4] Premiere installation : creation de l'environnement Python...
    python -m venv venv
    if errorlevel 1 (
        echo.
        echo ERREUR : Python n'est pas trouve. Installe Python 3.11+ depuis
        echo https://www.python.org/downloads/ puis relance ce fichier.
        pause
        exit /b 1
    )
)

call venv\Scripts\activate.bat

echo [2/4] Verification des dependances...
pip install -r requirements.txt -q

REM --- Cle secrete : generee automatiquement au tout premier lancement ---
if not exist .env (
    echo [3/4] Premiere installation : generation de ta cle secrete...
    for /f "delims=" %%i in ('python -c "import secrets; print(secrets.token_hex(32))"') do set SECRET=%%i
    echo EDU_SECRET_KEY=!SECRET!>.env
    echo   -> cle generee dans .env, ne la partage jamais et ne la commite pas.
) else (
    echo [3/4] Configuration deja presente.
)

echo [4/4] Lancement du serveur...
echo.
echo   Acces depuis cet ordinateur   : http://127.0.0.1:8000
echo   Acces depuis le reseau local  : http://[IP-de-ce-PC]:8000
echo   (voir README.md pour l'acces depuis l'exterieur)
echo.
echo Laisse cette fenetre ouverte tant que le site doit rester accessible.
echo Ferme-la (ou Ctrl+C) pour arreter le serveur.
echo.

python -m uvicorn main:app --host 0.0.0.0 --port 8000

pause
