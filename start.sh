#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

echo "==============================================="
echo "  Plateforme prof / élève - démarrage"
echo "==============================================="

if [ ! -d venv ]; then
    echo "[1/4] Première installation : création de l'environnement Python..."
    python3 -m venv venv
fi

source venv/bin/activate

echo "[2/4] Vérification des dépendances..."
pip install -r requirements.txt -q

if [ ! -f .env ]; then
    echo "[3/4] Première installation : génération de ta clé secrète..."
    echo "EDU_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')" > .env
    echo "  -> clé générée dans .env, ne la partage jamais et ne la commite pas."
else
    echo "[3/4] Configuration déjà présente."
fi

echo "[4/4] Lancement du serveur..."
echo ""
echo "  Accès depuis cette machine   : http://127.0.0.1:8000"
echo "  Accès depuis le réseau local : http://[IP-de-cette-machine]:8000"
echo "  (voir README.md pour l'accès depuis l'extérieur)"
echo ""

python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
