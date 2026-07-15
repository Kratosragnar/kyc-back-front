#!/bin/bash
# ==========================================================
# demo_rehearsal.sh - Répétition complète pour présentation
# Pipeline KYC offline : Docker -> émission -> export -> test hors-ligne
# ==========================================================
set -uo pipefail

DATA_FILE="${1:-data/rakoto_jean.json}"
OUTPUT_CRED="demo_citoyen.json"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

step() { echo -e "\n${YELLOW}▶ $1${NC}"; }
ok()   { echo -e "${GREEN}✓ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; }

# Nettoyage garanti des règles iptables, même en cas d'erreur/Ctrl+C
cleanup_iptables() {
    sudo iptables -D OUTPUT -p tcp --dport 443 -j DROP 2>/dev/null
    sudo iptables -D OUTPUT -p tcp --dport 80 -j DROP 2>/dev/null
}
trap cleanup_iptables EXIT

echo "=========================================="
echo "  RÉPÉTITION - Démo KYC Offline"
echo "=========================================="

# --- 1. Vérifier que le fichier de données existe ---
step "1/6 Vérification du fichier de données ($DATA_FILE)"
if [ ! -f "$DATA_FILE" ]; then
    fail "Fichier introuvable : $DATA_FILE"
    exit 1
fi
cat "$DATA_FILE"
ok "Fichier de données présent"

# --- 2. Docker ---
step "2/6 Vérification de Docker"
if docker info >/dev/null 2>&1; then
    ok "Docker daemon actif"
else
    echo "→ Démarrage de Docker..."
    sudo -v
    sudo dockerd > /tmp/docker.log 2>&1 &
    disown
    for i in $(seq 1 30); do
        if docker info >/dev/null 2>&1; then
            ok "Docker daemon prêt (après ${i}s)"
            break
        fi
        sleep 1
    done
fi

if ! docker info >/dev/null 2>&1; then
    fail "Docker n'a pas démarré. Voir /tmp/docker.log"
    exit 1
fi

RUNNING=$(docker ps --filter "status=running" -q | wc -l)
ok "$RUNNING conteneurs actifs"

# --- 3. Émission du credential ---
step "3/6 Émission du credential pour $DATA_FILE"
if ! python3 kyc_pipeline.py issue --data "$DATA_FILE"; then
    fail "Échec de l'émission. Vérifie la connexion au wallet-api (port 7001)."
    exit 1
fi
ok "Credential émis"

# --- 4. Export du credential pour test offline ---
step "4/6 Export vers $OUTPUT_CRED"
python3 << 'PYEOF'
import json, subprocess, sys

with open('state/last_credential.json') as f:
    cred = json.load(f)

result = subprocess.run(['curl', '-s', '-b', 'state/cookies.txt',
    'http://localhost:7001/wallet-api/wallet/accounts/wallets'],
    capture_output=True, text=True)
try:
    wallet_id = json.loads(result.stdout)['wallets'][0]['id']
except Exception:
    print("✗ Session expirée (cookies invalides). Relance kyc_pipeline.py issue.")
    sys.exit(1)

result = subprocess.run(['curl', '-s', '-b', 'state/cookies.txt',
    f'http://localhost:7001/wallet-api/wallet/{wallet_id}/credentials'],
    capture_output=True, text=True)

found = False
for c in json.loads(result.stdout):
    if c['id'] == cred['credential_id']:
        with open('demo_citoyen.json', 'w') as f:
            json.dump({'credential_jwt': c['document']}, f, indent=2)
        print("✓ demo_citoyen.json mis à jour")
        found = True
        break

if not found:
    print("✗ Credential non trouvé dans le wallet")
    sys.exit(1)
PYEOF

if [ $? -ne 0 ]; then
    fail "Export échoué"
    exit 1
fi

# --- 5. Vérification en ligne (optionnel, pour valider le pipeline complet) ---
step "5/6 Vérification en ligne (sanity check)"
python3 kyc_pipeline.py verify --data "$DATA_FILE" 2>/dev/null || echo "  (vérification en ligne non concluante, on continue avec le test offline)"

# --- 6. Test de vérification hors-ligne ---
step "6/6 Test hors-ligne (coupure réseau simulée)"
sudo -v
sudo iptables -A OUTPUT -p tcp --dport 443 -j DROP
sudo iptables -A OUTPUT -p tcp --dport 80 -j DROP

echo ""
python3 verifier_offline_final.py "$OUTPUT_CRED"
RESULT=$?

# cleanup_iptables s'exécute automatiquement via trap EXIT

echo ""
echo "=========================================="
if [ $RESULT -eq 0 ]; then
    ok "RÉPÉTITION RÉUSSIE - Prêt pour la présentation"
else
    fail "Échec du test hors-ligne - à corriger avant la présentation"
fi
echo "=========================================="

exit $RESULT
