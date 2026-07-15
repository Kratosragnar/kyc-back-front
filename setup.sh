#!/bin/bash
set -e

echo "========================================="
echo "  KYC OFFLINE - Installation"
echo "========================================="

if [ ! -f config.json ]; then
    cp config.example.json config.json
    echo "✓ config.json créé depuis config.example.json"
    echo "  Modifiez-le si nécessaire"
fi

echo "→ Démarrage de walt-id..."
cd ~/kyc-waltid/waltid-identity/docker-compose
docker-compose up -d
cd ~/kyc-offline-prodigy

echo "→ Attente des services..."
until curl -sf http://localhost:7001/livez > /dev/null 2>&1; do sleep 2; done
echo "  ✓ wallet-api prêt"
until curl -sf http://localhost:7002/livez > /dev/null 2>&1; do sleep 2; done
echo "  ✓ issuer-api prêt"
until curl -sf http://localhost:7003/livez > /dev/null 2>&1; do sleep 2; done
echo "  ✓ verifier-api prêt"

rm -f state/cookies.txt state/last_credential.json demo_citoyen.json state/revocation_list.json

echo "→ Création de l'issuer permanent..."
python3 onboard_issuer_permanent.py

echo "→ Émission d'une identité..."
python3 kyc_pipeline.py issue --data data/jean_dupont.json

echo "→ Récupération du credential..."
python3 << 'PYEOF'
import json, subprocess
with open('state/last_credential.json') as f:
    cred = json.load(f)
result = subprocess.run(['curl', '-s', '-b', 'state/cookies.txt',
    'http://localhost:7001/wallet-api/wallet/accounts/wallets'],
    capture_output=True, text=True)
wallet_id = json.loads(result.stdout)['wallets'][0]['id']
result = subprocess.run(['curl', '-s', '-b', 'state/cookies.txt',
    f'http://localhost:7001/wallet-api/wallet/{wallet_id}/credentials'],
    capture_output=True, text=True)
for c in json.loads(result.stdout):
    if c['id'] == cred['credential_id']:
        with open('demo_citoyen.json', 'w') as f:
            json.dump({'credential_jwt': c['document']}, f, indent=2)
        break
PYEOF

echo ""
echo "========================================="
echo "  ✅ Installation terminée !"
echo "========================================="
echo ""
echo "Pour tester la vérification offline :"
echo ""
echo "  sudo iptables -A OUTPUT -p tcp --dport 443 -j DROP"
echo "  sudo iptables -A OUTPUT -p tcp --dport 80 -j DROP"
echo "  python3 verifier_offline_final.py demo_citoyen.json"
echo "  sudo iptables -D OUTPUT -p tcp --dport 443 -j DROP"
echo "  sudo iptables -D OUTPUT -p tcp --dport 80 -j DROP"
