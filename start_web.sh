#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

echo "========================================="
echo "  KYC OFFLINE - Interface web"
echo "========================================="

./start_docker.sh

if [ ! -f config.json ]; then
    cp config.example.json config.json
    echo "✓ config.json créé depuis config.example.json"
fi

mkdir -p state data output/cartes

echo "→ Construction et démarrage de l'interface web..."
docker compose -f docker-compose.web.yml up -d --build

echo "→ Attente de la disponibilité de l'interface..."
for i in $(seq 1 30); do
    if curl -sf http://localhost:5000 > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

echo ""
echo "✅ Interface prête : http://localhost:5000"
echo ""
echo "Pour l'arrêter :  docker compose -f docker-compose.web.yml down"
echo "Pour voir les logs : docker compose -f docker-compose.web.yml logs -f"
echo ""

(xdg-open http://localhost:5000 >/dev/null 2>&1 || open http://localhost:5000 >/dev/null 2>&1 || true) &
