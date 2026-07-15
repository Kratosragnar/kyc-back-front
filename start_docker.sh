#!/bin/bash
set -euo pipefail

if docker info >/dev/null 2>&1; then
  echo "✓ Docker daemon déjà actif."
  exit 0
fi

echo "→ Démarrage de Docker daemon..."
sudo -v  # force la saisie du mot de passe MAINTENANT, une seule fois
sudo dockerd > /tmp/docker.log 2>&1 &
disown

echo "→ Attente du démarrage..."
for i in $(seq 1 30); do
  if docker info >/dev/null 2>&1; then
    echo "✓ Docker daemon prêt (après ${i}s)."
    exit 0
  fi
  sleep 1
done

echo "✗ Docker n'a pas démarré après 30s. Voir /tmp/docker.log"
exit 1
