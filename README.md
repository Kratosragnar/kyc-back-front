# 🏛️ KYC OFFLINE — Identité Vérifiable Sans Connexion Internet

## 🚀 Démarrage rapide

git clone git@github.com:michael-hei/kyc-offline-prodigy.git
cd kyc-offline-prodigy
./setup.sh

## ✅ Ce que fait setup.sh

1. Démarre walt-id (issuer, wallet, verifier)
2. Crée l'autorité émettrice permanente
3. Émet un IdentityCredential pour Jean Dupont
4. Prépare le fichier pour vérification offline

## 🧪 Tester la vérification offline

sudo iptables -A OUTPUT -p tcp --dport 443 -j DROP
sudo iptables -A OUTPUT -p tcp --dport 80 -j DROP
python3 verifier_offline_final.py demo_citoyen.json
sudo iptables -D OUTPUT -p tcp --dport 443 -j DROP
sudo iptables -D OUTPUT -p tcp --dport 80 -j DROP

## 📋 Autres commandes

python3 agent_terminal.py
python3 verifier_offline_final.py demo_citoyen.json
python3 revoke_agent.py --niu NIU_DU_CITOYEN
python3 kyc_pipeline.py issue --data data/jean_dupont.json

## 🖥️ Interface web (pour les agents de guichet)

Une interface web remplace l'usage direct des scripts ci-dessus pour les agents qui ne sont
pas à l'aise avec le terminal. Elle couvre l'enrôlement, la vérification hors-ligne, la
révocation et la consultation du registre national, dans un navigateur.

Prérequis : `./setup.sh` doit avoir été exécuté au moins une fois (config.json + issuer permanent créés).

Démarrage :

./start_web.sh

Puis ouvrez http://localhost:5000 (le script tente aussi d'ouvrir le navigateur automatiquement).

Arrêt :

docker compose -f docker-compose.web.yml down

L'interface web réutilise directement `kyc_pipeline.py` et `verifier_offline_final.py` : aucune
logique métier n'est dupliquée, les scripts en ligne de commande restent utilisables en parallèle.
