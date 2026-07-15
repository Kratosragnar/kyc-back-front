Action	Commande
Démarrer Walt-ID :	cd ~/kyc-waltid/waltid-identity/docker-compose && docker-compose up -d
Démarrer KYC :	cd ~/kyc-offline-prodigy && docker-compose -f docker-compose.web.yml up -d
Interface :	http://localhost:5000
Arrêter KYC :	cd ~/kyc-offline-prodigy && docker-compose -f docker-compose.web.yml down
Arrêter Walt-ID :	cd ~/kyc-waltid/waltid-identity/docker-compose && docker-compose down
