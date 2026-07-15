#!/usr/bin/env python3
import json, sys, hashlib, subprocess, uuid
from datetime import datetime
from pathlib import Path

from kyc_pipeline import ensure_login, load_config, run_curl

class AgentTerminal:
    def __init__(self):
        self.config = load_config()
        self.wallet_id = None
        self.did = None
        
    def start_enrollment(self):
        print("\n" + "="*60)
        print("  AGENCE KYC - SYSTEME PRODIGY/ONECI")
        print("  Terminal Agent de Guichet")
        print("="*60)
        
        self.wallet_id, self.did = ensure_login(self.config)
        
        citoyen = self._saisir_donnees()
        citoyen['niu'] = self._generer_niu(citoyen)
        
        print("\nCAPTURE BIOMETRIQUE")
        input("Positionnez le citoyen, appuyez sur Entrée...")
        citoyen['photo_hash'] = hashlib.sha256(f"PHOTO_{datetime.now()}".encode()).hexdigest()
        citoyen['empreinte_hash'] = hashlib.sha256(f"EMPREINTE_{datetime.now()}".encode()).hexdigest()
        
        print("\nVERIFICATION AGENT")
        print(f"Nom: {citoyen['nom']} {citoyen['prenom']}")
        print(f"NIN: {citoyen['nin']}")
        if input("Valider ? (O/N): ").upper() != 'O':
            return
        
        credential_id = self._emettre_credential(citoyen)
        if not credential_id:
            return
        
        self._generer_carte(citoyen, credential_id)
        self._sauvegarder_registre(citoyen, credential_id)
        
        print(f"\n{'='*60}")
        print(f"ENROLMENT REUSSI - NIU: {citoyen['niu']}")
        print(f"{'='*60}")
    
    def _saisir_donnees(self):
        print("\nDONNEES CIVILES")
        return {
            "prenom": input("Prénom: ").strip(),
            "nom": input("Nom: ").strip(),
            "nin": input("NIN: ").strip(),
            "date_naissance": input("Date naissance (JJ/MM/AAAA): ").strip(),
            "lieu_naissance": input("Lieu naissance: ").strip(),
            "nationalite": input("Nationalité: ").strip(),
            "genre": input("Genre (M/F): ").strip().upper(),
            "pere": input("Père: ").strip(),
            "mere": input("Mère: ").strip(),
            "profession": input("Profession: ").strip(),
            "adresse": input("Adresse: ").strip(),
            "document": input("Document présenté: ").strip(),
            "num_document": input("N° document: ").strip()
        }
    
    def _generer_niu(self, citoyen):
        data = f"{citoyen['nin']}{citoyen['nom']}{citoyen['prenom']}{datetime.now().isoformat()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16].upper()
    
    def _emettre_credential(self, citoyen):
        print("\nEMISSION CREDENTIAL VIA WALT-ID...")
        
        data_file = Path("data") / f"temp_{citoyen['nin']}.json"
        credential_data = {
            "firstName": citoyen['prenom'],
            "lastName": citoyen['nom'],
            "birthDate": citoyen['date_naissance'].replace('/', '-'),
            "city": citoyen['lieu_naissance'],
            "cin": citoyen['nin'],
            "niu": citoyen['niu'],
            "nationality": citoyen['nationalite']
        }
        
        data_file.parent.mkdir(exist_ok=True)
        with open(data_file, 'w') as f:
            json.dump(credential_data, f, indent=2)
        
        result = subprocess.run(
            [sys.executable, "kyc_pipeline.py", "issue", "--data", str(data_file)],
            capture_output=True, text=True
        )
        print(result.stdout)
        
        last_cred = Path("state/last_credential.json")
        if last_cred.exists():
            with open(last_cred) as f:
                return json.load(f)['credential_id']
        return None
    
    def _generer_carte(self, citoyen, credential_id):
        print("\nGENERATION CARTE PHYSIQUE...")
        
        result = subprocess.run(['curl', '-s', '-b', 'state/cookies.txt',
            f"{self.config['wallet_base_url']}/wallet-api/wallet/{self.wallet_id}/credentials"],
            capture_output=True, text=True)
        creds = json.loads(result.stdout)
        
        credential_jwt = None
        for cred in creds:
            if cred['id'] == credential_id:
                credential_jwt = cred['document']
                break
        
        output_dir = Path("output/cartes")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        with open(output_dir / f"credential_{citoyen['niu']}.json", 'w') as f:
            json.dump({
                "credential_jwt": credential_jwt,
                "credential_id": credential_id,
                "citoyen": citoyen
            }, f, indent=2)
        
        print(f"Carte sauvegardée: output/cartes/credential_{citoyen['niu']}.json")
    
    def _sauvegarder_registre(self, citoyen, credential_id):
        registre_file = Path("state/registre_national.json")
        registre = []
        if registre_file.exists():
            with open(registre_file) as f:
                registre = json.load(f)
        
        registre.append({
            "niu": citoyen['niu'],
            "nin": citoyen['nin'],
            "nom": citoyen['nom'],
            "prenom": citoyen['prenom'],
            "credential_id": credential_id,
            "date_enrolement": datetime.now().isoformat(),
            "agent_id": self.wallet_id,
            "statut": "ACTIF"
        })
        
        with open(registre_file, 'w') as f:
            json.dump(registre, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    terminal = AgentTerminal()
    terminal.start_enrollment()
