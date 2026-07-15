#!/usr/bin/env python3
import json, sys, subprocess
from datetime import datetime
from pathlib import Path

from kyc_pipeline import ensure_login, load_config

def revoke_credential(niu=None, nin=None, reason="DEMANDE_ADMINISTRATIVE"):
    config = load_config()
    wallet_id, did = ensure_login(config)
    
    registre_file = Path("state/registre_national.json")
    if not registre_file.exists():
        print("Registre national introuvable")
        return
    
    with open(registre_file) as f:
        registre = json.load(f)
    
    target = None
    for entry in registre:
        if niu and entry.get("niu") == niu:
            target = entry
            break
        if nin and entry.get("nin") == nin:
            target = entry
            break
    
    if not target:
        print(f"Aucun citoyen trouvé")
        return
    
    print(f"\nREVOCATION D'IDENTITE")
    print(f"NIU: {target['niu']}")
    print(f"Nom: {target['nom']} {target['prenom']}")
    print(f"Motif: {reason}")
    
    if input("Confirmer ? (O/N): ").upper() != 'O':
        return
    
    rev_list_path = Path("state/revocation_list.json")
    rev_list = {"revokedIndices": [], "lastUpdated": datetime.now().isoformat()}
    if rev_list_path.exists():
        with open(rev_list_path) as f:
            rev_list = json.load(f)
    
    rev_list["revokedIndices"].append(target['credential_id'])
    rev_list["lastUpdated"] = datetime.now().isoformat()
    
    with open(rev_list_path, 'w') as f:
        json.dump(rev_list, f, indent=2)
    
    target['statut'] = 'REVOQUE'
    target['date_revocation'] = datetime.now().isoformat()
    target['motif'] = reason
    
    with open(registre_file, 'w') as f:
        json.dump(registre, f, indent=2, ensure_ascii=False)
    
    print(f"\nREVOCATION EFFECTUEE")
    print(f"Credential: {target['credential_id']}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 revoke_agent.py --niu <NIU> [--reason DECES]")
        sys.exit(1)
    
    niu = None
    reason = "DEMANDE_ADMINISTRATIVE"
    
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == "--niu":
            niu = sys.argv[i+1]
            i += 2
        elif sys.argv[i] == "--reason":
            reason = sys.argv[i+1]
            i += 2
        else:
            i += 1
    
    revoke_credential(niu=niu, reason=reason)
