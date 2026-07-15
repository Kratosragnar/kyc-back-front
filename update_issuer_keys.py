#!/usr/bin/env python3
import json
from pathlib import Path

def sync_issuer_keys():
    permanent_file = Path("state/issuer_permanent.json")
    keys_file = Path("state/issuer_public_keys.json")
    
    if not permanent_file.exists():
        print("Aucun issuer permanent trouvé. Lancez onboard_issuer_permanent.py d'abord.")
        return
    
    with open(permanent_file) as f:
        issuer = json.load(f)
    
    keys = {}
    if keys_file.exists():
        with open(keys_file) as f:
            keys = json.load(f)
    
    jwk_public = {
        "kty": issuer["issuerKey"]["jwk"]["kty"],
        "crv": issuer["issuerKey"]["jwk"]["crv"],
        "x": issuer["issuerKey"]["jwk"]["x"],
        "y": issuer["issuerKey"]["jwk"]["y"]
    }
    
    did = issuer["issuerDid"]
    
    if did in keys:
        print(f"Clé déjà présente pour {did[:50]}...")
    else:
        keys[did] = jwk_public
        print(f"✓ Clé ajoutée pour {did[:50]}...")
    
    with open(keys_file, "w") as f:
        json.dump(keys, f, indent=2)
    
    print(f"Total clés enregistrées: {len(keys)}")

if __name__ == "__main__":
    sync_issuer_keys()
