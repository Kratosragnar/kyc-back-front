#!/usr/bin/env python3
import json, sys
from pathlib import Path
from kyc_pipeline import load_config, run_curl

config = load_config()
issuer_file = Path("state/issuer_permanent.json")

if issuer_file.exists():
    print("Issuer permanent déjà existant.")
    with open(issuer_file) as f:
        issuer = json.load(f)
    print(f"  DID: {issuer['issuerDid']}")
    sys.exit(0)

print("Création de l'issuer PERMANENT...")
issuer_base = config["issuer_base_url"]

text, parsed = run_curl([
    "-X", "POST", f"{issuer_base}/onboard/issuer",
    "-H", "Content-Type: application/json",
    "-d", json.dumps({
        "key": {"backend": "jwk", "keyType": "secp256r1"},
        "did": {"method": "key"}
    })
])

if not parsed or "issuerDid" not in parsed:
    print(f"Échec: {text}")
    sys.exit(1)

with open(issuer_file, "w") as f:
    json.dump(parsed, f, indent=2)

keys_file = Path("state/issuer_public_keys.json")
keys = {}
if keys_file.exists():
    with open(keys_file) as f:
        keys = json.load(f)

jwk_public = {
    "kty": parsed["issuerKey"]["jwk"]["kty"],
    "crv": parsed["issuerKey"]["jwk"]["crv"],
    "x": parsed["issuerKey"]["jwk"]["x"],
    "y": parsed["issuerKey"]["jwk"]["y"]
}
keys[parsed["issuerDid"]] = jwk_public

with open(keys_file, "w") as f:
    json.dump(keys, f, indent=2)

print(f"✓ Issuer permanent créé")
print(f"  DID: {parsed['issuerDid']}")
print(f"  Clé sauvegardée dans state/issuer_public_keys.json")
