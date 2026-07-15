#!/usr/bin/env python3
import json
import sys
import base64
import subprocess
from datetime import datetime

def decoder_jwt(token):
    parts = token.split('.')
    if len(parts) != 3:
        return None, None, None
    
    def decode_part(part):
        part = part.replace('-', '+').replace('_', '/')
        padding = 4 - len(part) % 4
        if padding != 4:
            part += '=' * padding
        return json.loads(base64.b64decode(part))
    
    return decode_part(parts[0]), decode_part(parts[1]), parts[2]

def base64url_decode(data):
    data = data.replace('-', '+').replace('_', '/')
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.b64decode(data)

def multibase_decode(mb_string):
    if mb_string[0] == 'z':
        return base64url_decode(mb_string[1:])
    elif mb_string[0] == 'f':
        return bytes.fromhex(mb_string[1:])
    elif mb_string[0] == '0':
        return mb_string[1:].encode()
    else:
        return base64url_decode(mb_string)

def extraire_cle_publique_did_key(did):
    if not did.startswith("did:key:"):
        return None
    
    multibase_key = did.replace("did:key:", "")
    key_bytes = multibase_decode(multibase_key)
    
    print(f"  Longueur totale : {len(key_bytes)} octets")
    print(f"  Premiers octets : {key_bytes[:4].hex()}")
    
    if len(key_bytes) >= 4 and key_bytes[:2] == bytes([0x80, 0x24]):
        pubkey_raw = key_bytes[2:]
        print(f"  Clé P-256 trouvée : {len(pubkey_raw)} octets")
    elif len(key_bytes) >= 4 and key_bytes[:2] == bytes([0x12, 0x01]):
        pubkey_raw = key_bytes[2:]
        print(f"  Clé Ed25519 trouvée : {len(pubkey_raw)} octets")
    else:
        print(f"  Type de clé inconnu. Recherche multicodec...")
        for i in range(min(len(key_bytes), 10)):
            if i + 2 <= len(key_bytes) and key_bytes[i:i+2] == bytes([0x80, 0x24]):
                pubkey_raw = key_bytes[i+2:]
                print(f"  P-256 trouvé à l'offset {i}")
                break
        else:
            return None
    
    der_prefix = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200')
    der_pubkey = der_prefix + pubkey_raw
    
    result = subprocess.run(
        ['openssl', 'pkey', '-pubin', '-inform', 'DER', '-outform', 'PEM'],
        input=der_pubkey,
        capture_output=True
    )
    
    if result.returncode == 0:
        return result.stdout.decode()
    
    print(f"  Erreur openssl : {result.stderr.decode()}")
    return None

def verifier_signature_openssl(jwt_token, pem_cle_publique):
    parts = jwt_token.split('.')
    message = f"{parts[0]}.{parts[1]}".encode()
    signature = base64url_decode(parts[2])
    
    with open('/tmp/jwt_message.bin', 'wb') as f:
        f.write(message)
    with open('/tmp/jwt_signature.bin', 'wb') as f:
        f.write(signature)
    with open('/tmp/jwt_public.pem', 'w') as f:
        f.write(pem_cle_publique)
    
    result = subprocess.run([
        'openssl', 'dgst', '-sha256', '-verify', '/tmp/jwt_public.pem',
        '-signature', '/tmp/jwt_signature.bin',
        '/tmp/jwt_message.bin'
    ], capture_output=True, text=True)
    
    return result.returncode == 0 and 'Verified OK' in result.stdout

def verifier_jwt_local(jwt_token):
    header, payload, signature_b64 = decoder_jwt(jwt_token)
    
    if not header or not payload:
        return {"valide": False, "erreur": "JWT malformé"}
    
    print(f"Header  : {json.dumps(header, indent=2)}")
    
    issuer_did = payload.get('iss', '')
    subject_did = payload.get('sub', '')
    
    print(f"Émetteur (iss) : {issuer_did}")
    print(f"Sujet (sub)    : {subject_did[:80]}...")
    
    public_key_pem = extraire_cle_publique_did_key(issuer_did)
    
    if not public_key_pem:
        return {"valide": False, "erreur": f"Impossible d'extraire la clé publique du DID"}
    
    print(f"✓ Clé publique extraite localement du DID:KEY")
    print(public_key_pem)
    
    signature_valide = verifier_signature_openssl(jwt_token, public_key_pem)
    
    if not signature_valide:
        return {"valide": False, "erreur": "Signature cryptographique INVALIDE"}
    
    print("✓ Signature ES256 VÉRIFIÉE LOCALEMENT (openssl)")
    
    exp = payload.get('exp', 0)
    if exp:
        exp_date = datetime.fromtimestamp(exp)
        if datetime.utcnow() > exp_date:
            return {"valide": False, "erreur": f"Credential expiré le {exp_date}"}
        print(f"✓ Non expiré (valable jusqu'au {exp_date})")
    
    vc = payload.get('vc', {})
    sujet = vc.get('credentialSubject', {})
    
    print(f"\n{'='*50}")
    print("IDENTITÉ VÉRIFIÉE HORS-LIGNE ✓")
    print(f"{'='*50}")
    print(f"Nom       : {sujet.get('lastName', 'N/A')} {sujet.get('firstName', 'N/A')}")
    print(f"Naissance : {sujet.get('birthDate', 'N/A')}")
    print(f"Ville     : {sujet.get('city', 'N/A')}")
    print(f"NIN/CIN   : {sujet.get('cin', 'N/A')}")
    print(f"Credential: {vc.get('id', 'N/A')}")
    print(f"{'='*50}\n")
    
    return {
        "valide": True,
        "sujet": sujet,
        "emetteur": issuer_did,
        "sujet_did": subject_did,
        "verifie_le": datetime.utcnow().isoformat(),
        "methode": "Offline DID:KEY + openssl ES256"
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 verifier_offline_pur.py <fichier_credential.json>")
        print("   ou: python3 verifier_offline_pur.py --jwt <token>")
        sys.exit(1)
    
    if sys.argv[1] == "--jwt":
        resultat = verifier_jwt_local(sys.argv[2])
    else:
        with open(sys.argv[1]) as f:
            data = json.load(f)
        jwt_token = data.get('credential_jwt') or data.get('document') or data.get('credential')
        if not jwt_token:
            print("Format de fichier non reconnu")
            sys.exit(1)
        resultat = verifier_jwt_local(jwt_token)
    
    if resultat and resultat.get('valide'):
        print("✅ IDENTITÉ AUTHENTIFIÉE - CONFIANCE ÉTABLIE")
        print("   Aucune connexion internet n'a été utilisée")
        print("   Vérification 100% locale (DID:KEY + openssl)")
    else:
        print(f"❌ ÉCHEC: {resultat.get('erreur', 'Erreur inconnue')}")
