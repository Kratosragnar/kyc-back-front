#!/usr/bin/env python3
import json
import sys
import base64
from datetime import datetime
from pathlib import Path

try:
    from jose import jwt
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "python-jose[cryptography]", "cryptography"])
    from jose import jwt
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

def decoder_jwt_sans_verifier(token):
    parts = token.split('.')
    if len(parts) != 3:
        return None
    
    def decode_part(part):
        padding = 4 - len(part) % 4
        if padding != 4:
            part += '=' * padding
        return json.loads(base64.urlsafe_b64decode(part))
    
    header = decode_part(parts[0])
    payload = decode_part(parts[1])
    
    return header, payload

def extraire_cle_publique_did_key(did):
    if not did.startswith("did:key:"):
        return None
    
    key_part = did.replace("did:key:", "")
    padding = 4 - len(key_part) % 4
    if padding != 4:
        key_part += "=" * padding
    
    decoded = base64.urlsafe_b64decode(key_part)
    
    if decoded[:2] == bytes([0x80, 0x24]):
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), decoded[2:]
        )
    
    return None

def extraire_cle_publique_did_jwk(did):
    if not did.startswith("did:jwk:"):
        return None
    
    jwk_b64 = did.replace("did:jwk:", "")
    padding = 4 - len(jwk_b64) % 4
    if padding != 4:
        jwk_b64 += "=" * padding
    
    jwk_json = base64.urlsafe_b64decode(jwk_b64)
    jwk = json.loads(jwk_json)
    
    if jwk.get('kty') == 'EC' and jwk.get('crv') == 'P-256':
        x = base64.urlsafe_b64decode(jwk['x'] + '==')
        y = base64.urlsafe_b64decode(jwk['y'] + '==')
        
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            b'\x04' + x + y
        )
    
    return None

def verifier_jwt_local(jwt_token):
    header, payload = decoder_jwt_sans_verifier(jwt_token)
    
    if not header or not payload:
        return {"valide": False, "erreur": "JWT malformé"}
    
    print(f"Header  : {json.dumps(header, indent=2)}")
    print(f"Payload : {json.dumps(payload, indent=2)[:500]}...")
    
    issuer_did = payload.get('iss', '')
    print(f"\nÉmetteur : {issuer_did}")
    
    public_key = None
    if issuer_did.startswith("did:jwk:"):
        public_key = extraire_cle_publique_did_jwk(issuer_did)
        print("Type DID : did:jwk")
    elif issuer_did.startswith("did:key:"):
        public_key = extraire_cle_publique_did_key(issuer_did)
        print("Type DID : did:key")
    
    if not public_key:
        return {"valide": False, "erreur": f"Impossible d'extraire la clé publique du DID: {issuer_did}"}
    
    print("✓ Clé publique extraite localement du DID")
    
    try:
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        verified = jwt.decode(
            jwt_token,
            public_pem.decode(),
            algorithms=['ES256'],
            options={"verify_aud": False}
        )
        print("✓ Signature ES256 VÉRIFIÉE LOCALEMENT")
    except Exception as e:
        return {"valide": False, "erreur": f"Signature invalide: {e}"}
    
    exp = verified.get('exp', 0)
    if exp:
        exp_date = datetime.fromtimestamp(exp)
        if datetime.utcnow() > exp_date:
            return {"valide": False, "erreur": f"Expiré le {exp_date}"}
        print(f"✓ Non expiré (valable jusqu'au {exp_date})")
    
    vc = verified.get('vc', {})
    sujet = vc.get('credentialSubject', {})
    
    print(f"\n{'='*50}")
    print("IDENTITÉ VÉRIFIÉE HORS-LIGNE ✓")
    print(f"{'='*50}")
    print(f"Nom      : {sujet.get('lastName', 'N/A')} {sujet.get('firstName', 'N/A')}")
    print(f"Naissance: {sujet.get('birthDate', 'N/A')}")
    print(f"Ville    : {sujet.get('city', 'N/A')}")
    print(f"NIN      : {sujet.get('cin', 'N/A')}")
    print(f"{'='*50}\n")
    
    return {
        "valide": True,
        "sujet": sujet,
        "emetteur": issuer_did,
        "verifie_le": datetime.utcnow().isoformat()
    }

def verifier_fichier(fichier):
    with open(fichier) as f:
        data = json.load(f)
    
    jwt_token = data.get('credential_jwt') or data.get('document') or data.get('credential')
    
    if not jwt_token:
        print("Format de fichier non reconnu. Attend : credential_jwt, document, ou credential")
        return
    
    return verifier_jwt_local(jwt_token)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 verifier_local.py <fichier_credential.json>")
        print("   ou: python3 verifier_local.py --jwt <token>")
        sys.exit(1)
    
    if sys.argv[1] == "--jwt":
        resultat = verifier_jwt_local(sys.argv[2])
    else:
        resultat = verifier_fichier(sys.argv[1])
    
    if resultat and resultat.get('valide'):
        print("✅ IDENTITÉ AUTHENTIFIÉE - CONFIANCE ÉTABLIE")
        print("   Aucune connexion internet n'a été utilisée")
    else:
        print(f"❌ ÉCHEC: {resultat.get('erreur', 'Erreur inconnue')}")
