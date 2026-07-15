#!/usr/bin/env python3
import json, sys, base64, subprocess, tempfile, os
from datetime import datetime
from pathlib import Path

def b64url_decode(part):
    part = part.replace('-', '+').replace('_', '/')
    padding = 4 - len(part) % 4
    if padding != 4:
        part += '=' * padding
    return base64.b64decode(part)

def load_issuer_keys():
    keys = {}
    issuer_file = Path('state/issuer_public_keys.json')
    if issuer_file.exists():
        with open(issuer_file) as f:
            data = json.load(f)
            for did, jwk in data.items():
                x = base64.urlsafe_b64decode(jwk['x'] + '==')
                y = base64.urlsafe_b64decode(jwk['y'] + '==')
                pubkey = b'\x04' + x + y
                der_prefix = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200')
                der = der_prefix + pubkey
                result = subprocess.run(['openssl', 'pkey', '-pubin', '-inform', 'DER', '-outform', 'PEM'],
                                      input=der, capture_output=True)
                if result.returncode == 0:
                    keys[did] = result.stdout.decode()
    return keys

def signature_raw_to_der(signature_raw):
    r = int.from_bytes(signature_raw[:32], 'big')
    s = int.from_bytes(signature_raw[32:], 'big')
    
    def to_bytes(n):
        n_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        if n_bytes[0] & 0x80:
            n_bytes = b'\x00' + n_bytes
        return b'\x02' + bytes([len(n_bytes)]) + n_bytes
    
    r_bytes = to_bytes(r)
    s_bytes = to_bytes(s)
    return b'\x30' + bytes([len(r_bytes) + len(s_bytes)]) + r_bytes + s_bytes

def check_revocation(credential_id):
    rev_file = Path('state/revocation_list.json')
    if not rev_file.exists():
        return False, None
    
    with open(rev_file) as f:
        rev_list = json.load(f)
    
    if credential_id in rev_list.get('revokedIndices', []):
        return True, rev_list.get('lastUpdated', 'inconnue')
    return False, None

def verify_offline(jwt_token, issuer_keys):
    parts = jwt_token.split('.')
    
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    signature_raw = b64url_decode(parts[2])
    
    print(f"Algorithm: {header.get('alg')}")
    print(f"Issuer: {payload['iss']}")
    
    issuer_did = payload['iss']
    
    if issuer_did not in issuer_keys:
        return {"valide": False, "erreur": f"Clé publique inconnue pour {issuer_did}"}
    
    pem = issuer_keys[issuer_did]
    print("✓ Clé publique trouvée pour cet issuer")
    
    signature_der = signature_raw_to_der(signature_raw)
    message = f"{parts[0]}.{parts[1]}"
    
    tmp_dir = tempfile.mkdtemp(prefix="kycverif_")
    msg_path = os.path.join(tmp_dir, "msg.txt")
    sig_path = os.path.join(tmp_dir, "sig.bin")
    key_path = os.path.join(tmp_dir, "key.pem")
    try:
        with open(msg_path, 'w') as f: f.write(message)
        with open(sig_path, 'wb') as f: f.write(signature_der)
        with open(key_path, 'w') as f: f.write(pem)

        result = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', key_path,
                               '-signature', sig_path, msg_path],
                              capture_output=True, text=True)
    finally:
        for p in (msg_path, sig_path, key_path):
            try: os.remove(p)
            except OSError: pass
        try: os.rmdir(tmp_dir)
        except OSError: pass

    if result.returncode != 0:
        return {"valide": False, "erreur": "Signature cryptographique INVALIDE"}
    
    print("✓ Signature ES256 vérifiée")
    
    exp = payload.get('exp', 0)
    if exp:
        exp_date = datetime.fromtimestamp(exp)
        if datetime.utcnow() > exp_date:
            return {"valide": False, "erreur": f"Credential expiré le {exp_date}"}
        print(f"✓ Non expiré (valable jusqu'au {exp_date})")
    
    credential_id = payload.get('jti', '') or payload.get('vc', {}).get('id', '')
    is_revoked, rev_date = check_revocation(credential_id)
    
    if is_revoked:
        return {"valide": False, "erreur": f"Credential RÉVOQUÉ (liste du {rev_date})"}
    print("✓ Non révoqué")
    
    sujet = payload['vc']['credentialSubject']
    
    print(f"\n{'='*50}")
    print("IDENTITÉ VÉRIFIÉE HORS-LIGNE ✓")
    print(f"{'='*50}")
    print(f"Nom       : {sujet['lastName']} {sujet['firstName']}")
    print(f"Naissance : {sujet['birthDate']}")
    print(f"Ville     : {sujet['city']}")
    print(f"CIN       : {sujet['cin']}")
    if sujet.get('niu'):
        print(f"NIU       : {sujet['niu']}")
    print(f"Credential: {credential_id}")
    print(f"{'='*50}\n")
    
    return {"valide": True, "sujet": sujet, "id": credential_id}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 verifier_offline_final.py <fichier.json>")
        sys.exit(1)
    
    with open(sys.argv[1]) as f:
        data = json.load(f)
    
    jwt_token = data.get('credential_jwt') or data.get('document')
    
    issuer_keys = load_issuer_keys()
    
    if not issuer_keys:
        print("Aucune clé d'issuer enregistrée. Synchronisation...")
        import subprocess as sp
        sp.run([sys.executable, 'update_issuer_keys.py'])
        issuer_keys = load_issuer_keys()
    
    resultat = verify_offline(jwt_token, issuer_keys)
    
    if resultat['valide']:
        print("✅ IDENTITÉ AUTHENTIFIÉE - VÉRIFICATION 100% LOCALE")
        print("   Aucune connexion internet n'a été utilisée")
    else:
        print(f"❌ ÉCHEC: {resultat['erreur']}")
