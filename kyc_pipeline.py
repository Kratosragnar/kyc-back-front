#!/usr/bin/env python3
"""
Pipeline KYC automatisé pour waltid-identity.
"""
import argparse
import json
import subprocess
import sys
import uuid
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
STATE_DIR = BASE_DIR / "state"
STATE_DIR.mkdir(exist_ok=True)

CONFIG_PATH = BASE_DIR / "config.json"
COOKIES_PATH = STATE_DIR / "cookies.txt"
ISSUER_PATH = STATE_DIR / "issuer.json"
LAST_CREDENTIAL_PATH = STATE_DIR / "last_credential.json"


def load_config():
    if not CONFIG_PATH.exists():
        sys.exit(f"Fichier de config manquant : {CONFIG_PATH}")
    with open(CONFIG_PATH) as f:
        return json.load(f)


def run_curl(args, capture_json=True):
    result = subprocess.run(["curl", "-s"] + args, capture_output=True, text=True)
    text = result.stdout.strip()
    parsed = None
    if capture_json and text:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
    return text, parsed


def ensure_login(config):
    """Se connecte ou utilise wallet_id et did du config."""
    wallet_id = config.get("wallet_id")
    did = config.get("did")

    # Si wallet_id et did sont déjà dans la config, on les utilise directement
    if wallet_id and did:
        print(f"  ✓ Utilisation du wallet_id configuré : {wallet_id}")
        print(f"  ✓ Utilisation du did configuré : {did}")
        return wallet_id, did

    wallet_base = config["wallet_base_url"]

    # Tester si le wallet existe déjà
    if COOKIES_PATH.exists():
        text, parsed = run_curl(
            ["-b", str(COOKIES_PATH), f"{wallet_base}/wallet-api/wallet/accounts/wallets"]
        )
        if parsed is not None and isinstance(parsed, dict) and "wallets" in parsed:
            if parsed["wallets"]:
                wallet_id = parsed["wallets"][0]["id"]
                print(f"  wallet_id récupéré : {wallet_id}")
                return wallet_id, did

    # Si on arrive ici, on essaie de se connecter
    print("→ Connexion au wallet...")
    text, parsed = run_curl(
        [
            "-c", str(COOKIES_PATH),
            "-X", "POST", f"{wallet_base}/auth/login",
            "-H", "Content-Type: application/json",
            "-d", json.dumps({
                "email": config["wallet_email"],
                "password": config["wallet_password"],
            }),
        ]
    )

    if parsed is None or "token" not in parsed:
        print("\n========== LOGIN ERROR ==========")
        print("Réponse brute :", text)
        print("JSON :", parsed)
        print("=================================\n")
        print("⚠️  Le login a échoué. Utilisation du wallet_id du config si disponible.")
        if wallet_id and did:
            return wallet_id, did
        sys.exit(f"Échec du login : {text}")

    print("  ✓ Connecté avec succès.")

    # Récupérer wallet_id
    text, parsed = run_curl(
        ["-b", str(COOKIES_PATH), f"{wallet_base}/wallet-api/wallet/accounts/wallets"]
    )
    if parsed and parsed.get("wallets"):
        wallet_id = parsed["wallets"][0]["id"]
        print(f"  wallet_id détecté : {wallet_id}")
    else:
        wallet_id = config.get("wallet_id")
        if not wallet_id:
            sys.exit(f"Impossible de récupérer le wallet_id : {text}")

    # Récupérer DID
    if not did:
        text, parsed = run_curl(
            ["-b", str(COOKIES_PATH), f"{wallet_base}/wallet-api/wallet/{wallet_id}/dids"]
        )
        if parsed and isinstance(parsed, list) and len(parsed) > 0:
            did = parsed[0]["did"]
            print(f"  did détecté : {did}")

    if not did:
        did = config.get("did", "did:key:zDnaerBx8UayLkh8fMVbCiqpPv9v1bD9x9QP6kTnT9u3nWo9f")
        print(f"  Utilisation du did par défaut : {did}")

    return wallet_id, did


def ensure_issuer(config):
    """Onboarde un issuer une seule fois."""
    if ISSUER_PATH.exists():
        with open(ISSUER_PATH) as f:
            return json.load(f)

    print("→ Onboarding d'un nouvel issuer...")
    issuer_base = config["issuer_base_url"]
    text, parsed = run_curl(
        [
            "-X", "POST", f"{issuer_base}/onboard/issuer",
            "-H", "Content-Type: application/json",
            "-d", json.dumps({
                "key": {"backend": "jwk", "keyType": "secp256r1"},
                "did": {"method": "key"},
            }),
        ]
    )
    if not parsed or "issuerDid" not in parsed:
        sys.exit(f"Échec de l'onboarding issuer : {text}")

    with open(ISSUER_PATH, "w") as f:
        json.dump(parsed, f, indent=2)
    print(f"  issuer_did : {parsed['issuerDid']}")
    return parsed


def issue_credential(config, data_path):
    """Émet un credential à partir d'un fichier JSON."""
    wallet_id, did = ensure_login(config)
    issuer = ensure_issuer(config)

    with open(data_path) as f:
        credential_subject = json.load(f)

    credential_id = f"urn:uuid:{uuid.uuid4()}"

    issuance_request = {
        "issuerKey": issuer["issuerKey"],
        "issuerDid": issuer["issuerDid"],
        "credentialConfigurationId": config.get(
            "credential_configuration_id", "IdentityCredential_jwt_vc_json"
        ),
        "credentialData": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", "IdentityCredential"],
            "id": credential_id,
            "issuer": {"id": issuer["issuerDid"]},
            "credentialSubject": credential_subject,
        },
        "mapping": {
            "id": "<uuid>",
            "issuer": {"id": "<issuerDid>"},
        },
    }

    req_path = STATE_DIR / "issuance_request.json"
    with open(req_path, "w") as f:
        json.dump(issuance_request, f, indent=2)

    print("→ Émission du credential...")
    issuer_base = config["issuer_base_url"]
    text, _ = run_curl(
        [
            "-X", "POST", f"{issuer_base}/openid4vc/jwt/issue",
            "-H", "Content-Type: application/json",
            "-d", f"@{req_path}",
        ],
        capture_json=False,
    )
    raw_offer = text.strip()
    if not raw_offer.startswith("openid-credential-offer://"):
        sys.exit(f"Échec de l'émission (réponse inattendue) : {raw_offer}")

    print("→ Réception du credential dans le wallet...")
    wallet_base = config["wallet_base_url"]
    text, parsed = run_curl(
        [
            "-b", str(COOKIES_PATH),
            "-X", "POST",
            f"{wallet_base}/wallet-api/wallet/{wallet_id}/exchange/useOfferRequest?did={did}",
            "-H", "Content-Type: text/plain",
            "--data-raw", raw_offer,
        ]
    )
    if not parsed or not isinstance(parsed, list):
        sys.exit(f"Échec de la réception dans le wallet : {text}")

    real_credential_id = parsed[0]["id"]
    if real_credential_id != credential_id:
        print(f"  (id réel attribué par le serveur : {real_credential_id})")

    with open(LAST_CREDENTIAL_PATH, "w") as f:
        json.dump({"credential_id": real_credential_id, "wallet_id": wallet_id, "did": did}, f, indent=2)

    print(f"✓ Credential émis et stocké avec succès : {real_credential_id}")
    return real_credential_id


def main():
    parser = argparse.ArgumentParser(description="Pipeline KYC automatisé waltid-identity")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_issue = subparsers.add_parser("issue", help="Émettre un credential")
    p_issue.add_argument("--data", required=True, help="Fichier JSON des données du credential")

    args = parser.parse_args()
    config = load_config()

    if args.command == "issue":
        issue_credential(config, args.data)


if __name__ == "__main__":
    main()