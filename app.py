#!/usr/bin/env python3
"""
Interface web KYC OFFLINE.

Remplace l'usage direct des scripts en ligne de commande (agent_terminal.py,
verifier_offline_final.py, revoke_agent.py) par des formulaires web, pour les
agents non-techniques. Toute la logique métier reste dans les modules déjà
existants : ce fichier ne fait que les appeler.

Lancement : voir start_web.sh (Docker) ou `python3 app.py` en local.
"""
import hashlib
import json
from datetime import datetime
from pathlib import Path

import requests
from flask import Flask, flash, redirect, render_template, request, send_file, url_for

from kyc_pipeline import (
    BASE_DIR, COOKIES_PATH, STATE_DIR, CONFIG_PATH,
    load_config, ensure_login, issue_credential,
)
from verifier_offline_final import load_issuer_keys, verify_offline, check_revocation

DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "output" / "cartes"
REGISTRE_PATH = STATE_DIR / "registre_national.json"
REVOCATION_PATH = STATE_DIR / "revocation_list.json"
ISSUER_PERMANENT_PATH = STATE_DIR / "issuer_permanent.json"

DATA_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = "kyc-offline-local-interface"  # interface locale uniquement, pas exposée publiquement


# ---------------------------------------------------------------------------
# Aides communes
# ---------------------------------------------------------------------------

def config_ready():
    return CONFIG_PATH.exists()


def issuer_ready():
    return ISSUER_PERMANENT_PATH.exists() or (STATE_DIR / "issuer.json").exists()


def load_registre():
    if not REGISTRE_PATH.exists():
        return []
    with open(REGISTRE_PATH, encoding="utf-8") as f:
        return json.load(f)


def save_registre(registre):
    with open(REGISTRE_PATH, "w", encoding="utf-8") as f:
        json.dump(registre, f, indent=2, ensure_ascii=False)


def ping(url):
    try:
        r = requests.get(f"{url}/livez", timeout=1.5)
        return r.status_code < 400
    except requests.RequestException:
        return False


def services_status(config):
    return {
        "wallet": ping(config["wallet_base_url"]),
        "issuer": ping(config["issuer_base_url"]),
        "verifier": ping(config["verifier_base_url"]),
    }


def generer_niu(citoyen):
    data = f"{citoyen['nin']}{citoyen['nom']}{citoyen['prenom']}{datetime.now().isoformat()}"
    return hashlib.sha256(data.encode()).hexdigest()[:16].upper()


@app.before_request
def check_prerequisites():
    if request.endpoint in ("static",):
        return None
    if not config_ready():
        return render_template("setup_required.html", step="config")
    return None


# ---------------------------------------------------------------------------
# Tableau de bord
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    config = load_config()
    registre = load_registre()
    stats = {
        "total": len(registre),
        "actifs": sum(1 for c in registre if c.get("statut") == "ACTIF"),
        "revoques": sum(1 for c in registre if c.get("statut") == "REVOQUE"),
        "dernier": registre[-1] if registre else None,
    }
    return render_template(
        "index.html",
        stats=stats,
        services=services_status(config),
        issuer_ready=issuer_ready(),
    )


# ---------------------------------------------------------------------------
# Enrôlement
# ---------------------------------------------------------------------------

CHAMPS_ENROLEMENT = [
    "prenom", "nom", "nin", "date_naissance", "lieu_naissance",
    "nationalite", "genre", "pere", "mere", "profession",
    "adresse", "document", "num_document",
]


@app.route("/enrolement", methods=["GET", "POST"])
def enrolement():
    if request.method == "GET":
        return render_template("enrolement.html", valeurs={}, erreurs=[])

    valeurs = {champ: request.form.get(champ, "").strip() for champ in CHAMPS_ENROLEMENT}
    valeurs["genre"] = valeurs["genre"].upper()
    biometrie_confirmee = request.form.get("biometrie_confirmee") == "on"

    erreurs = [c for c in ("prenom", "nom", "nin", "date_naissance") if not valeurs[c]]
    if not biometrie_confirmee:
        erreurs.append("biometrie_confirmee")

    if erreurs:
        flash("Merci de compléter les champs obligatoires et de confirmer la capture biométrique.", "error")
        return render_template("enrolement.html", valeurs=valeurs, erreurs=erreurs)

    citoyen = dict(valeurs)
    citoyen["niu"] = generer_niu(citoyen)
    citoyen["photo_hash"] = hashlib.sha256(f"PHOTO_{datetime.now()}".encode()).hexdigest()
    citoyen["empreinte_hash"] = hashlib.sha256(f"EMPREINTE_{datetime.now()}".encode()).hexdigest()

    config = load_config()

    try:
        wallet_id, did = ensure_login(config)
    except SystemExit as e:
        flash(f"Connexion aux services walt-id impossible : {e}", "error")
        return render_template("enrolement.html", valeurs=valeurs, erreurs=[])

    data_file = DATA_DIR / f"temp_{citoyen['nin']}.json"
    with open(data_file, "w", encoding="utf-8") as f:
        json.dump({
            "firstName": citoyen["prenom"],
            "lastName": citoyen["nom"],
            "birthDate": citoyen["date_naissance"].replace("/", "-"),
            "city": citoyen["lieu_naissance"],
            "cin": citoyen["nin"],
            "niu": citoyen["niu"],
            "nationality": citoyen["nationalite"],
        }, f, indent=2)

    try:
        credential_id = issue_credential(config, data_file)
    except SystemExit as e:
        flash(f"Échec de l'émission du credential : {e}", "error")
        return render_template("enrolement.html", valeurs=valeurs, erreurs=[])

    # Récupère le JWT du credential fraîchement émis pour générer la "carte".
    # ensure_login() a déjà posé les cookies de session dans state/cookies.txt (format Netscape,
    # écrit par curl -c) ; on les réutilise ici directement.
    import http.cookiejar
    jar = http.cookiejar.MozillaCookieJar(str(COOKIES_PATH))
    try:
        jar.load(ignore_discard=True, ignore_expires=True)
    except Exception:
        jar = None
    resp = requests.get(
        f"{config['wallet_base_url']}/wallet-api/wallet/{wallet_id}/credentials",
        cookies=jar,
        timeout=10,
    )
    credential_jwt = None
    if resp.ok:
        for cred in resp.json():
            if cred.get("id") == credential_id:
                credential_jwt = cred.get("document")
                break

    carte_path = OUTPUT_DIR / f"credential_{citoyen['niu']}.json"
    with open(carte_path, "w", encoding="utf-8") as f:
        json.dump({
            "credential_jwt": credential_jwt,
            "credential_id": credential_id,
            "citoyen": citoyen,
        }, f, indent=2, ensure_ascii=False)

    registre = load_registre()
    registre.append({
        "niu": citoyen["niu"],
        "nin": citoyen["nin"],
        "nom": citoyen["nom"],
        "prenom": citoyen["prenom"],
        "credential_id": credential_id,
        "date_enrolement": datetime.now().isoformat(),
        "agent_id": wallet_id,
        "statut": "ACTIF",
    })
    save_registre(registre)

    return render_template(
        "enrolement_resultat.html",
        citoyen=citoyen,
        credential_id=credential_id,
        fichier=carte_path.name,
    )


@app.route("/telecharger/<niu>")
def telecharger_carte(niu):
    path = OUTPUT_DIR / f"credential_{niu}.json"
    if not path.exists():
        flash("Fichier de credential introuvable pour ce NIU.", "error")
        return redirect(url_for("registre_view"))
    return send_file(path, as_attachment=True, download_name=path.name)


# ---------------------------------------------------------------------------
# Vérification (hors-ligne)
# ---------------------------------------------------------------------------

@app.route("/verification", methods=["GET", "POST"])
def verification():
    if request.method == "GET":
        return render_template("verification.html", resultat=None)

    jwt_token = None
    uploaded = request.files.get("fichier")
    collé = request.form.get("jwt_colle", "").strip()

    if uploaded and uploaded.filename:
        try:
            data = json.loads(uploaded.read().decode("utf-8"))
            jwt_token = data.get("credential_jwt") or data.get("document")
        except (json.JSONDecodeError, UnicodeDecodeError):
            flash("Le fichier fourni n'est pas un JSON valide.", "error")
            return render_template("verification.html", resultat=None)
    elif collé:
        jwt_token = collé

    if not jwt_token:
        flash("Fournissez un fichier de credential ou collez le jeton JWT.", "error")
        return render_template("verification.html", resultat=None)

    issuer_keys = load_issuer_keys()
    if not issuer_keys:
        flash("Aucune clé d'émetteur locale trouvée. Synchronisez les clés avant de vérifier hors-ligne.", "error")
        return render_template("verification.html", resultat=None)

    try:
        resultat = verify_offline(jwt_token, issuer_keys)
    except Exception as e:
        resultat = {"valide": False, "erreur": f"Jeton illisible : {e}"}

    return render_template("verification.html", resultat=resultat)


# ---------------------------------------------------------------------------
# Révocation
# ---------------------------------------------------------------------------

@app.route("/revocation", methods=["GET", "POST"])
def revocation():
    cible = None
    recherche = request.values.get("recherche", "").strip()

    if recherche:
        registre = load_registre()
        for entry in registre:
            if entry.get("niu") == recherche or entry.get("nin") == recherche:
                cible = entry
                break
        if not cible:
            flash("Aucun citoyen trouvé avec ce NIU ou NIN.", "error")

    if request.method == "POST" and request.form.get("confirmer") == "on":
        niu = request.form.get("niu")
        motif = request.form.get("motif") or "DEMANDE_ADMINISTRATIVE"
        registre = load_registre()
        target = next((e for e in registre if e.get("niu") == niu), None)
        if not target:
            flash("Citoyen introuvable, révocation annulée.", "error")
            return redirect(url_for("revocation"))

        rev_list = {"revokedIndices": [], "lastUpdated": datetime.now().isoformat()}
        if REVOCATION_PATH.exists():
            with open(REVOCATION_PATH, encoding="utf-8") as f:
                rev_list = json.load(f)
        rev_list["revokedIndices"].append(target["credential_id"])
        rev_list["lastUpdated"] = datetime.now().isoformat()
        with open(REVOCATION_PATH, "w", encoding="utf-8") as f:
            json.dump(rev_list, f, indent=2)

        target["statut"] = "REVOQUE"
        target["date_revocation"] = datetime.now().isoformat()
        target["motif"] = motif
        save_registre(registre)

        flash(f"Identité {target['niu']} révoquée avec succès.", "success")
        return redirect(url_for("revocation"))

    return render_template("revocation.html", cible=cible, recherche=recherche)


# ---------------------------------------------------------------------------
# Registre national
# ---------------------------------------------------------------------------

@app.route("/registre")
def registre_view():
    q = request.args.get("q", "").strip().lower()
    registre = load_registre()
    if q:
        registre = [
            c for c in registre
            if q in c.get("nom", "").lower()
            or q in c.get("prenom", "").lower()
            or q in c.get("niu", "").lower()
            or q in c.get("nin", "").lower()
        ]
    registre = list(reversed(registre))
    return render_template("registre.html", registre=registre, q=q)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
