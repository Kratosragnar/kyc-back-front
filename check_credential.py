import os
if not os.path.exists('state/last_credential.json'):
    print("Aucun credential existant, lance d'abord `issue`.")
    exit(1)
