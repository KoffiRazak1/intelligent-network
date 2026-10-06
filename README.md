# Intelligent Network Packet Analyzer

Tableau de bord FastAPI pour observer et analyser des résumés de trafic réseau. Le backend local s’appuie sur Scapy/Npcap pour lire une interface réseau, regroupe les paquets en communications, détecte quelques comportements à examiner et conserve un historique SQLite.

## État actuel et limites à connaître

- **Exécution locale Windows :** la capture Scapy utilise les interfaces que Windows/Npcap expose à l’application. Exécuter le serveur avec les permissions requises et installer Npcap si Scapy ne voit pas l’interface.
- **Railway :** le tableau de bord et son API peuvent être hébergés. Une instance Railway ne peut pas lire la carte Wi-Fi de ton PC : la capture est donc désactivée dans l’image cloud (`CAPTURE_ENABLED=false`). L’interface réseau et les nouvelles captures locales ne fonctionneront pas dans Railway tant qu’un agent installé sur le PC n’aura pas été développé pour transmettre ses résumés au service.
- **Accès public :** l’application exige HTTP Basic Auth lorsque `APP_ENV=production`. Configure un nom d’utilisateur et un mot de passe forts dans les variables Railway. `/api/health` est la seule route publique, pour le contrôle de santé Railway.
- **Persistance :** SQLite est configuré via `DATABASE_PATH`. Dans Railway, attache un volume au chemin `/app/data` et configure `DATABASE_PATH=/app/data/network_analyzer.db`. Sans volume, l’historique ne survivra pas aux redéploiements.
- **Échelle :** l’historique est SQLite sur un seul disque local persistant. Garde une seule instance/réplique Railway pour le moment ; plusieurs répliques ne partageraient pas la même base SQLite.

Le déploiement Railway prévu ici est un tableau de bord privé et persistant, pas une sonde de capture du réseau de ton ordinateur. Ne présente pas les données vides du service cloud comme une capture réelle.

## Fonctions en place

- Tableau de bord HTML/Jinja avec CSS et JavaScript servis par FastAPI.
- Découverte des interfaces et démarrage/arrêt de capture via Scapy en mode local.
- Résumés récents de paquets, regroupement en communications et compteurs de trafic.
- Détection d’activités configurées dans `AlertDetector` ; une alerte est un indicateur à vérifier, pas une preuve d’attaque.
- Historique SQLite des sessions et des résumés de paquets, export CSV des paquets d’une session.
- API JSON sous `/api` et route de santé `/api/health`.
- Protection HTTP Basic activée en production.

Plusieurs fichiers sont encore des espaces réservés vides : les routes `routes_connections.py`, `routes_enrichment.py`, `routes_history.py`, `routes_packets.py` et `routes_alerts.py`, plusieurs modules d’analyse/enrichissement/modèles, les quatre pages secondaires (`connections.html`, `history.html`, `packets.html`, `alerts.html`) et les fichiers de `docs/`. Les routes non vides ne sont pas enregistrées dans `main.py`. Les fonctions actuellement livrées sont celles décrites ci-dessus ; le reste est à terminer avant de considérer toutes les rubriques du projet comme finies.

## Structure du dépôt

    intelligent-network-packet-analyzer/
    ├── backend/
    │   ├── app/
    │   │   ├── analysis/             # Analyse paquets, communications, alertes, risques
    │   │   ├── api/                  # Routes FastAPI ; routes_capture est enregistrée
    │   │   ├── capture/              # Découverte interfaces et gestionnaire Scapy
    │   │   ├── database/             # Dépôts et connecteur Supabase (composants isolés)
    │   │   ├── enrichment/           # Enrichissement threat intelligence
    │   │   ├── explanation/          # Explications de protocoles et détections
    │   │   ├── models/               # Modèles de données
    │   │   ├── services/             # Services d’analyse
    │   │   ├── storage/              # Persistance SQLite et historique
    │   │   ├── utils/                # Configuration auxiliaire, validation, logs
    │   │   ├── config.py             # Variables d’environnement
    │   │   └── main.py               # Application FastAPI, dashboard, santé, auth
    │   ├── tests/                    # Tests unitaires backend
    │   └── run.py                    # Démarrage local avec les paramètres .env
    ├── frontend/
    │   ├── static/
    │   │   ├── css/style.css         # Feuille de style
    │   │   ├── images/               # Ressources visuelles
    │   │   └── js/                   # Appels API, filtres, graphiques et UI
    │   └── templates/                # Pages Jinja (dashboard.html est active)
    ├── docs/                         # Fichiers présents mais actuellement vides
    ├── data/                         # Base SQLite locale/runtime (non versionnée)
    ├── Dockerfile                    # Image conteneur Railway
    ├── railway.json                  # Build Dockerfile, santé et redémarrage
    ├── .dockerignore                 # Exclut secrets, base, environnements et caches
    ├── .env.example                  # Modèle de configuration locale
    ├── requirements.txt              # Dépendances runtime
    ├── requirements-dev.txt          # Dépendances de test
    └── README.md


### Parcours d’une capture locale

1. `main.py` sert `dashboard.html` et enregistre `routes_capture.py`.
2. Le navigateur appelle les routes `/api/interfaces`, `/api/capture/*`, `/api/packets`, `/api/flows`, `/api/alerts` et `/api/history`.
3. `CaptureManager` démarre Scapy, appelle `parse_packet`, met à jour `FlowTracker` et `AlertDetector`, puis conserve les résumés récents.
4. `HistoryStore` enregistre les sessions et les résumés dans SQLite. L’export `/api/history/{session_id}/packets.csv` lit la session archivée.

Les résumés contiennent des métadonnées (adresses, ports, protocoles, taille, indicateurs), pas le contenu applicatif complet des paquets.

## Routes API actuellement actives

| Méthode | Route | Description |
| --- | --- | --- |
| `GET` | `/` | Tableau de bord HTML |
| `GET` | `/api/health` | Santé du service, publique pour Railway |
| `GET` | `/api/interfaces` | Interfaces disponibles (local seulement si capture activée) |
| `POST` | `/api/capture/start` | Démarre une capture locale |
| `POST` | `/api/capture/stop` | Arrête la capture locale |
| `GET` | `/api/capture/status` | État et compteurs de capture |
| `GET` | `/api/packets?limit=50` | Paquets récents |
| `GET` | `/api/flows?limit=50` | Communications regroupées |
| `GET` | `/api/alerts?limit=50` | Alertes de la session en mémoire |
| `GET` | `/api/history?limit=50` | Sessions persistées |
| `GET` | `/api/history/{session_id}/packets.csv` | Export CSV d’une session |

En production, toutes ces routes sauf `/api/health` demandent l’authentification HTTP Basic.

## Configuration

Copie `.env.example` vers `.env` pour le développement local. Ne versionne jamais `.env`.

| Variable | Défaut local | Usage |
| --- | --- | --- |
| `APP_NAME` | `Intelligent Network Packet Analyzer` | Titre du produit |
| `APP_ENV` | `development` | Mettre `production` sur Railway ; impose l’authentification |
| `APP_HOST` | `127.0.0.1` | Hôte du lanceur local ; le conteneur Railway écoute sur `0.0.0.0` |
| `APP_PORT` | `8000` | Port du lanceur local uniquement ; Railway injecte `PORT` |
| `LOG_LEVEL` | `INFO` | Niveau de journalisation |
| `CAPTURE_ENABLED` | `true` | `false` dans Railway, `true` pour capture Scapy locale |
| `DATABASE_PATH` | `data/network_analyzer.db` | Emplacement de SQLite ; Railway : `/app/data/network_analyzer.db` |
| `APP_USERNAME` | vide | Obligatoire en production |
| `APP_PASSWORD` | vide | Obligatoire en production ; garder secret et fort |

## Développement local (Windows)

Prérequis : Python 3.11 ou 3.12 recommandé, PowerShell et Npcap si tu veux capturer.

    py -3.12 -m venv .venv
    .\.venv\Scripts\Activate.ps1
    python -m pip install --upgrade pip
    pip install -r requirements.txt
    pip install -r requirements-dev.txt
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
    python backend\run.py

Ouvre `http://127.0.0.1:8000`. Pour une capture réelle, exécute le terminal avec les permissions adaptées à Npcap, puis choisis l’interface voulue dans le tableau de bord. Sans Npcap/permission ou sur Railway, la capture peut être indisponible.

## Vérification

Depuis la racine du dépôt, avec l’environnement virtuel activé :

    $env:PYTHONPATH = "backend"
    python -m pytest backend\tests -q

La suite de tests du dépôt a été exécutée pendant la préparation de ce déploiement : **20 tests réussis**. Après toute modification, relance la commande ci-dessus. Cela vérifie le backend testé, pas la capture d’une interface matérielle ni la configuration de ton compte Railway.

Vérification manuelle locale : ouvre `/api/health`, puis la page `/`. Pour la capture, Npcap et une interface active sont nécessaires.

## Déploiement sur Railway

Le déploiement est configuré avec `Dockerfile` et `railway.json`. Le CLI Railway peut envoyer directement le dossier local : GitHub n’est pas obligatoire. Consulte la [documentation officielle du CLI Railway](https://docs.railway.com/cli) pour l’installer.

1. Depuis la racine du projet, connecte-toi et crée un projet Railway lié au dossier :

       railway login
       railway init --name intelligent-network-packet-analyzer
       railway add --service analyzer

2. Dans le tableau de bord Railway, ajoute au service `analyzer` ces variables avant son premier déploiement. Ne mets pas le vrai mot de passe dans Git ni dans ce README :

       APP_ENV=production
       APP_NAME=Intelligent Network Packet Analyzer
       APP_USERNAME=<ton nom d’utilisateur>
       APP_PASSWORD=<un secret long et unique>
       CAPTURE_ENABLED=false
       DATABASE_PATH=/app/data/network_analyzer.db
       LOG_LEVEL=INFO

3. Attache un **Volume** au service, avec le chemin de montage `/app/data`. C’est à cet emplacement que le fichier SQLite sera persistant.
4. Lance le déploiement depuis la racine du dépôt :

       railway up

   La commande envoie le dossier courant au service Railway et utilise le `Dockerfile`. Le fichier `.gitignore` exclut `.env`, les environnements Python, la base `data/` et le dossier `scapy/` ; contrôle les fichiers proposés avant l’envoi.

5. Dans les paramètres Networking du service, génère un domaine public. Ouvre le domaine : le navigateur demandera les identifiants Basic Auth.
6. Vérifie `https://<ton-domaine>/api/health` (doit répondre avec `status: ok`), puis connecte-toi au domaine et ouvre le tableau de bord. Vérifie que `/api/interfaces` indique explicitement que la capture est désactivée.
7. Confirme dans Railway que le déploiement est sain, que le volume est attaché et que l’historique persiste après redémarrage.

Si tu préfères un déploiement automatique depuis GitHub, crée un dépôt privé, pousse le contenu et connecte-le comme source Railway. Le dépôt local est initialisé sur la branche `main` et les fichiers sont préparés dans l’index, mais aucun commit ni envoi distant n’a été effectué.

### Ce que Railway ne fera pas dans cette version

Un conteneur Railway n’a pas accès à la carte réseau locale Intel Wi-Fi du PC. `CAPTURE_ENABLED=false` empêche donc de présenter les interfaces virtuelles du conteneur comme si c’était la carte du PC. Pour avoir de vraies captures dans le tableau de bord hébergé, il reste à développer et sécuriser un agent Windows local qui envoie les résumés via une API authentifiée/TLS. Ne mets pas `CAPTURE_ENABLED=true` sur Railway en espérant capturer le trafic de ton PC.

## Sécurité et données

- Les identifiants de production doivent être définis comme variables/secrets du service Railway.
- Ne publie pas le dashboard sans `APP_ENV=production`, `APP_USERNAME` et `APP_PASSWORD`.
- Les captures de paquets contiennent potentiellement des adresses et métadonnées sensibles ; ne les analyse que sur des réseaux et interfaces autorisés.
- La base locale n’est pas copiée dans l’image Docker. Le volume Railway conserve l’historique de ce service ; protège et sauvegarde ce volume selon tes besoins.
- L’authentification actuelle est HTTP Basic et dépend du HTTPS fourni par le domaine Railway pour protéger les identifiants en transit.


Créé par Mr KOFFI ABDOUL-RAZAK.
