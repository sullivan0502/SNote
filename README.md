# Plateforme prof / élève

Site où le professeur crée les comptes élèves, organise des classes (et des
sous-groupes), partage des fichiers/textes avec accès sélectif, publie des
devoirs (dépôt de fichier + case à cocher "fait"), note ses élèves et crée
des QCM auto-corrigés. Chacun peut mettre une photo de profil.

## Démarrer (sans passer par la ligne de commande)

* **Windows** : double-clique sur `start.bat`.
* **Linux / Mac** : `./start.sh` (la première fois : `chmod +x start.sh`).

Le script installe tout seul un environnement Python isolé, les dépendances,
génère ta clé secrète automatiquement au premier lancement, puis démarre le
site sur **http://127.0.0.1:8000** (et sur ton réseau local via l'IP de la
machine). Laisse la fenêtre ouverte tant que le site doit rester accessible.

Au tout premier lancement, ouvre la page de connexion et déplie "Premier
lancement ? Créer le compte professeur" pour créer ton compte (ça ne
fonctionne qu'une seule fois).

## Sécurité déjà en place dans le code

* Mots de passe **hachés avec bcrypt**, jamais stockés en clair.
* **JWT** signé, expire après 12h ; la clé de signature vient de `.env`
(jamais codée en dur, l'appli refuse même de démarrer sans elle).
* **Anti brute-force** : après 5 tentatives de connexion échouées pour un
même identifiant depuis la même IP, la connexion est bloquée 15 minutes.
* **Accès aux fichiers vérifié côté serveur** à chaque téléchargement (pas
juste caché dans l'interface) — classe, groupe ou élève précis.
* **Limite de taille d'upload** (50 Mo) pour éviter qu'un envoi ne sature le
disque du serveur.
* **En-têtes de sécurité HTTP** (anti-clickjacking, anti-sniffing MIME) sur
toutes les réponses.
* Chaque élève ne voit que ses propres classes/devoirs/notes ; chaque prof
ne voit que ce qu'il a créé lui-même.

## Héberger depuis chez toi (accès à distance)

Tu as une IP fixe ou un service comme DuckDNS/No-IP — voici le chemin le
plus simple et sûr, avec **HTTPS automatique** :

1. **DuckDNS/No-IP** : crée un sous-domaine (ex. `tonpseudo.duckdns.org`)
qui pointe vers ton IP publique, et installe leur petit client qui la
met à jour automatiquement si elle change.
2. **IP locale fixe** : dans les paramètres de ton routeur, réserve une IP
locale fixe pour la machine qui héberge le site (pour que la redirection
de ports ne se casse pas si le routeur lui redonne une autre IP).
3. **Redirection de ports** sur le routeur : redirige les ports **80** et
**443** (externes) vers cette IP locale (ports 80/443 aussi). C'est
Caddy, pas l'appli elle-même, qui doit recevoir ces ports.
4. **Caddy** (reverse proxy avec HTTPS automatique) :

   * télécharge Caddy : https://caddyserver.com/download
   * copie `Caddyfile.example` en `Caddyfile`, remplace le domaine par le
tien
   * lance `caddy run` (dans le même dossier que le Caddyfile)
   * Caddy obtient et renouvelle seul le certificat Let's Encrypt, et
redirige tout le trafic HTTP vers HTTPS.
5. Lance l'appli normalement avec `start.bat` (elle écoute déjà sur
`0.0.0.0:8000`, donc accessible en local pour Caddy).
6. Accès distant final : **https://tonpseudo.duckdns.org**

Important : n'ouvre **jamais** le port 8000 directement sur ton routeur —
seuls 80/443 vers Caddy doivent être exposés. Le port 8000 ne doit être
joignable que depuis la machine elle-même (127.0.0.1) ou ton réseau local,
jamais depuis Internet directement.

### Sans reverse proxy (déconseillé, dépannage seulement)

Si tu veux juste tester rapidement sans HTTPS (réseau local uniquement, pas
depuis Internet) : lance `start.bat`, puis sur un autre appareil du même
réseau Wi-Fi, va sur `http://\\\[IP-locale-du-PC]:8000`. Trouve l'IP locale
avec `ipconfig` (Windows) dans la ligne "Adresse IPv4". Ne fais jamais ça
en exposant le port 8000 directement sur Internet : sans HTTPS, tout
circule en clair (mots de passe compris) et n'importe qui peut l'intercepter.

## Ce qui reste pour une V2 éventuelle

* Commentaires sur les fichiers/devoirs.
* Modification/suppression de comptes élèves, réinitialisation de mot de
passe.
* Notifications (nouveau devoir, nouvelle note, nouveau QCM).
* Historique/export des notes en PDF ou tableau.

## Structure du projet

```
main.py            → routes API (auth, prof, élève)
auth.py             → hachage mots de passe + JWT (lit .env)
database.py         → schéma SQLite (migrations légères incluses)
static/              → frontend (HTML/CSS/JS natif, pas de framework)
storage/files/          → fichiers publiés par les profs
storage/submissions/    → devoirs déposés par les élèves
storage/avatars/        → photos de profil
start.bat / start.sh    → démarrage en un clic (Windows / Linux-Mac)
.env.example             → modèle de config (copier en .env)
Caddyfile.example        → modèle de reverse proxy HTTPS
```



