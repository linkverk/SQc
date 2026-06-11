"""
config.py - Centrale instellingen en constanten.

Alles waar meerdere lagen het over eens moeten zijn (paden, de hardcoded
super-admin, toegestane lijsten, rollen, limieten) staat hier op een plek.
"""

import os

# --- Bestandslocaties (alleen schrijven binnen deze map, eis van de opdracht) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "declaratie.db")
BACKUP_DIR = os.path.join(BASE_DIR, "backups")

# --- Hardcoded super-admin (bewust onveilig, vereist door de casus) ---
# Staat NIET in de database; zo kan de docent altijd inloggen.
SUPER_ADMIN_USERNAME = "super_admin"
SUPER_ADMIN_PASSWORD = "Admin_123?"

# --- Cryptografie ---
# De symmetrische sleutel wordt afgeleid van dit geheim, zodat backups op elke
# machine te ontsleutelen zijn maar het rauwe .db-bestand onleesbaar blijft.
APP_SECRET = b"CoreStaff-DeclaratieApp-2026-symmetric-master-secret"
APP_SALT = b"CoreStaff-static-kdf-salt-v1"
KDF_ITERATIONS = 200_000

# --- Rollen ---
ROLE_SUPER_ADMIN = "super_admin"
ROLE_MANAGER = "manager"
ROLE_EMPLOYEE = "employee"

# --- Brute-force ---
# Boven dit aantal mislukte logins op rij: markeer als verdacht in het log.
SUSPICIOUS_LOGIN_THRESHOLD = 3
# Boven dit aantal mislukte pogingen per gebruikersnaam: blokkeer die naam
# tijdelijk (kort en zelfherstellend, zodat het geen permanente lock-out wordt).
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 60

# --- Vaste keuzelijsten (whitelists) ---
CITIES = [
    "Rotterdam", "Amsterdam", "Den Haag", "Utrecht", "Eindhoven",
    "Groningen", "Tilburg", "Almere", "Breda", "Nijmegen",
]
IDENTITY_DOCUMENT_TYPES = ["Passport", "ID-Card"]
GENDERS = ["male", "female"]
CLAIM_TYPES = ["Travel", "Home Office"]

# --- Limieten tegen extreem lange invoer (DoS) ---
# Langere invoer dan dit bekijken we nooit (zie validators.is_safe_text).
MAX_INPUT_LENGTH = 256
# Maximale grootte van de database-entry in een backup-zip (rem tegen zip-bomb).
MAX_BACKUP_DB_BYTES = 100 * 1024 * 1024  # 100 MB
