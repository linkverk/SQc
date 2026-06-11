"""
auth_service.py - Inloggen en sessiebeheer.

* Controleert de hardcoded super-admin en database-gebruikers (Argon2).
* Houdt de huidige sessie bij.
* Detecteert brute-force (verdacht loggen) en blokkeert een gebruikersnaam
  tijdelijk na te veel mislukte pogingen.

De login-invoer halen we bewust NIET door de strenge username-validator: een
aanvaller mag van alles typen. Alles wat niet bij een echt account hoort, is
gewoon een mislukte login (en we verklappen nooit welk veld fout was).
"""

import hmac
import time

import config
from data.repositories import UserRepository
from security import hashing


class AuthService:
    def __init__(self, log_service):
        self._users = UserRepository()
        self._log = log_service
        self.current_user = None
        # Mislukte pogingen op rij over het hele login-scherm.
        self._consecutive_failures = 0
        # Mislukte pogingen per gebruikersnaam:
        # {key: {"fails": aantal, "locked_until": tijdstip}}.
        self._failed_by_user = {}
        # Hoeveel seconden de laatste poging geblokkeerd was (UI leest dit).
        self.last_lockout_seconds = 0

    # --- sessie -----------------------------------------------------------
    def is_logged_in(self):
        return self.current_user is not None

    def logout(self):
        if self.current_user:
            self._log.log(self.current_user["username"], "Logged out")
        self.current_user = None

    def revalidate_session(self):
        """Controleer na een restore of de ingelogde gebruiker nog geldig bestaat.

        Geeft True als de sessie geldig blijft; anders maakt hij de sessie
        ongeldig en geeft False. De hardcoded super-admin is altijd geldig.
        """
        if self.current_user is None:
            return False
        if (self.current_user["role"] == config.ROLE_SUPER_ADMIN
                and self.current_user["id"] == 0):
            return True
        fresh = self._users.get_by_id(self.current_user["id"])
        if (fresh is None
                or fresh["username"].lower() != self.current_user["username"].lower()
                or fresh["role"] != self.current_user["role"]):
            self._log.log(self.current_user["username"],
                          "Session invalidated after restore",
                          info="logged-in account no longer matches the database",
                          suspicious=True)
            self.current_user = None
            return False
        # Ververs gecachete velden (naam / must_change_password kan gewijzigd zijn).
        self.current_user = fresh
        return True

    # --- invoer-veiligheid op de login-grens ------------------------------
    def _has_control_chars(self, value):
        """True als de invoer een NULL-byte of stuurteken bevat (tab mag wel)."""
        if not isinstance(value, str):
            return False
        for ch in value:
            if ch == "\t":          # gewone tab mag wel
                continue
            if ord(ch) < 32:        # NULL-byte of ander stuurteken
                return True
        return False

    def _safe(self, value):
        """Geef de invoer terug, of '' bij geen tekst / te lang / stuurtekens."""
        if value is None or not isinstance(value, str):
            return ""
        if len(value) > config.MAX_INPUT_LENGTH:
            return ""
        if self._has_control_chars(value):
            return ""
        return value

    # --- brute-force-lockout ----------------------------------------------
    def _lock_key(self, username):
        """Genormaliseerde sleutel, zodat 'Bob ' en 'bob' dezelfde teller delen."""
        return username.strip().lower()

    def _remaining_lockout(self, key):
        """Seconden dat de gebruikersnaam nog geblokkeerd is (0 = niet)."""
        record = self._failed_by_user.get(key)
        if not record:
            return 0
        remaining = int(record["locked_until"] - time.time())
        if remaining > 0:
            return remaining
        return 0

    def _register_failure(self, key):
        """Tel een mislukte poging en blokkeer boven de limiet."""
        record = self._failed_by_user.get(key, {"fails": 0, "locked_until": 0.0})
        record["fails"] += 1
        if record["fails"] >= config.MAX_LOGIN_ATTEMPTS:
            record["locked_until"] = time.time() + config.LOGIN_LOCKOUT_SECONDS
        self._failed_by_user[key] = record

    # --- login ------------------------------------------------------------
    def login(self, username, password):
        """Geef het ingelogde gebruiker-dict bij succes, of None bij mislukking."""
        self.last_lockout_seconds = 0

        # NULL-byte / stuurteken = manipulatie: weiger en log verdacht.
        if self._has_control_chars(username) or self._has_control_chars(password):
            return self._reject_malformed_login(username)

        username = self._safe(username)
        password = self._safe(password)
        key = self._lock_key(username)

        # Weiger zolang de gebruikersnaam geblokkeerd is (voor de wachtwoordcheck,
        # zodat een geblokkeerd account niet ge-brute-forced kan worden).
        remaining = self._remaining_lockout(key)
        if remaining > 0:
            return self._reject_locked_login(username, remaining)

        user = self._authenticate(username, password)
        if user is not None:
            self._consecutive_failures = 0
            self._failed_by_user.pop(key, None)   # teller wissen bij succes
            self.current_user = user
            self._log.log(user["username"], "Logged in successfully")
            return user

        return self._reject_failed_login(username, key)

    def _reject_malformed_login(self, username):
        """Weiger een login met een NULL-byte/stuurteken en log verdacht."""
        log_name = self._safe(username) or "-"
        key = self._lock_key(log_name)
        self._register_failure(key)
        self._consecutive_failures += 1
        self.last_lockout_seconds = self._remaining_lockout(key)
        self._log.log(
            log_name, "Unsuccessful login",
            info="login input contained a NULL byte or control character "
                 "(possible tampering); attempt rejected.",
            suspicious=True,
        )
        return None

    def _reject_locked_login(self, username, remaining):
        """Weiger een login omdat de gebruikersnaam tijdelijk geblokkeerd is."""
        self.last_lockout_seconds = remaining
        self._consecutive_failures += 1
        self._log.log(
            username or "-", "Login blocked (account locked)",
            info=f'username "{username}" is temporarily locked after too '
                 f"many failed attempts ({remaining}s remaining).",
            suspicious=True,
        )
        return None

    def _reject_failed_login(self, username, key):
        """Tel een gewone mislukte login en log (verdacht bij te veel op rij)."""
        self._register_failure(key)
        self._consecutive_failures += 1
        self.last_lockout_seconds = self._remaining_lockout(key)
        if self._consecutive_failures >= config.SUSPICIOUS_LOGIN_THRESHOLD:
            self._log.log(
                username or "-", "Unsuccessful login",
                info=f"{self._consecutive_failures} failed attempts in a row "
                     f"(possible brute-force).",
                suspicious=True,
            )
        else:
            self._log.log(
                username or "-", "Unsuccessful login",
                info=f'username "{username}" used with a wrong password.',
            )
        return None

    def _authenticate(self, username, password):
        """Geef het gebruiker-dict terug bij juiste inloggegevens, anders None."""
        # 1) Hardcoded super-admin (wachtwoord in constante tijd vergeleken).
        if (username.lower() == config.SUPER_ADMIN_USERNAME
                and hmac.compare_digest(password, config.SUPER_ADMIN_PASSWORD)):
            return {
                "id": 0,
                "username": config.SUPER_ADMIN_USERNAME,
                "role": config.ROLE_SUPER_ADMIN,
                "first_name": "Super",
                "last_name": "Administrator",
                "must_change_password": 0,
            }

        # 2) Database-gebruiker met Argon2-verificatie.
        user = self._users.find_by_username(username)
        if user is None:
            # Dummy-verify zodat een onbekende gebruiker evenveel tijd kost als
            # een bekende -> geen user enumeration via timing.
            hashing.dummy_verify()
            return None
        if hashing.verify_password(user["password_hash"], password):
            return user
        return None
