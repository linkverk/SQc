"""
crypto.py - Symmetrische versleuteling van gevoelige gegevens.

Elke gevoelige waarde wordt los versleuteld voor het opslaan en ontsleuteld na
het lezen, zodat het rauwe databasebestand alleen ciphertext bevat.

* encrypt/decrypt : Fernet (AES-128-CBC + HMAC), willekeurige IV per waarde.
* blind_index     : deterministische keyed hash (HMAC) om versleutelde kolommen
                    toch exact te kunnen opzoeken (bijv. de gebruikersnaam).
"""

import base64
import hashlib
import hmac

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import config


def _derive_fernet_key():
    """Leid de 32-byte Fernet-sleutel af uit het applicatiegeheim (PBKDF2)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=config.APP_SALT,
        iterations=config.KDF_ITERATIONS,
    )
    raw_key = kdf.derive(config.APP_SECRET)
    return base64.urlsafe_b64encode(raw_key)


# Eenmalig opbouwen bij het importeren.
_FERNET = Fernet(_derive_fernet_key())

# Aparte sleutel voor de blind index (versleutelingssleutel nooit hergebruiken).
_INDEX_KEY = hashlib.sha256(b"blind-index::" + config.APP_SECRET).digest()


def encrypt(plaintext):
    """Versleutel een string tot een opslaanbare token (str)."""
    if plaintext is None:
        plaintext = ""
    token = _FERNET.encrypt(str(plaintext).encode("utf-8"))
    return token.decode("utf-8")


def decrypt(token):
    """Ontsleutel een token. Geeft '' terug als het niet leesbaar/echt is."""
    if token is None or token == "":
        return ""
    try:
        return _FERNET.decrypt(token.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError):
        # Gemanipuleerd, beschadigd of niet met onze sleutel versleuteld.
        return ""


def encrypt_bool(value):
    """Versleutel een ja/nee-vlag als 'true'/'false' (geen leesbare 0/1)."""
    if value:
        return encrypt("true")
    return encrypt("false")


def decrypt_bool(token):
    """Lees een met encrypt_bool opgeslagen vlag terug als True/False."""
    return decrypt(token) == "true"


def blind_index(value):
    """Deterministische keyed hash: zelfde invoer -> zelfde, niet-omkeerbare hash."""
    if value is None:
        value = ""
    digest = hmac.new(_INDEX_KEY, value.encode("utf-8"), hashlib.sha256)
    return digest.hexdigest()
