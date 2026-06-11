"""
hashing.py - Wachtwoord-hashing met Argon2id.

We slaan nooit een wachtwoord op, alleen de hash. Argon2 zet zelf een
willekeurige salt in elke hash, dus gelijke wachtwoorden geven verschillende
hashes.
"""

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

_hasher = PasswordHasher()

# Vaste dummy-hash om een mislukte login even lang te laten duren wanneer de
# gebruikersnaam niet bestaat. Zonder dit zou "onbekende gebruiker" sneller
# terugkeren dan "bekende gebruiker, fout wachtwoord" -> timing-lek.
_DUMMY_HASH = _hasher.hash("timing-equalisation-dummy-password")


def hash_password(plain_password):
    """Geef een Argon2id-hash terug voor het wachtwoord."""
    return _hasher.hash(plain_password)


def dummy_verify():
    """Draai een verify tegen de dummy-hash (timing gelijktrekken)."""
    try:
        _hasher.verify(_DUMMY_HASH, "definitely-wrong")
    except Exception:
        pass


def verify_password(stored_hash, plain_password):
    """Geef True als het wachtwoord bij de hash hoort, anders False."""
    try:
        return _hasher.verify(stored_hash, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError, TypeError):
        return False
