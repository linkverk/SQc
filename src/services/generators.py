"""
generators.py - Veilige generatie van server-side waarden.

Deze waarden maakt de applicatie zelf aan (de gebruiker typt ze nooit). We
gebruiken `secrets` (cryptografisch veilig), niet `random`.
"""

import secrets
import string


def generate_temp_password(length=16):
    """Genereer een willekeurig wachtwoord dat aan de wachtwoordregels voldoet."""
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    specials = "~!@#$%&_-+="
    alphabet = lower + upper + digits + specials

    # Begin met minstens 1 teken uit elke vereiste categorie, vul daarna aan.
    password_chars = [
        secrets.choice(lower),
        secrets.choice(upper),
        secrets.choice(digits),
        secrets.choice(specials),
    ]
    for _ in range(length - 4):
        password_chars.append(secrets.choice(alphabet))
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def generate_employee_id(exists_func):
    """Genereer een uniek werknemer-ID van 7 cijfers."""
    while True:
        digits = ""
        for _ in range(7):
            digits += secrets.choice("0123456789")
        if not exists_func(digits):
            return digits


def generate_restore_code(length=20):
    """Genereer een eenmalige restore-code (lang en alfanumeriek)."""
    alphabet = string.ascii_letters + string.digits
    code = ""
    for _ in range(length):
        code += secrets.choice(alphabet)
    return code
