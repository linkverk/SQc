"""
validators.py - Invoervalidatie volgens whitelisting + deny by default.

Elke is_valid_* beschrijft POSITIEF wat WEL mag (een regex met re.fullmatch of
een vaste lijst). Past de invoer daar niet exact op, dan is het automatisch fout:
de laatste regel is altijd `return False`. We schonen invoer nooit stiekem op.
"""

import re
from datetime import datetime, date

import config


# Toegestane speciale tekens in een wachtwoord (naast letters en cijfers).
_PASSWORD_SPECIALS = r"~!@#$%&_\-+=`|\\(){}\[\]:;'<>,.?/"


# --- Account ---------------------------------------------------------------
def is_valid_username(value):
    # Begint met letter of '_', daarna 7-9 toegestane tekens (totaal 8-10).
    if re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_'.]{7,9}", value):
        return True
    return False


def is_valid_password(value):
    # Eist (via lookaheads) minstens 1 kleine letter, hoofdletter, cijfer en
    # speciaal teken, en in totaal 12-50 tekens uit de toegestane set.
    pattern = (
        r"(?=.*[a-z])"
        r"(?=.*[A-Z])"
        r"(?=.*[0-9])"
        r"(?=.*[" + _PASSWORD_SPECIALS + r"])"
        r"[A-Za-z0-9" + _PASSWORD_SPECIALS + r"]{12,50}"
    )
    if re.fullmatch(pattern, value):
        return True
    return False


# --- Profiel- / werknemergegevens ------------------------------------------
def is_valid_name(value):
    # 1-40 tekens; begint met letter, daarna letters, spaties, - of '.
    if re.fullmatch(r"[a-zA-Z][a-zA-Z '\-]{0,39}", value):
        return True
    return False


def is_valid_date_format(value):
    # Alleen de vorm YYYY-MM-DD (verder geen betekenis-check).
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        return True
    return False


def is_valid_gender(value):
    # Vaste lijst.
    if value in config.GENDERS:
        return True
    return False


def is_valid_zip(value):
    # 4 cijfers + 2 hoofdletters, bijv. 1234AB.
    if re.fullmatch(r"[0-9]{4}[A-Z]{2}", value):
        return True
    return False


def is_valid_house_number(value):
    # 1-6 cijfers.
    if re.fullmatch(r"[0-9]{1,6}", value):
        return True
    return False


def is_valid_city(value):
    # Vaste lijst.
    if value in config.CITIES:
        return True
    return False


def is_valid_email(value):
    # iets @ iets . letters
    if re.fullmatch(r"[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,255}\.[a-zA-Z]{2,}", value):
        return True
    return False


def is_valid_phone(value):
    # De 8 cijfers die na +31-6- komen.
    if re.fullmatch(r"[0-9]{8}", value):
        return True
    return False


def is_valid_doc_type(value):
    # Vaste lijst.
    if value in config.IDENTITY_DOCUMENT_TYPES:
        return True
    return False


def is_valid_doc_number(value):
    # XXDDDDDDD (2 hoofdletters + 7 cijfers) of XDDDDDDDD (1 + 8).
    if re.fullmatch(r"[A-Z]{2}[0-9]{7}|[A-Z][0-9]{8}", value):
        return True
    return False


def is_valid_bsn(value):
    # Precies 9 cijfers.
    if re.fullmatch(r"[0-9]{9}", value):
        return True
    return False


# --- Declaratie (claim) ----------------------------------------------------
def is_valid_project_number(value):
    # 2-10 cijfers.
    if re.fullmatch(r"[0-9]{2,10}", value):
        return True
    return False


def is_valid_claim_type(value):
    # Vaste lijst.
    if value in config.CLAIM_TYPES:
        return True
    return False


def is_valid_distance(value):
    # 1-4 cijfers, eerste cijfer 1-9 (dus altijd > 0, geen voorloopnullen).
    if re.fullmatch(r"[1-9][0-9]{0,3}", value):
        return True
    return False


def is_valid_salary_batch(value):
    # YYYY-MM, maand 01-12.
    if re.fullmatch(r"[0-9]{4}-(0[1-9]|1[0-2])", value):
        return True
    return False


# --- Zoeksleutel (een deel van een waarde mag) -----------------------------
def is_valid_search_key(value):
    # 1-50 tekens: letters, cijfers, spatie en een paar onschuldige tekens.
    if re.fullmatch(r"[A-Za-z0-9 '.\-@]{1,50}", value):
        return True
    return False


# --- Boundary-laag voor ALLE invoer (defense in depth) ---------------------
def is_safe_text(value):
    """Weiger niet-tekst, te lange invoer, en NULL-bytes/stuurtekens (tab mag wel).

    Wordt eenmalig op de input-boundary aangeroepen (ui/console.read_field),
    nog voor de veldspecifieke whitelist.
    """
    if not isinstance(value, str):
        return False
    if len(value) > config.MAX_INPUT_LENGTH:
        return False
    for ch in value:
        if ch == "\t":
            continue
        if ch == "\x00" or ord(ch) < 32:
            return False
    return True


# --- Datum-checks (elk checkt 1 ding) --------------------------------------
def is_existing_date(value):
    # Bestaat de datum echt (strptime weigert bijv. 2021-02-30)?
    try:
        datetime.strptime(value, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def is_within_claim_window(value):
    # Niet ouder dan 2 maanden en max. 14 dagen in de toekomst.
    try:
        claim_day = datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return False
    today = date.today()
    latest = date.fromordinal(today.toordinal() + 14)
    if _two_months_ago(today) <= claim_day <= latest:
        return True
    return False


def is_valid_age(value):
    # Leeftijd 16-100 en niet in de toekomst.
    try:
        birthday = datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return False
    today = date.today()
    age = today.year - birthday.year
    if (today.month, today.day) < (birthday.month, birthday.day):
        age -= 1
    if birthday <= today and 16 <= age <= 100:
        return True
    return False


def is_valid_claim_date(value):
    # Samensteller: juiste vorm + bestaat echt + binnen het venster.
    return (is_valid_date_format(value)
            and is_existing_date(value)
            and is_within_claim_window(value))


def is_valid_birthday(value):
    # Samensteller: juiste vorm + bestaat echt + geldige leeftijd.
    return (is_valid_date_format(value)
            and is_existing_date(value)
            and is_valid_age(value))


# --- Kleine datumhelpers ---------------------------------------------------
def _two_months_ago(today):
    """Geef de datum van 2 kalendermaanden geleden."""
    month = today.month - 2
    year = today.year
    while month <= 0:
        month += 12
        year -= 1
    day = min(today.day, _days_in_month(year, month))
    return date(year, month, day)


def _days_in_month(year, month):
    """Aantal dagen in een maand."""
    if month == 12:
        first_of_next = date(year + 1, 1, 1)
    else:
        first_of_next = date(year, month + 1, 1)
    return (first_of_next - date(year, month, 1)).days
