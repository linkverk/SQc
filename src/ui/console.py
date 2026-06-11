"""
console.py - Kleine hulpjes voor het console-scherm.

Het belangrijkste is `read_field`: dat blijft vragen tot de waarde geldig is, zodat
foute invoer nooit bij de services komt en het programma nooit crasht. De gebruiker
kan altijd '/cancel' typen om te stoppen.
"""

import getpass

import config
from validation import validators as v

CANCEL = "/cancel"


# --- verdachte-invoer hook -------------------------------------------------
# De app koppelt hier een functie aan die verdachte invoer logt. Zo kan read_field
# een NULL-byte / stuurteken / te lange invoer melden zonder de UI vast te koppelen
# aan de service-laag. Zonder hook (bijv. in een test) gebeurt er niets.
_suspicious_input_handler = None


def set_suspicious_input_handler(handler):
    """Koppel een callback `handler(label, reason)` voor verdachte invoer (of None)."""
    global _suspicious_input_handler
    _suspicious_input_handler = handler


def _unsafe_reason(raw):
    """Korte reden waarom is_safe_text de invoer afkeurde (echo nooit de waarde)."""
    if not isinstance(raw, str):
        return "non-text input"
    if len(raw) > config.MAX_INPUT_LENGTH:
        return "input exceeds the maximum allowed length"
    return "NULL byte or control character in input"


def _report_suspicious_input(label, raw):
    if _suspicious_input_handler is not None:
        try:
            _suspicious_input_handler(label, _unsafe_reason(raw))
        except Exception:
            pass   # loggen mag de UI nooit laten crashen


# --- output ---------------------------------------------------------------
def header(title):
    line = "=" * 60
    print("\n" + line)
    print(title)
    print(line)


def info(message):
    print(message)


def error(message):
    print("  [!] " + message)


def success(message):
    print("  [OK] " + message)


def pause():
    input("\nPress Enter to continue...")


# --- input ----------------------------------------------------------------
def read_field(label, is_valid=None, error_message="Invalid input, please try again.",
               optional=False, password=False):
    """Vraag net zo lang om een waarde tot die geldig is, en geef hem terug.

    * is_valid      : functie die True/False geeft (None = alles mag).
    * error_message : tekst bij afgekeurde invoer.
    * optional      : leeg laten mag (-> None).
    * password      : verborgen typen.

    Geeft de geldige waarde, of None bij '/cancel' of een leeg optioneel veld.
    """
    if password:
        suffix = ""
    else:
        suffix = f" (type '{CANCEL}' to stop)"
    while True:
        if password:
            raw = getpass.getpass(f"{label}: ")
        else:
            raw = input(f"{label}{suffix}: ")

        if not password and raw.strip() == CANCEL:
            return None
        if optional and raw.strip() == "":
            return None

        # Boundary-laag voor ELK veld: weiger NULL-bytes/stuurtekens/te lange
        # invoer, nog voor de veldspecifieke whitelist. Verdacht -> via de hook.
        if not v.is_safe_text(raw):
            _report_suspicious_input(label, raw)
            error(error_message)
            continue

        if is_valid is None:      # geen check nodig
            return raw
        if is_valid(raw):         # geldig
            return raw
        error(error_message)      # ongeldig -> opnieuw vragen


def read_menu_choice(prompt="Choose an option"):
    return input(f"\n{prompt}: ").strip().lower()


def confirm(question):
    answer = input(f"{question} (y/n): ").strip().lower()
    return answer in ("y", "yes")


def pick_from_list(items, render, title="Select an item"):
    """Toon een genummerde lijst en geef het gekozen item terug, of None."""
    if not items:
        info("  (nothing to show)")
        return None
    header(title)
    for index, item in enumerate(items, start=1):
        print(f"  {index}. {render(item)}")
    # Blijf vragen tot er een geldige keuze is; leeg of '/cancel' annuleert.
    while True:
        raw = input(f"\nEnter number (or '{CANCEL}'): ").strip().lower()
        if raw == CANCEL or raw == "":
            return None
        if not raw.isdigit():
            error("Please enter a valid number.")
            continue
        index = int(raw)
        if 1 <= index <= len(items):
            return items[index - 1]
        error("That number is not in the list.")


def print_record(record, fields):
    """Print een dict als uitgelijnde label/waarde-regels."""
    width = 0
    for _, label in fields:
        if len(label) > width:
            width = len(label)
    for key, label in fields:
        print(f"  {label.ljust(width)} : {record.get(key, '')}")
