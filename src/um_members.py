"""
um_members.py - Startpunt van het DeclaratieApp-backendsysteem.

Draai dit bestand om te starten:   python um_members.py

Het koppelt de lagen aan elkaar (een App-context met de services) en draait de
login-lus. Na een succesvolle login: dwing zo nodig een wachtwoordwijziging af,
toon een waarschuwing over ongelezen verdachte activiteit, en open het menu dat
bij de rol hoort.
"""

import config
from data import database
from services.log_service import LogService
from services.auth_service import AuthService
from services.user_service import UserService
from services.claim_service import ClaimService
from services.backup_service import BackupService
from services import authorization as az
from ui import console as c
from ui import menus


class App:
    """Context-object dat de gedeelde services bevat."""

    def __init__(self):
        self.log_service = LogService()
        self.auth = AuthService(self.log_service)
        self.user_service = UserService(self.log_service)
        self.claim_service = ClaimService(self.log_service)
        self.backup_service = BackupService(self.log_service)
        # Koppel de verdachte-invoer hook van de UI aan het log, zodat een
        # NULL-byte/stuurteken/te lange invoer op elk veld verdacht gelogd wordt.
        c.set_suspicious_input_handler(self._report_suspicious_input)

    def _report_suspicious_input(self, label, reason):
        user = self.auth.current_user
        if user:
            username = user["username"]
        else:
            username = "-"
        self.log_service.log(
            username,
            "Suspicious input rejected",
            info=f"field '{label}': {reason}",
            suspicious=True,
        )


def _force_password_change(app, temp_password):
    c.header("You must change your password")
    c.info("You are using a temporary password. Set a new password now.")
    while True:
        new = menus._read_new_password("New password")
        if new is None:
            continue
        try:
            app.user_service.update_own_password(
                app.auth.current_user, temp_password, new)
            c.success("Password changed.")
            return
        except ValueError as exc:        # bijv. tijdelijk wachtwoord klopt niet
            c.error(str(exc))


def _show_suspicious_alert(app):
    if az.has_permission(app.auth.current_user, az.VIEW_LOGS):
        count = app.log_service.unread_suspicious_count()
        if count > 0:
            c.header("SECURITY ALERT")
            c.info(f"  There are {count} unread SUSPICIOUS activities in the log.")
            c.info("  Please review the activity log (View logs).")


def login_screen(app):
    """Vraag om inloggegevens. True = doorgaan, False = gebruiker wil stoppen."""
    c.header("DeclaratieApp - Login")
    c.info("Type '/cancel' as username to exit the program.")
    username = c.read_field("Username")
    if username is None or username.strip().lower() in ("/cancel", "exit", "quit"):
        return False
    password = c.read_field("Password", password=True)
    user = app.auth.login(username, password or "")
    if user is None:
        if app.auth.last_lockout_seconds > 0:
            c.error(f"Too many failed attempts. This account is temporarily "
                    f"locked. Try again in {app.auth.last_lockout_seconds} "
                    f"seconds.")
        else:
            c.error("Login failed. Check your username and password.")
        c.pause()
        return True  # blijf op het inlogscherm
    c.success(f"Welcome, {user.get('first_name') or user['username']}!")
    if user.get("must_change_password"):
        _force_password_change(app, password)
    _show_suspicious_alert(app)
    menus.run_for_role(app)
    return True


def main():
    database.initialize_database()
    c.header("DeclaratieApp backend system - CoreStaff Solutions")
    try:
        running = True
        while running:
            running = login_screen(app=APP)
    except (KeyboardInterrupt, EOFError):
        print()
    finally:
        database.close_connection()
        c.info("Goodbye.")


APP = App()

if __name__ == "__main__":
    main()
