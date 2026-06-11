"""
menus.py - De menu's per rol (super-admin, manager, employee).

Elke rol ziet alleen de acties die hij mag. Elke actie loopt via _run(), zodat een
fout netjes als melding verschijnt in plaats van het programma te laten crashen.
De menu's praten alleen met de service-laag, nooit rechtstreeks met de database.

Validatie gebeurt in read_field() (zie ui/console.py): per veld geven we een
check-functie (validators.is_valid_*) en een foutmelding mee.
"""

import config
from validation import validators as v
from services import authorization as az
from ui import console as c


# ===========================================================================
# Gedeelde invoer-helpers
# ===========================================================================
_USERNAME_HELP = ("8 to 10 characters, starts with a letter or _, then only "
                  "letters, digits, _, ' or a period.")
_PASSWORD_HELP = ("12 to 50 characters, with at least 1 lowercase letter, 1 "
                  "uppercase letter, 1 digit and 1 special character.")
_NAME_HELP = "Only letters, spaces, - or ' (maximum 40 characters)."
_SEARCH_HELP = "1 to 50 characters: letters, digits, space or ' . - @"


def _read_new_username(app):
    while True:
        username = c.read_field("Username", v.is_valid_username, _USERNAME_HELP)
        if username is None:
            return None
        if not app.user_service.username_available(username):
            c.error("That username is already taken.")
            continue
        return username


def _read_new_password(label="New password"):
    """Vraag een nieuw wachtwoord en laat het ter bevestiging herhalen."""
    while True:
        pwd = c.read_field(label, v.is_valid_password, _PASSWORD_HELP, password=True)
        if pwd is None:
            return None
        if c.read_field("Repeat password", password=True) == pwd:
            return pwd
        c.error("The passwords do not match. Please try again.")


def _pick_choice(title, options):
    """Toon een genummerde keuzelijst en geef de gekozen optie terug (of None)."""
    return c.pick_from_list(options, lambda x: x, title=f"Choose {title}")


def _collect_employee_profile():
    """Vraag alle werknemergegevens (Tabel 2). Geeft een dict of None."""
    fields = [
        ("birthday", "Date of birth (YYYY-MM-DD)", v.is_valid_birthday,
         "Use format YYYY-MM-DD; age must be between 16 and 100."),
        ("street", "Street name", v.is_valid_name,
         "Only letters, spaces, - or ' (maximum 40 characters)."),
        ("house_number", "House number", v.is_valid_house_number,
         "Only digits (1 to 6)."),
        ("zip", "Zip code (DDDDXX, e.g. 1234AB)", v.is_valid_zip,
         "Use 4 digits + 2 UPPERCASE letters, e.g. 1234AB."),
        ("email", "Email address", v.is_valid_email,
         "Use a valid email address, e.g. name@example.com."),
        ("doc_number", "ID document number (XXDDDDDDD or XDDDDDDDD)",
         v.is_valid_doc_number, "Use format XXDDDDDDD or XDDDDDDDD."),
        ("bsn", "BSN (9 digits)", v.is_valid_bsn,
         "A BSN consists of exactly 9 digits."),
    ]
    profile = {}
    for key, label, is_valid, message in fields:
        value = c.read_field(label, is_valid, message)
        if value is None:
            return None
        profile[key] = value

    # Geslacht, stad en documenttype kiest de gebruiker uit een vaste lijst.
    gender = _pick_choice("Gender", config.GENDERS)
    if gender is None:
        return None
    profile["gender"] = gender

    city = _pick_choice("City", config.CITIES)
    if city is None:
        return None
    profile["city"] = city

    doc_type = _pick_choice("ID document type", config.IDENTITY_DOCUMENT_TYPES)
    if doc_type is None:
        return None
    profile["doc_type"] = doc_type

    # Telefoon: de gebruiker typt 8 cijfers, wij zetten +31-6- ervoor.
    eight_digits = c.read_field("Mobile number (8 digits after +31-6-)",
                                v.is_valid_phone, "Type exactly 8 digits.")
    if eight_digits is None:
        return None
    profile["phone"] = "+31-6-" + eight_digits
    return profile


def _collect_claim_data():
    """Vraag de gegevens van een declaratie. Geeft een dict of None."""
    data = {}
    claim_date = c.read_field("Claim date (YYYY-MM-DD)", v.is_valid_claim_date,
                              "Date may not be older than 2 months or more than 14 "
                              "days in the future (format YYYY-MM-DD).")
    if claim_date is None:
        return None
    data["claim_date"] = claim_date

    project = c.read_field("Project number (2 to 10 digits)", v.is_valid_project_number,
                           "A project number consists of 2 to 10 digits.")
    if project is None:
        return None
    data["project_number"] = project

    claim_type = _pick_choice("Claim type", config.CLAIM_TYPES)
    if claim_type is None:
        return None
    data["claim_type"] = claim_type

    # Alleen bij 'Travel' vragen we de reisgegevens (Tabel 3).
    if claim_type == "Travel":
        travel_fields = [
            ("Travel distance in km", "distance", v.is_valid_distance,
             "Only digits and greater than 0."),
            ("Departure zip code (DDDDXX)", "from_zip", v.is_valid_zip,
             "Use 4 digits + 2 UPPERCASE letters, e.g. 1234AB."),
            ("Departure house number", "from_house", v.is_valid_house_number,
             "Only digits."),
            ("Destination zip code (DDDDXX)", "to_zip", v.is_valid_zip,
             "Use 4 digits + 2 UPPERCASE letters, e.g. 1234AB."),
            ("Destination house number", "to_house", v.is_valid_house_number,
             "Only digits."),
        ]
        for label, key, is_valid, message in travel_fields:
            value = c.read_field(label, is_valid, message)
            if value is None:
                return None
            data[key] = value
    return data


# ===========================================================================
# Generieke actie-wrapper
# ===========================================================================
def _run(app, action):
    """Voer een actie uit en vang fouten netjes op (het menu crasht nooit)."""
    try:
        action()
    except az.AuthorizationError as exc:
        # Via het menu zie je alleen toegestane knoppen. Komt er toch een
        # autorisatie-weigering binnen, dan is dat manipulatie/bug -> verdacht.
        user = app.auth.current_user
        if user:
            username = user["username"]
        else:
            username = "-"
        app.log_service.log(
            username, "Authorization denied", info=str(exc), suspicious=True)
        c.error(str(exc))
    except ValueError as exc:                 # bedrijfsregel-fout (bijv. dubbel)
        c.error(str(exc))
    except Exception as exc:                  # vangnet
        c.error(f"Unexpected error: {exc}")
    c.pause()


# ===========================================================================
# Eigen account (gedeeld)
# ===========================================================================
def change_own_password(app):
    old = c.read_field("Current password", optional=False, password=True)
    new = _read_new_password("New password")
    if new is None:
        return
    app.user_service.update_own_password(app.auth.current_user, old, new)
    c.success("Password changed.")


def update_own_account(app):
    c.info("Leave a field empty to keep it unchanged.")
    first = c.read_field("First name", v.is_valid_name, _NAME_HELP, optional=True)
    last = c.read_field("Last name", v.is_valid_name, _NAME_HELP, optional=True)
    new_username = c.read_field("New username", v.is_valid_username,
                                _USERNAME_HELP, optional=True)
    if new_username and not app.user_service.username_available(new_username):
        c.error("That username is already taken.")
        return
    app.user_service.update_own_account(app.auth.current_user,
                                        first_name=first, last_name=last,
                                        new_username=new_username)
    c.success("Account updated.")


def delete_own_account(app):
    if not c.confirm("Are you sure you want to delete your own account?"):
        return
    app.user_service.delete_own_account(app.auth.current_user)
    c.success("Your account has been deleted. You will be logged out.")
    app.auth.current_user = None


# ===========================================================================
# Werknemerbeheer (manager / super-admin)
# ===========================================================================
def _select_user(app, role, title):
    users = app.user_service.list_role(app.auth.current_user, role)
    return c.pick_from_list(
        users,
        lambda u: f"{u['username']} - {u['first_name']} {u['last_name']}",
        title=title,
    )


def add_employee(app):
    c.header("Add new employee")
    username = _read_new_username(app)
    if username is None:
        return
    password = _read_new_password("Initial password")
    if password is None:
        return
    first = c.read_field("First name", v.is_valid_name, _NAME_HELP)
    if first is None:
        return
    last = c.read_field("Last name", v.is_valid_name, _NAME_HELP)
    if last is None:
        return
    profile = _collect_employee_profile()
    if profile is None:
        return
    employee_id = app.user_service.add_employee(
        app.auth.current_user, username, password, first, last, profile)
    c.success(f"Employee created with employee ID {employee_id}.")


def update_employee(app):
    target = _select_user(app, config.ROLE_EMPLOYEE, "Choose employee to update")
    if target is None:
        return
    c.info("Leave a field empty to keep it unchanged.")
    first = c.read_field("First name", v.is_valid_name, _NAME_HELP, optional=True)
    last = c.read_field("Last name", v.is_valid_name, _NAME_HELP, optional=True)
    names = {}
    if first:
        names["first_name"] = first
    if last:
        names["last_name"] = last

    # Alle velden van Tabel 2 zijn bij te werken; elk veld is optioneel.
    profile = {}
    profile_fields = [
        ("Date of birth (YYYY-MM-DD)", "birthday", v.is_valid_birthday,
         "Use format YYYY-MM-DD; age must be between 16 and 100."),
        ("Street name", "street", v.is_valid_name, _NAME_HELP),
        ("House number", "house_number", v.is_valid_house_number, "Only digits."),
        ("Zip code (DDDDXX)", "zip", v.is_valid_zip,
         "Use 4 digits + 2 UPPERCASE letters, e.g. 1234AB."),
        ("Email address", "email", v.is_valid_email, "Use a valid email address."),
        ("ID document number (XXDDDDDDD or XDDDDDDDD)", "doc_number",
         v.is_valid_doc_number, "Use format XXDDDDDDD or XDDDDDDDD."),
        ("BSN (9 digits)", "bsn", v.is_valid_bsn,
         "A BSN consists of exactly 9 digits."),
    ]
    for label, key, is_valid, message in profile_fields:
        value = c.read_field(label, is_valid, message, optional=True)
        if value:
            profile[key] = value

    eight_digits = c.read_field("Mobile number (8 digits after +31-6-)",
                                v.is_valid_phone, "Type exactly 8 digits.",
                                optional=True)
    if eight_digits:
        profile["phone"] = "+31-6-" + eight_digits

    c.info("Choice fields below: press Enter to keep the current value.")
    gender = _pick_choice("Gender", config.GENDERS)
    if gender:
        profile["gender"] = gender
    city = _pick_choice("City", config.CITIES)
    if city:
        profile["city"] = city
    doc_type = _pick_choice("ID document type", config.IDENTITY_DOCUMENT_TYPES)
    if doc_type:
        profile["doc_type"] = doc_type

    app.user_service.update_employee(app.auth.current_user, target["id"],
                                     names=names or None, profile=profile or None)
    c.success("Employee updated.")


def delete_employee(app):
    target = _select_user(app, config.ROLE_EMPLOYEE, "Choose employee to delete")
    if target is None:
        return
    if not c.confirm(f"Delete employee {target['username']}?"):
        return
    app.user_service.delete_employee(app.auth.current_user, target["id"])
    c.success("Employee deleted.")


def reset_employee_password(app):
    target = _select_user(app, config.ROLE_EMPLOYEE, "Choose employee")
    if target is None:
        return
    temp = app.user_service.reset_employee_password(app.auth.current_user,
                                                    target["id"])
    c.success(f"Temporary password for {target['username']}: {temp}")


def search_employees(app):
    key = c.read_field("Search term (partial is allowed)", v.is_valid_search_key,
                       _SEARCH_HELP)
    if key is None:
        return
    results = app.user_service.search_employees(app.auth.current_user, key)
    c.header(f"{len(results)} employee(s) found")
    for emp in results:
        c.print_record(emp, [
            ("employee_id", "Employee-ID"), ("username", "Username"),
            ("first_name", "First name"), ("last_name", "Last name"),
            ("street", "Street"), ("house_number", "House no"),
            ("zip", "Zip"), ("city", "City"), ("email", "Email"),
            ("phone", "Phone"), ("doc_type", "ID type"),
            ("doc_number", "ID number"), ("bsn", "BSN"),
        ])
        print("  " + "-" * 40)


# ===========================================================================
# Managerbeheer (alleen super-admin)
# ===========================================================================
def add_manager(app):
    c.header("Add new manager")
    username = _read_new_username(app)
    if username is None:
        return
    password = _read_new_password("Initial password")
    if password is None:
        return
    first = c.read_field("First name", v.is_valid_name, _NAME_HELP)
    if first is None:
        return
    last = c.read_field("Last name", v.is_valid_name, _NAME_HELP)
    if last is None:
        return
    app.user_service.add_manager(app.auth.current_user, username, password,
                                 first, last)
    c.success("Manager created.")


def update_manager(app):
    target = _select_user(app, config.ROLE_MANAGER, "Choose manager to update")
    if target is None:
        return
    first = c.read_field("First name", v.is_valid_name, _NAME_HELP, optional=True)
    last = c.read_field("Last name", v.is_valid_name, _NAME_HELP, optional=True)
    names = {}
    if first:
        names["first_name"] = first
    if last:
        names["last_name"] = last
    app.user_service.update_manager(app.auth.current_user, target["id"], names)
    c.success("Manager updated.")


def delete_manager(app):
    target = _select_user(app, config.ROLE_MANAGER, "Choose manager to delete")
    if target is None:
        return
    if not c.confirm(f"Delete manager {target['username']}?"):
        return
    app.user_service.delete_manager(app.auth.current_user, target["id"])
    c.success("Manager deleted.")


def reset_manager_password(app):
    target = _select_user(app, config.ROLE_MANAGER, "Choose manager")
    if target is None:
        return
    temp = app.user_service.reset_manager_password(app.auth.current_user,
                                                   target["id"])
    c.success(f"Temporary password for {target['username']}: {temp}")


# ===========================================================================
# Claim-acties
# ===========================================================================
def add_claim(app):
    c.header("Add new claim")
    data = _collect_claim_data()
    if data is None:
        return
    claim_id = app.claim_service.add_claim(app.auth.current_user, data)
    c.success(f"Claim {claim_id} added (status: Pending).")


def _render_claim(claim):
    if claim["locked"]:
        locked_label = "[locked]"
    else:
        locked_label = ""
    return (f"#{claim['id']} {claim['claim_date']} {claim['claim_type']} "
            f"proj={claim['project_number']} status={claim['approved']} "
            f"{locked_label}")


def view_my_claims(app):
    claims = app.claim_service.list_own_claims(app.auth.current_user)
    c.header(f"My claims ({len(claims)})")
    for claim in claims:
        print("  " + _render_claim(claim))


def update_my_claim(app):
    claims = []
    for cl in app.claim_service.list_own_claims(app.auth.current_user):
        if not cl["locked"]:
            claims.append(cl)
    claim = c.pick_from_list(claims, _render_claim, "Choose claim to update")
    if claim is None:
        return
    data = _collect_claim_data()
    if data is None:
        return
    app.claim_service.update_own_claim(app.auth.current_user, claim["id"], data)
    c.success("Claim updated.")


def delete_my_claim(app):
    claims = []
    for cl in app.claim_service.list_own_claims(app.auth.current_user):
        if not cl["locked"]:
            claims.append(cl)
    claim = c.pick_from_list(claims, _render_claim, "Choose claim to delete")
    if claim is None:
        return
    if not c.confirm(f"Delete claim #{claim['id']}?"):
        return
    app.claim_service.delete_own_claim(app.auth.current_user, claim["id"])
    c.success("Claim deleted.")


def search_my_claims(app):
    key = c.read_field("Search term (partial is allowed)", v.is_valid_search_key,
                       _SEARCH_HELP)
    if key is None:
        return
    results = app.claim_service.search_own_claims(app.auth.current_user, key)
    c.header(f"{len(results)} claim(s) found")
    for claim in results:
        print("  " + _render_claim(claim))


def search_claims(app):
    key = c.read_field("Search term (partial is allowed)", v.is_valid_search_key,
                       _SEARCH_HELP)
    if key is None:
        return
    results = app.claim_service.search_claims(app.auth.current_user, key)
    c.header(f"{len(results)} claim(s) found")
    for claim in results:
        print("  " + _render_claim(claim))


def modify_claim(app):
    # Een claim in een salaris-batch (locked) is afgehandeld; die tonen we niet.
    claims = []
    for cl in app.claim_service.list_all_claims(app.auth.current_user):
        if not cl["locked"]:
            claims.append(cl)
    claim = c.pick_from_list(claims, _render_claim, "Choose claim to modify")
    if claim is None:
        return
    c.info("Leave a field empty to keep it unchanged.")
    project = c.read_field("New project number", v.is_valid_project_number,
                           "A project number consists of 2 to 10 digits.",
                           optional=True)
    distance = None
    if claim["claim_type"] == "Travel":
        distance = c.read_field("New travel distance (km)", v.is_valid_distance,
                                "Only digits and greater than 0.", optional=True)
    app.claim_service.modify_claim(app.auth.current_user, claim["id"],
                                   project_number=project, distance=distance)
    c.success("Claim modified.")


def approve_claim(app):
    claims = []
    for cl in app.claim_service.list_all_claims(app.auth.current_user):
        if cl["approved"] == "Pending":
            claims.append(cl)
    claim = c.pick_from_list(claims, _render_claim, "Choose claim to approve")
    if claim is None:
        return
    batch = c.read_field("Salary batch (YYYY-MM)", v.is_valid_salary_batch,
                         "Use format YYYY-MM, e.g. 2026-07.")
    if batch is None:
        return
    app.claim_service.approve_claim(app.auth.current_user, claim["id"], batch)
    c.success("Claim approved and added to salary batch.")


def reject_claim(app):
    claims = []
    for cl in app.claim_service.list_all_claims(app.auth.current_user):
        if cl["approved"] == "Pending":
            claims.append(cl)
    claim = c.pick_from_list(claims, _render_claim, "Choose claim to reject")
    if claim is None:
        return
    app.claim_service.reject_claim(app.auth.current_user, claim["id"])
    c.success("Claim rejected.")


# ===========================================================================
# Systeem-acties (backup / restore / logs)
# ===========================================================================
def create_backup(app):
    name = app.backup_service.create_backup(app.auth.current_user)
    c.success(f"Backup created: {name}")


def restore_any_backup(app):
    backups = app.backup_service.list_backups(app.auth.current_user)
    name = c.pick_from_list(backups, lambda x: x, "Choose backup to restore")
    if name is None:
        return
    if not c.confirm(f"Restore {name}? This overwrites the current data."):
        return
    app.backup_service.restore_any(app.auth.current_user, name)
    c.success("Backup restored.")
    _check_session_after_restore(app)


def restore_with_code(app):
    code = c.read_field("Enter your restore code", v.is_valid_search_key, _SEARCH_HELP)
    if code is None:
        return
    if not c.confirm("Restore now? This overwrites the current data."):
        return
    app.backup_service.restore_with_code(app.auth.current_user, code)
    c.success("Backup restored.")
    _check_session_after_restore(app)


def _check_session_after_restore(app):
    """Bewaak de sessie na een restore (de hele database is vervangen).

    1. Account bestaat niet meer / komt niet meer overeen -> uitloggen.
    2. Account staat met een tijdelijk wachtwoord -> uitloggen, zodat de
       tijdelijk-wachtwoord-flow bij de volgende login grijpt.
    """
    if not app.auth.revalidate_session():
        c.error("Your account no longer exists in the restored database. "
                "You will be logged out for security reasons.")
        return
    user = app.auth.current_user
    if user and user.get("must_change_password"):
        app.log_service.log(
            user["username"],
            "Logged out after restore (account requires a password change)")
        app.auth.current_user = None
        c.error("The restored data marks your account as requiring a password "
                "change. You will be logged out; please log in again.")


def generate_restore_code(app):
    manager = _select_user(app, config.ROLE_MANAGER, "Choose manager")
    if manager is None:
        return
    backups = app.backup_service.list_backups(app.auth.current_user)
    name = c.pick_from_list(backups, lambda x: x, "Choose backup for this code")
    if name is None:
        return
    code = app.backup_service.generate_restore_code(
        app.auth.current_user, manager["id"], name)
    c.success(f"One-use restore code for {manager['username']}: {code}")


def revoke_restore_code(app):
    manager = _select_user(app, config.ROLE_MANAGER, "Choose manager")
    if manager is None:
        return
    code = c.read_field("Restore code to revoke", v.is_valid_search_key, _SEARCH_HELP)
    if code is None:
        return
    ok = app.backup_service.revoke_restore_code(app.auth.current_user,
                                                code, manager["id"])
    if ok:
        c.success("Restore code revoked.")
    else:
        c.success("No active code found.")


def view_logs(app):
    az.require(app.auth.current_user, az.VIEW_LOGS)
    logs = app.log_service.get_logs()
    c.header(f"Activity log ({len(logs)} entries)")
    print(f"  {'No.':>3} {'Date':<10} {'Time':<8} {'Username':<12} "
          f"{'Susp.':<5} Description / Info")
    for entry in logs:
        if entry["suspicious"]:
            flag = "YES"
        else:
            flag = "no"
        desc = entry["description"]
        if entry["info"]:
            desc += f" | {entry['info']}"
        print(f"  {entry['no']:>3} {entry['date']:<10} {entry['time']:<8} "
              f"{entry['username'][:12]:<12} {flag:<5} {desc}")
    app.log_service.mark_all_read()


# ===========================================================================
# Menu-definities per rol
# ===========================================================================
def _show_menu(title, options):
    c.header(title)
    for key, label, _ in options:
        print(f"  {key}. {label}")
    print("  0. Log out")


def _dispatch(app, options):
    """Toon het menu en voer de gekozen actie uit, tot de gebruiker uitlogt."""
    while app.auth.is_logged_in():
        title = f"{app.auth.current_user['role'].upper()} MENU " \
                f"({app.auth.current_user['username']})"
        _show_menu(title, options)
        choice = c.read_menu_choice()
        if choice == "0":
            app.auth.logout()
            return
        matched = None
        for option in options:
            if option[0] == choice:
                matched = option
                break
        if matched is None:
            c.error("Unknown choice.")
            continue
        key, label, action = matched          # tuple uitpakken in namen
        _run(app, lambda: action(app))


def employee_menu(app):
    options = [
        ("1", "Change my password", change_own_password),
        ("2", "Add new claim", add_claim),
        ("3", "View my claims", view_my_claims),
        ("4", "Search my claims", search_my_claims),
        ("5", "Update one of my claims", update_my_claim),
        ("6", "Delete one of my claims", delete_my_claim),
    ]
    _dispatch(app, options)


def manager_menu(app):
    options = [
        ("1", "Change my password", change_own_password),
        ("2", "Update my account", update_own_account),
        ("3", "Delete my account", delete_own_account),
        ("4", "Add employee", add_employee),
        ("5", "Update employee", update_employee),
        ("6", "Delete employee", delete_employee),
        ("7", "Reset employee password", reset_employee_password),
        ("8", "Search employees", search_employees),
        ("9", "Search / view claims", search_claims),
        ("10", "Modify claim (project no. / distance)", modify_claim),
        ("11", "Approve claim", approve_claim),
        ("12", "Reject claim", reject_claim),
        ("13", "Create backup", create_backup),
        ("14", "Restore backup (with code)", restore_with_code),
        ("15", "View logs", view_logs),
    ]
    _dispatch(app, options)


def super_admin_menu(app):
    options = [
        ("1", "Add manager", add_manager),
        ("2", "Update manager", update_manager),
        ("3", "Delete manager", delete_manager),
        ("4", "Reset manager password", reset_manager_password),
        ("5", "Add employee", add_employee),
        ("6", "Update employee", update_employee),
        ("7", "Delete employee", delete_employee),
        ("8", "Reset employee password", reset_employee_password),
        ("9", "Search employees", search_employees),
        ("10", "Search / view claims", search_claims),
        ("11", "Modify claim (project no. / distance)", modify_claim),
        ("12", "Approve claim", approve_claim),
        ("13", "Reject claim", reject_claim),
        ("14", "Create backup", create_backup),
        ("15", "Restore any backup", restore_any_backup),
        ("16", "Generate restore code", generate_restore_code),
        ("17", "Revoke restore code", revoke_restore_code),
        ("18", "View logs", view_logs),
    ]
    _dispatch(app, options)


def run_for_role(app):
    role = app.auth.current_user["role"]
    if role == config.ROLE_SUPER_ADMIN:
        super_admin_menu(app)
    elif role == config.ROLE_MANAGER:
        manager_menu(app)
    else:
        employee_menu(app)
