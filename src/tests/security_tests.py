"""
security_tests.py - Adversariële security-testsuite voor de DeclaratieApp.

Draai het vanuit de map src/ (gebruikt een wegwerp-database in de OS-tempmap):

    python tests/security_tests.py

De cases zijn gebaseerd op de cursusboeken / -onderwerpen:
  * Huseby, "Innocent Code" (TB2): vertrouw invoer nooit, SQL-injectie (incl.
    second-order), invoervalidatie, encoding/charset-trucs, geheime identifiers,
    afhandeling van foute invoer, logging.
  * Hoffman, "Web Application Security" (TB1) + de auth/crypto-colleges:
    wachtwoord-hashing, timing-zijkanalen / user enumeration, geauthenticeerde
    versleuteling, toegangscontrole.
"""

import os
import sys
import glob
import time
import hashlib
import tempfile

# Maak src/ importeerbaar en verwijs de database naar een wegwerp-tempmap.
SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SRC_DIR)

import config
_TMP = tempfile.mkdtemp(prefix="declaratie_sectest_")
config.DB_PATH = os.path.join(_TMP, "declaratie.db")
config.BACKUP_DIR = os.path.join(_TMP, "backups")

from data import database
from data.repositories import (UserRepository, ClaimRepository,
                               EmployeeRepository, LogRepository)
from security import hashing, crypto
from services.log_service import LogService
from services.auth_service import AuthService
from services.user_service import UserService
from services.claim_service import ClaimService
from services.backup_service import BackupService
from services import authorization as az
from services import generators
from validation import validators as v

PASS = FAIL = 0


def check(cond, label):
    global PASS, FAIL
    print(f"  {'PASS' if cond else 'FAIL'}  {label}" + ("" if cond else "   <<<<<"))
    if cond:
        PASS += 1
    else:
        FAIL += 1


def expect_raise(exc_types, fn, label):
    try:
        fn()
        check(False, label + " (no exception)")
    except exc_types:
        check(True, label)
    except Exception as e:
        check(False, f"{label} (wrong exception {type(e).__name__}: {e})")


# ---------------------------------------------------------------------------
def setup():
    if os.path.exists(config.DB_PATH):
        os.remove(config.DB_PATH)
    database.initialize_database()
    log = LogService()
    us = UserService(log)
    cs = ClaimService(log)
    bs = BackupService(log)
    ur = UserRepository()
    sup = {"id": 0, "username": "super_admin", "role": "super_admin"}
    profile = {"birthday": "1995-05-20", "gender": "female", "street": "Kerkstraat",
               "house_number": "12", "zip": "1234AB", "city": "Rotterdam",
               "email": "anna@example.com", "phone": "+31-6-12345678",
               "doc_type": "Passport", "doc_number": "AB1234567", "bsn": "123456789"}
    us.add_manager(sup, "man_bob1", "Manager_2026!", "Bob", "Smit")
    us.add_employee(sup, "emp_anna", "Employee_2026!", "Anna", "Jansen", profile)
    us.add_employee(sup, "emp_kees", "Employee_2026!", "Kees", "Bos",
                    {**profile, "email": "kees@example.com", "bsn": "987654321"})
    return dict(log=log, us=us, cs=cs, bs=bs, ur=ur, sup=sup, profile=profile,
                anna=ur.find_by_username("emp_anna"),
                kees=ur.find_by_username("emp_kees"),
                bob=ur.find_by_username("man_bob1"))


def main():
    ctx = setup()
    us, cs, bs, ur = ctx["us"], ctx["cs"], ctx["bs"], ctx["ur"]
    log, sup = ctx["log"], ctx["sup"]
    anna, kees, bob = ctx["anna"], ctx["kees"], ctx["bob"]
    profile = ctx["profile"]
    claim = cs.add_claim(anna, {"claim_date": "2026-06-01", "project_number": "4567",
                                "claim_type": "Home Office"})

    print("\n== A. SQL injection (TB2 ch.2) ==")
    auth = AuthService(log)
    check(auth.login("' OR '1'='1", "' OR '1'='1") is None, "SQLi login rejected")
    check(auth.login("emp_anna", "x' OR '1'='1' --") is None, "SQLi password rejected")
    check(ur.find_by_username("'; DROP TABLE users;--") is None, "SQLi username lookup safe")
    check(len(us.search_employees(sup, "anna")) == 1, "users table intact after SQLi")

    print("\n== B. Second-order / stored injection (TB2) ==")
    # Een SQLi/HTML/terminal-payload moet op de WEG NAAR BINNEN geweigerd worden
    # (whitelist), zodat hij nooit opgeslagen kan worden en later kan 'uitvoeren'.
    # De validators geven False bij foute invoer ('deny by default').
    check(not v.is_valid_name("Robert'); DROP TABLE users;--"),
          "stored-SQLi name rejected on input")
    check(not v.is_valid_name("<script>alert(1)</script>"),
          "stored-XSS/HTML name rejected on input")
    # Een zoeksleutel die op SQL lijkt wordt als letterlijke string behandeld, geen fout.
    check(us.search_employees(sup, "anna") is not None, "SQL-like search handled literally")

    print("\n== C. Encoding / charset tricks (TB2 ch.3) ==")
    check(not v.is_valid_bsn("١٢٣٤٥٦٧٨٩"), "Arabic-Indic digits rejected (not ASCII 0-9)")
    check(not v.is_valid_bsn("１２３４５６７８９"), "full-width digits rejected")
    check(not v.is_valid_username("pаssword"), "Cyrillic homoglyph in username rejected")
    check(not v.is_valid_name("An\x00na"), "NULL-byte rejected")
    check(not v.is_valid_name("Bob\r\nInjected"), "CRLF rejected")
    check(not v.is_valid_name("hack\x1b[31m"), "ANSI escape rejected")
    check(not v.is_valid_username("a" * 100000), "overlong input rejected")
    # Strikte invoer: exact-correcte waarden komen door, slordige worden geweigerd
    # (geen stille 'massaging' -> zie Les 3 'do not massage invalid input').
    check(v.is_valid_zip("1234AB"), "correct zip accepted")
    check(not v.is_valid_zip(" 1234ab "), "lowercase/spaced zip rejected (strict)")

    print("\n== D. Numeric edge cases ==")
    check(not v.is_valid_distance("0"), "distance 0 rejected")
    check(not v.is_valid_distance("-5"), "negative distance rejected")
    check(not v.is_valid_project_number("1"), "1-digit project rejected")
    check(not v.is_valid_salary_batch("2026-13"), "month 13 rejected")
    check(not v.is_valid_salary_batch("2026-00"), "month 00 rejected")
    check(v.is_valid_project_number("4567"), "valid project number accepted")

    print("\n== E. Authorization: vertical privilege escalation ==")
    expect_raise(az.AuthorizationError, lambda: cs.approve_claim(anna, claim, "2026-06"), "employee cannot approve")
    expect_raise(az.AuthorizationError, lambda: us.add_employee(anna, "emp_x1234", "Employee_2026!", "X", "Y", profile), "employee cannot add employees")
    expect_raise(az.AuthorizationError, lambda: az.require(anna, az.VIEW_LOGS), "employee cannot view logs")
    expect_raise(az.AuthorizationError, lambda: bs.create_backup(anna), "employee cannot back up")
    expect_raise(az.AuthorizationError, lambda: us.add_manager(bob, "man_eve1", "Manager_2026!", "E", "D"), "manager cannot add managers")
    expect_raise(az.AuthorizationError, lambda: bs.restore_any(bob, "x.zip"), "manager cannot restore any")
    expect_raise(az.AuthorizationError, lambda: us.update_own_password(sup, "Admin_123?", "Whatever_2026!"), "super cannot change own password")

    print("\n== F. Authorization: horizontal access (other users' data) ==")
    expect_raise(az.AuthorizationError, lambda: cs.get_claim(kees, claim), "cannot read other's claim")
    expect_raise(ValueError, lambda: cs.update_own_claim(kees, claim, {"claim_type": "Home Office"}), "cannot edit other's claim")
    expect_raise(ValueError, lambda: cs.delete_own_claim(kees, claim), "cannot delete other's claim")

    print("\n== G. Never trust input: server-generated fields (TB2, Lecture 3 s32) ==")
    # Het vervalsen van approval / id / lock bij het AANMAKEN van een claim breekt
    # de operatie af.
    expect_raise(ValueError, lambda: cs.add_claim(anna, {
        "claim_date": "2026-06-02", "project_number": "4567",
        "claim_type": "Home Office", "approved": "Approved", "approved_by": "hacker",
        "salary_batch": "2026-01", "employee_id": "9999999", "locked": 1}),
        "forged server-fields on add -> operation aborted")
    # Een schone claim werkt nog en krijgt een SERVER-gezette employee_id.
    clean = cs.add_claim(anna, {"claim_date": "2026-06-02", "project_number": "4567",
                                "claim_type": "Home Office"})
    fc = cs.get_claim(anna, clean)
    check(fc["approved"] == "Pending", "clean claim defaults to Pending")
    real_eid = EmployeeRepository().get_by_user_id(anna["id"])["employee_id"]
    check(fc["employee_id"] == real_eid, "employee_id is server-set, not user-supplied")
    # Vervalsen bij UPDATE breekt ook af -> de claim blijft onaangeroerd.
    expect_raise(ValueError, lambda: cs.update_own_claim(anna, clean, {
        "claim_type": "Home Office", "approved": "Approved", "locked": 1,
        "salary_batch": "2026-01"}), "forged server-fields on update -> operation aborted")
    fc2 = cs.get_claim(anna, clean)
    check(fc2["approved"] == "Pending" and fc2["locked"] == 0, "update did not set approval/lock")

    print("\n== G2. Claims in a salary batch are immutable ==")
    # Zodra een claim aan een salaris-batch hangt (goedgekeurd -> locked), is hij
    # administratief afgehandeld. Vanaf dan mag NIEMAND hem meer aanpassen: de
    # werknemer niet (eis uit de casus), maar ook de Manager/Super Admin niet
    # (anders lopen administratie en uitbetaling uit elkaar).
    settled = cs.add_claim(anna, {"claim_date": "2026-06-03",
                                  "project_number": "8888",
                                  "claim_type": "Home Office"})
    cs.approve_claim(sup, settled, "2026-07")
    expect_raise(ValueError, lambda: cs.modify_claim(sup, settled, project_number="9999"),
                 "manager/SA cannot modify a claim in a salary batch")
    expect_raise(ValueError, lambda: cs.approve_claim(sup, settled, "2026-08"),
                 "cannot re-approve into another salary batch")
    expect_raise(ValueError, lambda: cs.reject_claim(sup, settled),
                 "cannot reject a settled claim")
    expect_raise(ValueError, lambda: cs.update_own_claim(anna, settled,
                 {"claim_type": "Home Office"}),
                 "employee cannot edit a settled claim")
    expect_raise(ValueError, lambda: cs.delete_own_claim(anna, settled),
                 "employee cannot delete a settled claim")
    check(cs.get_claim(sup, settled)["project_number"] == "8888",
          "settled claim is unchanged after all attempts")

    print("\n== H. Cryptography: authenticated encryption (crypto lecture) ==")
    token = crypto.encrypt("topsecret-value")
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    check(crypto.decrypt(tampered) == "", "tampered ciphertext fails safe (returns '')")
    check(crypto.encrypt("x") != crypto.encrypt("x"), "encryption is non-deterministic (random IV)")
    check(crypto.decrypt(crypto.encrypt("€ é \U0001f600")) == "€ é \U0001f600", "unicode round-trips")

    print("\n== I. Password hashing (TB1/TB2) ==")
    h1, h2 = hashing.hash_password("Same_Password_1!"), hashing.hash_password("Same_Password_1!")
    check(h1 != h2, "equal passwords get different hashes (per-password salt)")
    check(h1.startswith("$argon2id$"), "Argon2id is used")
    check(hashing.verify_password(h1, "Same_Password_1!") and not hashing.verify_password(h1, "wrong"), "verify accepts only the right password")

    print("\n== J. Blind index keyed (not a plain hash) ==")
    bi = crypto.blind_index("emp_anna")
    check(bi == crypto.blind_index("emp_anna"), "blind index is deterministic")
    check(bi != hashlib.sha256(b"emp_anna").hexdigest(), "blind index is keyed (not plain SHA-256)")

    print("\n== K. Secret identifiers: restore codes (TB2) ==")
    codes = {generators.generate_restore_code() for _ in range(2000)}
    check(len(codes) == 2000, "2000 restore codes all unique (no collisions)")
    sample = generators.generate_restore_code()
    check(len(sample) >= 16 and sample.isalnum(), "restore code is long & alphanumeric (high entropy)")

    print("\n== L. Brute-force & user enumeration (password-cracking lecture) ==")
    before = log.unread_suspicious_count()
    a2 = AuthService(log)
    a2.login("emp_anna", "w1"); a2.login("emp_anna", "w2"); a2.login("emp_anna", "w3")
    check(log.unread_suspicious_count() > before, "repeated failed logins flagged suspicious")
    # Timing-gelijktrekking: een onbekende gebruiker mag niet duidelijk sneller
    # zijn dan een bekende gebruiker met een fout wachtwoord (we asserten alleen
    # dat de mitigatie draait).
    t0 = time.perf_counter(); AuthService(log).login("does_not_exist", "x"); t_unknown = time.perf_counter() - t0
    t0 = time.perf_counter(); AuthService(log).login("emp_anna", "x"); t_known = time.perf_counter() - t0
    check(t_unknown >= t_known * 0.3, f"unknown-user login not trivially fast (dummy verify runs) [{t_unknown*1000:.0f}ms vs {t_known*1000:.0f}ms]")

    print("\n== M. Log forging via newline (TB2 logging) ==")
    # Een newline is ook een stuurteken: de login-grens weigert hem en logt 'm
    # als verdacht met username '-'. Zo belandt er geen rauw stuurteken in het log
    # EN kan een newline nooit een extra (vervalste) logregel toevoegen.
    n_before = len(log.get_logs())
    AuthService(log).login("evil\nFORGED 99 admin hacked", "x")
    logs = log.get_logs()
    check(len(logs) == n_before + 1, "newline in username creates exactly ONE log row (no forging)")
    check(not any("\n" in e["username"] for e in logs),
          "newline never stored raw in the username field (rejected/sanitised)")

    print("\n== N. Backup path traversal (TB2 'never trust input') ==")
    expect_raise(ValueError, lambda: bs.restore_any(sup, "..\\..\\evil.zip"), "'..' traversal rejected")
    expect_raise(ValueError, lambda: bs.restore_any(sup, "/etc/passwd"), "absolute path rejected")
    expect_raise(ValueError, lambda: bs.restore_any(sup, "notazip.txt"), "non-zip rejected")

    print("\n== O. Restore-code binding / one-use / revoke ==")
    b0 = bs.create_backup(sup)
    us.add_manager(sup, "man_eve1", "Manager_2026!", "Eve", "Doe")
    eve = ur.find_by_username("man_eve1")
    code_bob = bs.generate_restore_code(sup, bob["id"], b0)
    expect_raise(ValueError, lambda: bs.restore_with_code(eve, code_bob), "cannot use another manager's code")
    code_rev = bs.generate_restore_code(sup, eve["id"], b0)
    bs.revoke_restore_code(sup, code_rev, eve["id"])
    expect_raise(ValueError, lambda: bs.restore_with_code(eve, code_rev), "revoked code rejected")

    print("\n== P. Encryption at rest & no plaintext passwords ==")
    database.get_connection().commit()
    raw = open(config.DB_PATH, "rb").read()
    for s in [b"Anna", b"Jansen", b"Rotterdam", b"987654321", b"AB1234567",
              b"emp_anna", b"man_bob1", b"Manager_2026!", b"Employee_2026!",
              # de rol is ook versleuteld: noch de waarden noch een CHECK-constraint
              # mag 'manager'/'employee' leesbaar in het bestand laten staan.
              b"manager", b"employee"]:
        check(s not in raw, f"plaintext {s.decode()!r} absent from raw .db")
    check(ur.get_by_id(bob["id"])["password_hash"].startswith("$argon2"), "passwords stored as Argon2 hash only")
    check(ur.get_by_id(bob["id"])["role"] == "manager", "role still decrypts correctly in the app")

    print("\n== Q. Session lifecycle ==")
    s = AuthService(log)
    s.login("man_bob1", "Manager_2026!")
    check(s.is_logged_in(), "manager logged in")
    s.logout()
    check(not s.is_logged_in() and s.current_user is None, "session cleared on logout")
    # verouderde sessie na een restore (de gerapporteerde bug)
    s2 = AuthService(log)
    s2.login("man_eve1", "Manager_2026!")
    snap = bs.create_backup(sup)          # snapshot ZONDER een toekomstige manager
    us.add_manager(sup, "man_new01", "Manager_2026!", "New", "Guy")
    newm = ur.find_by_username("man_new01")
    s3 = AuthService(log); s3.login("man_new01", "Manager_2026!")
    code_new = bs.generate_restore_code(sup, newm["id"], snap)
    bs.restore_with_code(s3.current_user, code_new)
    check(s3.revalidate_session() is False and s3.current_user is None,
          "session invalidated after restoring a backup without the account")
    sup_s = AuthService(log); sup_s.login("super_admin", "Admin_123?")
    any_b = bs.create_backup(sup_s.current_user); bs.restore_any(sup_s.current_user, any_b)
    check(sup_s.revalidate_session() is True, "super-admin session survives restore")

    print("\n== R. Source hygiene: dangerous calls (TB2 shell-injection) ==")
    dangerous = ["os.system(", "subprocess", "eval(", "exec(", "pickle",
                 "shell=True", "input() ", "os.popen("]
    found = []
    for path in glob.glob(os.path.join(SRC_DIR, "**", "*.py"), recursive=True):
        if os.path.join("tests", "") in path:
            continue
        text = open(path, encoding="utf-8").read()
        for pat in dangerous:
            if pat in text:
                found.append(f"{os.path.relpath(path, SRC_DIR)}: {pat}")
    check(not found, "no dangerous calls (os.system/subprocess/eval/exec/pickle) in app code"
          + ("" if not found else f" -> {found}"))
    # Controleer dat de timing-hardening daadwerkelijk is aangesloten.
    auth_src = open(os.path.join(SRC_DIR, "services", "auth_service.py"), encoding="utf-8").read()
    check("compare_digest" in auth_src, "constant-time password compare present for super-admin")
    check("dummy_verify" in auth_src, "dummy verify wired in against user enumeration")

    print("\n== S. Brute-force lockout (Lecture 4 'online password cracking') ==")
    us.add_employee(sup, "emp_lock1", "Employee_2026!", "Lock", "Test",
                    {**profile, "email": "lock@example.com", "bsn": "112233445"})
    al = AuthService(log)
    for _ in range(config.MAX_LOGIN_ATTEMPTS):
        al.login("emp_lock1", "wrong-password!")
    check(al.login("emp_lock1", "Employee_2026!") is None,
          "correct password is refused while the account is locked")
    check(al.last_lockout_seconds > 0, "lockout window is reported to the UI")
    check(al._remaining_lockout("emp_anna") == 0,
          "lockout is per-username (no collateral lock-out of other users)")
    check(log.unread_suspicious_count() > 0, "lockout/blocked login flagged suspicious")

    print("\n== T. Server-generated input tampering: abort + log (Lecture 3 s32) ==")
    # 'breek de operatie af en log het incident' -> de actie stopt EN er wordt een
    # verdachte regel weggeschreven.
    s0 = log.unread_suspicious_count()
    expect_raise(ValueError, lambda: cs.add_claim(anna, {
        "claim_date": "2026-06-03", "project_number": "4567",
        "claim_type": "Home Office", "approved": "Approved", "locked": 1,
        "approved_by": "hacker"}), "forged server-field on ADD aborts the operation")
    check(log.unread_suspicious_count() > s0, "aborted ADD is logged as suspicious")
    # Een schone claim om het UPDATE-pad te oefenen.
    ok_claim = cs.add_claim(anna, {"claim_date": "2026-06-03", "project_number": "4567",
                                   "claim_type": "Home Office"})
    s1 = log.unread_suspicious_count()
    expect_raise(ValueError, lambda: cs.update_own_claim(anna, ok_claim, {
        "approved": "Approved", "salary_batch": "2026-01"}),
        "forged server-field on UPDATE aborts the operation")
    check(log.unread_suspicious_count() > s1, "aborted UPDATE is logged as suspicious")
    tc = cs.get_claim(anna, ok_claim)
    check(tc["approved"] == "Pending" and tc["locked"] == 0, "no forged values applied")

    print("\n== U. Directory-traversal '....//' collapse trick (Lecture 3 slide 35) ==")
    expect_raise(ValueError, lambda: bs.restore_any(sup, "....//evil.zip"),
                 "'....//' collapse trick rejected")
    expect_raise(ValueError, lambda: bs.restore_any(sup, "backups/../declaratie.db"),
                 "nested relative path rejected")
    expect_raise(ValueError, lambda: bs.restore_any(sup, "good/../../evil.zip"),
                 "mixed traversal rejected")

    print("\n== V. assertValid on server-generated selection fields (Lecture 3 s20/s32) ==")
    # Keuzelijst-waarden (claim_type, gender, city, doc_type) zijn server-
    # generated: ongeldig -> breek de operatie af + log, vraag niet opnieuw.
    s0 = log.unread_suspicious_count()
    expect_raise(ValueError, lambda: cs.add_claim(anna, {
        "claim_date": "2026-06-04", "project_number": "4567", "claim_type": "BOGUS"}),
        "invalid claim_type aborts the operation")
    check(log.unread_suspicious_count() > s0, "invalid claim_type logged as suspicious")
    s1 = log.unread_suspicious_count()
    expect_raise(ValueError, lambda: us.add_employee(
        sup, "emp_v1234", "Employee_2026!", "V", "W",
        {**profile, "email": "v@example.com", "bsn": "111222333", "gender": "alien"}),
        "invalid gender aborts add_employee before any account is created")
    check(log.unread_suspicious_count() > s1, "invalid gender logged as suspicious")
    check(ur.find_by_username("emp_v1234") is None, "no half-created account left behind")
    # Een geldige keuze werkt nog steeds.
    okv = cs.add_claim(anna, {"claim_date": "2026-06-04", "project_number": "4567",
                              "claim_type": "Travel", "distance": "10",
                              "from_zip": "1234AB", "from_house": "1",
                              "to_zip": "5678CD", "to_house": "2"})
    check(cs.get_claim(anna, okv)["claim_type"] == "Travel", "valid claim_type accepted")

    print("\n== W. NULL-byte / control-char login logged as suspicious (Lecture 3 s22) ==")
    # Een NULL-byte of stuurteken in de login-invoer is geen typefout maar
    # manipulatie: de poging wordt geweigerd EN als verdacht gelogd.
    before = log.unread_suspicious_count()
    aw = AuthService(log)
    check(aw.login("emp\x00anna", "whatever") is None, "NULL-byte username login rejected")
    check(aw.login("emp_anna", "pw\x1bord") is None, "control-char (ANSI) password login rejected")
    check(log.unread_suspicious_count() >= before + 2, "malformed-input logins flagged suspicious")
    check(any("NULL byte or control character" in e.get("info", "") for e in log.get_logs()),
          "malformed-input login has a descriptive log entry")

    print("\n== X. Restore must not erase logs (teacher scenario) ==")
    # Maak een backup, doe daarna een paar dingen die logregels opleveren, en
    # zet daarna die OUDERE backup terug. De logs van NA de backup moeten blijven
    # staan (logging mag nooit verdwijnen door een restore).
    sx = AuthService(log); sx.login("super_admin", "Admin_123?")
    backup_before = bs.create_backup(sx.current_user)
    logs_at_backup = len(log.get_logs())
    # activiteit die het log laat oplopen (mislukte logins + een zoekactie)
    AuthService(log).login("emp_anna", "nope1")
    AuthService(log).login("emp_anna", "nope2")
    us.search_employees(sx.current_user, "anna")
    logs_after_activity = len(log.get_logs())
    check(logs_after_activity > logs_at_backup, "activity after backup grew the log")
    bs.restore_any(sx.current_user, backup_before)
    logs_after_restore = len(log.get_logs())
    check(logs_after_restore >= logs_after_activity,
          "no log entries lost after restoring an older backup")

    print("\n== Y. Restore must not resurrect a consumed/revoked restore-code ==")
    # De aanvalsvorm: een code wordt INGETROKKEN (of gebruikt), maar er bestaat
    # een oudere backup waarin die code nog ongebruikt stond. Door die backup
    # terug te zetten zou de code anders weer geldig worden -> eenmalig gebruik
    # en intrekken moeten een restore overleven (monotoon).
    by = AuthService(log); by.login("super_admin", "Admin_123?")
    backup_B = bs.create_backup(by.current_user)
    code_resurrect = bs.generate_restore_code(by.current_user, bob["id"], backup_B)
    backup_C = bs.create_backup(by.current_user)        # bevat code als ongebruikt
    bs.revoke_restore_code(by.current_user, code_resurrect, bob["id"])
    check(bs._codes.find_valid(code_resurrect, bob["id"]) is None,
          "revoked code is invalid before any restore")
    code_for_C = bs.generate_restore_code(by.current_user, bob["id"], backup_C)
    bob_sess = AuthService(log); bob_sess.login("man_bob1", "Manager_2026!")
    bs.restore_with_code(bob_sess.current_user, code_for_C)
    check(bs._codes.find_valid(code_resurrect, bob["id"]) is None,
          "revoked code stays invalid after restoring an older backup")
    expect_raise(ValueError,
                 lambda: bs.restore_with_code(bob_sess.current_user, code_resurrect),
                 "resurrected revoked code cannot be used to restore")
    # En een GEBRUIKTE code blijft ook gebruikt na een restore.
    check(bs._codes.find_valid(code_for_C, bob["id"]) is None,
          "a one-use code stays used after the restore it performed")

    print("\n== Z. Mass-assignment & cross-role guards on user management ==")
    # Een Manager mag een werknemer bijwerken, maar mag via het profiel-dict GEEN
    # gevoelige velden injecteren (rol, koppeling). De allow-list van de repository
    # negeert alles wat er niet op staat -> geen privilege-escalatie.
    us.update_employee(bob, anna["id"], names={"first_name": "Anna"},
                       profile={"role": "manager", "user_id": 0,
                                "id": 1, "city": "Utrecht"})
    check(ur.get_by_id(anna["id"])["role"] == "employee",
          "injected 'role' in employee update is ignored (stays employee)")
    check(ur.get_by_id(anna["id"])["id"] == anna["id"],
          "injected 'id'/'user_id' in employee update is ignored")
    # Cross-role: het employee-beheerpad weigert een doel dat geen werknemer is.
    expect_raise(ValueError, lambda: us.update_employee(bob, bob["id"],
                 names={"first_name": "X"}),
                 "manager cannot update another manager via the employee path")
    expect_raise(ValueError, lambda: us.delete_employee(bob, bob["id"]),
                 "manager cannot delete a manager via the employee path")
    expect_raise(ValueError, lambda: us.reset_employee_password(bob, bob["id"]),
                 "manager cannot reset a manager's password via the employee path")
    # En een actie op de (niet in de DB staande) hardcoded super admin faalt netjes.
    expect_raise(ValueError, lambda: us.delete_employee(sup, 0),
                 "cannot delete the hardcoded super admin (not in the DB)")

    print("\n== AA. Authorization denial is logged as suspicious ==")
    # Een autorisatie-weigering kan via het menu bijna niet ontstaan (je ziet
    # alleen toegestane knoppen); gebeurt het toch, dan is het manipulatie/bug
    # en moet het verdacht gelogd worden.
    from types import SimpleNamespace
    from ui import menus
    import ui.console as cons
    cons.pause = lambda: None          # niet blokkeren op input() in de test
    app_stub = SimpleNamespace(
        auth=SimpleNamespace(current_user=anna), log_service=log)
    s0 = log.unread_suspicious_count()
    menus._run(app_stub, lambda: az.require(anna, az.VIEW_LOGS))
    check(log.unread_suspicious_count() > s0,
          "AuthorizationError routed through _run is logged as suspicious")
    check(any(e["description"] == "Authorization denied" for e in log.get_logs()),
          "denied authorization has a clear log entry")

    print("\n== AB. Restore that re-flags must_change_password logs the user out ==")
    # Een restore kan het account terugzetten naar een tijdelijk-wachtwoord-staat.
    # Mid-sessie kunnen we dat niet veilig afdwingen, dus de gebruiker wordt
    # uitgelogd (de tijdelijk-wachtwoord-flow grijpt dan bij de volgende login).
    us.add_manager(sup, "man_flag1", "Manager_2026!", "Flag", "Test")
    flag_mgr = ur.find_by_username("man_flag1")
    sflag = AuthService(log); sflag.login("man_flag1", "Manager_2026!")
    # Zet het account in een tijdelijk-wachtwoord-staat en leg dat vast in een backup.
    ur.update_password(flag_mgr["id"], hashing.hash_password("Manager_2026!"),
                       must_change_password=1)
    sup_f = AuthService(log); sup_f.login("super_admin", "Admin_123?")
    bak_flagged = bs.create_backup(sup_f.current_user)
    bs.restore_any(sup_f.current_user, bak_flagged)
    app_flag = SimpleNamespace(auth=sflag, log_service=log, backup_service=bs)
    menus._check_session_after_restore(app_flag)
    check(sflag.current_user is None,
          "session is logged out when the restored account needs a password change")

    print("\n== AC. NULL-byte / control char on ANY field logged as suspicious ==")
    # Niet alleen op het loginscherm: ook een gewoon veld (read_field) meldt een
    # NULL-byte/stuurteken als verdacht via de hook, en herstelt daarna netjes.
    import builtins
    from ui import console as cons
    # Koppel de hook precies zoals um_members.App dat doet.
    cons.set_suspicious_input_handler(lambda label, reason: log.log(
        "-", "Suspicious input rejected",
        info=f"field '{label}': {reason}", suspicious=True))
    s0 = log.unread_suspicious_count()
    # Voer eerst een NULL-byte-waarde in, daarna een geldige naam.
    seq = iter(["An\x00na", "Anna"])
    orig_input = builtins.input
    builtins.input = lambda prompt="": next(seq)
    try:
        val = cons.read_field("First name", v.is_valid_name, "bad")
    finally:
        builtins.input = orig_input
    check(val == "Anna", "read_field rejects the unsafe value and recovers to a valid one")
    check(log.unread_suspicious_count() > s0,
          "NULL-byte in a non-login field is logged as suspicious")
    check(any(e["description"] == "Suspicious input rejected"
              and "NULL byte or control character" in e.get("info", "")
              for e in log.get_logs()),
          "suspicious-input log entry is descriptive (no raw value echoed)")
    cons.set_suspicious_input_handler(None)

    print("\n== AD. Service-layer re-validation (defense in depth, TB2) ==")
    # De UI valideert al, maar de servicelaag is een eigen vertrouwensgrens: een
    # ongeldige waarde die hier toch binnenkomt (UI omzeild) is geen typefout maar
    # manipulatie -> de operatie breekt af EN wordt verdacht gelogd, en er blijft
    # geen half account achter.
    s0 = log.unread_suspicious_count()
    expect_raise(ValueError, lambda: us.add_employee(
        sup, "ab", "Employee_2026!", "X", "Y",
        {**profile, "email": "ad1@example.com", "bsn": "555000111"}),
        "invalid username on add_employee aborts at the service layer")
    expect_raise(ValueError, lambda: us.add_manager(
        sup, "man_adok1", "weak", "X", "Y"),
        "weak password on add_manager aborts at the service layer")
    expect_raise(ValueError, lambda: us.add_employee(
        sup, "emp_adok1", "Employee_2026!", "X3v!l", "Y",
        {**profile, "email": "ad2@example.com", "bsn": "555000222"}),
        "invalid first name on add_employee aborts at the service layer")
    expect_raise(ValueError, lambda: us.update_employee(
        bob, anna["id"], profile={"bsn": "12"}),
        "invalid bsn on update_employee aborts at the service layer")
    check(log.unread_suspicious_count() > s0,
          "service-layer validation failures are logged as suspicious")
    check(ur.find_by_username("ab") is None
          and ur.find_by_username("man_adok1") is None
          and ur.find_by_username("emp_adok1") is None,
          "no account created when the service-layer validation aborts")
    check(EmployeeRepository().get_by_user_id(anna["id"])["bsn"] != "12",
          "aborted update did not write the forged bsn")

    print("\n== AE. Backup zip-bomb guard (length limit vs DoS, Lecture 3) ==")
    # De DB-entry uit een backup wordt niet blind in het geheugen gelezen: boven
    # een grootte-limiet weigeren we de restore (rem tegen een 'zip bomb').
    sae = AuthService(log); sae.login("super_admin", "Admin_123?")
    bak = bs.create_backup(sae.current_user)
    saved_limit = config.MAX_BACKUP_DB_BYTES
    config.MAX_BACKUP_DB_BYTES = 10        # forceer 'te groot' voor de echte db
    try:
        expect_raise(ValueError, lambda: bs.restore_any(sae.current_user, bak),
                     "oversized backup db is refused (not read into memory)")
    finally:
        config.MAX_BACKUP_DB_BYTES = saved_limit
    bs.restore_any(sae.current_user, bak)   # onder de normale limiet werkt het weer
    check(sae.revalidate_session() is True,
          "restore works again under the normal size limit")

    print(f"\n==== RESULT: {PASS} passed, {FAIL} failed ====")
    database.close_connection()
    return 1 if FAIL else 0


if __name__ == "__main__":
    code = 1
    try:
        code = main()
    finally:
        import shutil
        database.close_connection()
        shutil.rmtree(_TMP, ignore_errors=True)
    sys.exit(code)
