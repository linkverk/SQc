"""
repositories.py - Alle databasetoegang loopt hier doorheen.

* SQL-injectie: elke query gebruikt `?`-placeholders; gebruikersdata komt nooit
  in de SQL-tekst terecht. Het enige dynamische deel (kolomnamen in een UPDATE)
  komt uit een vaste allow-list in de code.
* Versleuteling: we versleutelen vlak voor het schrijven en ontsleutelen vlak na
  het lezen, zodat de rest van de app met gewone waarden werkt.
* Versleutelde koppelingen (foreign keys): we kunnen er niet met SQL op filteren,
  dus we lezen alle rijen, ontsleutelen de koppeling en vergelijken in Python.
"""

import json

from data.database import get_connection
from security import crypto


# --- Hulpjes voor versleutelde id-koppelingen ------------------------------
def _enc_id(value):
    """Versleutel een id tot een opslaanbare token."""
    return crypto.encrypt(str(value))


def _dec_id(token):
    """Lees een met _enc_id opgeslagen id terug als int (of None)."""
    text = crypto.decrypt(token)
    if text == "":
        return None
    return int(text)


# ===========================================================================
# Users
# ===========================================================================
class UserRepository:
    def create_user(self, username, password_hash, role, first_name,
                    last_name, registration_date, must_change_password=0):
        conn = get_connection()
        cur = conn.execute(
            """
            INSERT INTO users (username_idx, username_enc, password_hash, role_enc,
                               first_name_enc, last_name_enc,
                               registration_date_enc, must_change_password_enc)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                crypto.blind_index(username.lower()),
                crypto.encrypt(username),
                password_hash,
                crypto.encrypt(role),
                crypto.encrypt(first_name),
                crypto.encrypt(last_name),
                crypto.encrypt(registration_date),
                crypto.encrypt_bool(must_change_password),
            ),
        )
        conn.commit()
        return cur.lastrowid

    def _row_to_dict(self, row):
        if row is None:
            return None
        return {
            "id": row["id"],
            "username": crypto.decrypt(row["username_enc"]),
            "password_hash": row["password_hash"],
            "role": crypto.decrypt(row["role_enc"]),
            "first_name": crypto.decrypt(row["first_name_enc"]),
            "last_name": crypto.decrypt(row["last_name_enc"]),
            "registration_date": crypto.decrypt(row["registration_date_enc"]),
            "must_change_password": crypto.decrypt_bool(row["must_change_password_enc"]),
        }

    def find_by_username(self, username):
        conn = get_connection()
        row = conn.execute(
            "SELECT * FROM users WHERE username_idx = ?",
            (crypto.blind_index(username.lower()),),
        ).fetchone()
        return self._row_to_dict(row)

    def get_by_id(self, user_id):
        conn = get_connection()
        row = conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return self._row_to_dict(row)

    def username_exists(self, username):
        conn = get_connection()
        row = conn.execute(
            "SELECT 1 FROM users WHERE username_idx = ?",
            (crypto.blind_index(username.lower()),),
        ).fetchone()
        return row is not None

    def update_password(self, user_id, password_hash, must_change_password=0):
        conn = get_connection()
        conn.execute(
            "UPDATE users SET password_hash = ?, must_change_password_enc = ? WHERE id = ?",
            (password_hash, crypto.encrypt_bool(must_change_password), user_id),
        )
        conn.commit()

    def update_profile(self, user_id, first_name, last_name):
        conn = get_connection()
        conn.execute(
            "UPDATE users SET first_name_enc = ?, last_name_enc = ? WHERE id = ?",
            (crypto.encrypt(first_name), crypto.encrypt(last_name), user_id),
        )
        conn.commit()

    def update_username(self, user_id, new_username):
        conn = get_connection()
        conn.execute(
            "UPDATE users SET username_idx = ?, username_enc = ? WHERE id = ?",
            (crypto.blind_index(new_username.lower()),
             crypto.encrypt(new_username), user_id),
        )
        conn.commit()

    def delete_user(self, user_id):
        # Versleutelde koppelingen kunnen geen ON DELETE CASCADE gebruiken, dus
        # ruimen we de onderliggende rijen hier handmatig op. De tabel-/kolom-
        # namen komen uit een vaste lijst (geen invoer) -> SQLi-veilig.
        conn = get_connection()
        child_tables = (
            ("staff", "user_id_enc"),
            ("claims", "owner_user_id_enc"),
            ("restore_codes", "mgr_user_id_enc"),
        )
        for table, fk_col in child_tables:
            rows = conn.execute(f"SELECT id, {fk_col} AS fk FROM {table}").fetchall()
            for row in rows:
                if _dec_id(row["fk"]) == user_id:
                    conn.execute(f"DELETE FROM {table} WHERE id = ?", (row["id"],))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()

    def list_by_role(self, role):
        # De rol staat versleuteld, dus we filteren in Python.
        conn = get_connection()
        rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
        result = []
        for row in rows:
            user = self._row_to_dict(row)
            if user["role"] == role:
                result.append(user)
        return result


# ===========================================================================
# Employees (volledig record van Tabel 2)
# ===========================================================================
# Allow-list van bewerkbare kolommen -> de veldnaam waar ze op mappen.
_EMPLOYEE_FIELDS = {
    "birthday": "birthday_enc",
    "gender": "gender_enc",
    "street": "street_enc",
    "house_number": "house_number_enc",
    "zip": "zip_enc",
    "city": "city_enc",
    "email": "email_enc",
    "phone": "phone_enc",
    "doc_type": "doc_type_enc",
    "doc_number": "doc_number_enc",
    "bsn": "bsn_enc",
}


class EmployeeRepository:
    def create_employee(self, user_id, employee_id, data):
        conn = get_connection()
        conn.execute(
            """
            INSERT INTO staff
                (user_id_enc, emp_no_idx, emp_no_enc, birthday_enc,
                 gender_enc, street_enc, house_number_enc, zip_enc, city_enc,
                 email_enc, phone_enc, doc_type_enc, doc_number_enc, bsn_enc)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _enc_id(user_id),
                crypto.blind_index(employee_id),
                crypto.encrypt(employee_id),
                crypto.encrypt(data.get("birthday", "")),
                crypto.encrypt(data.get("gender", "")),
                crypto.encrypt(data.get("street", "")),
                crypto.encrypt(data.get("house_number", "")),
                crypto.encrypt(data.get("zip", "")),
                crypto.encrypt(data.get("city", "")),
                crypto.encrypt(data.get("email", "")),
                crypto.encrypt(data.get("phone", "")),
                crypto.encrypt(data.get("doc_type", "")),
                crypto.encrypt(data.get("doc_number", "")),
                crypto.encrypt(data.get("bsn", "")),
            ),
        )
        conn.commit()

    def _row_to_dict(self, row):
        if row is None:
            return None
        return {
            "id": row["id"],
            "user_id": _dec_id(row["user_id_enc"]),
            "employee_id": crypto.decrypt(row["emp_no_enc"]),
            "birthday": crypto.decrypt(row["birthday_enc"]),
            "gender": crypto.decrypt(row["gender_enc"]),
            "street": crypto.decrypt(row["street_enc"]),
            "house_number": crypto.decrypt(row["house_number_enc"]),
            "zip": crypto.decrypt(row["zip_enc"]),
            "city": crypto.decrypt(row["city_enc"]),
            "email": crypto.decrypt(row["email_enc"]),
            "phone": crypto.decrypt(row["phone_enc"]),
            "doc_type": crypto.decrypt(row["doc_type_enc"]),
            "doc_number": crypto.decrypt(row["doc_number_enc"]),
            "bsn": crypto.decrypt(row["bsn_enc"]),
        }

    def _find_raw_by_user_id(self, user_id):
        """Zoek de rauwe staff-rij voor een user_id (koppeling is versleuteld)."""
        conn = get_connection()
        rows = conn.execute("SELECT * FROM staff ORDER BY id").fetchall()
        for row in rows:
            if _dec_id(row["user_id_enc"]) == user_id:
                return row
        return None

    def get_by_user_id(self, user_id):
        return self._row_to_dict(self._find_raw_by_user_id(user_id))

    def get_by_employee_id(self, employee_id):
        conn = get_connection()
        row = conn.execute(
            "SELECT * FROM staff WHERE emp_no_idx = ?",
            (crypto.blind_index(employee_id),),
        ).fetchone()
        return self._row_to_dict(row)

    def employee_id_exists(self, employee_id):
        conn = get_connection()
        row = conn.execute(
            "SELECT 1 FROM staff WHERE emp_no_idx = ?",
            (crypto.blind_index(employee_id),),
        ).fetchone()
        return row is not None

    def update_employee(self, user_id, data):
        """Werk alleen de meegegeven, allow-listed velden bij."""
        columns = []
        values = []
        for field, value in data.items():
            if field in _EMPLOYEE_FIELDS:            # allow-list-controle
                columns.append(f"{_EMPLOYEE_FIELDS[field]} = ?")
                values.append(crypto.encrypt(value))
        if not columns:
            return
        raw = self._find_raw_by_user_id(user_id)
        if raw is None:
            return
        values.append(raw["id"])
        conn = get_connection()
        conn.execute(
            f"UPDATE staff SET {', '.join(columns)} WHERE id = ?",
            tuple(values),
        )
        conn.commit()

    def list_all(self):
        conn = get_connection()
        rows = conn.execute("SELECT * FROM staff ORDER BY id").fetchall()
        result = []
        for row in rows:
            result.append(self._row_to_dict(row))
        return result


# ===========================================================================
# Claims (record van Tabel 3)
# ===========================================================================
_CLAIM_FIELDS = {
    "claim_date": "claim_date_enc",
    "project_number": "project_number_enc",
    "employee_id": "emp_no_enc",
    "claim_type": "claim_type_enc",
    "distance": "distance_enc",
    "from_zip": "from_zip_enc",
    "from_house": "from_house_enc",
    "to_zip": "to_zip_enc",
    "to_house": "to_house_enc",
}


class ClaimRepository:
    def create_claim(self, owner_user_id, data):
        conn = get_connection()
        cur = conn.execute(
            """
            INSERT INTO claims
                (owner_user_id_enc, claim_date_enc, project_number_enc,
                 emp_no_enc, claim_type_enc, distance_enc, from_zip_enc,
                 from_house_enc, to_zip_enc, to_house_enc, approved_enc,
                 approved_by_enc, salary_batch_enc, locked_enc)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _enc_id(owner_user_id),
                crypto.encrypt(data.get("claim_date", "")),
                crypto.encrypt(data.get("project_number", "")),
                crypto.encrypt(data.get("employee_id", "")),
                crypto.encrypt(data.get("claim_type", "")),
                crypto.encrypt(data.get("distance", "")),
                crypto.encrypt(data.get("from_zip", "")),
                crypto.encrypt(data.get("from_house", "")),
                crypto.encrypt(data.get("to_zip", "")),
                crypto.encrypt(data.get("to_house", "")),
                crypto.encrypt("Pending"),
                crypto.encrypt(""),
                crypto.encrypt(""),
                crypto.encrypt_bool(False),
            ),
        )
        conn.commit()
        return cur.lastrowid

    def _row_to_dict(self, row):
        if row is None:
            return None
        return {
            "id": row["id"],
            "owner_user_id": _dec_id(row["owner_user_id_enc"]),
            "claim_date": crypto.decrypt(row["claim_date_enc"]),
            "project_number": crypto.decrypt(row["project_number_enc"]),
            "employee_id": crypto.decrypt(row["emp_no_enc"]),
            "claim_type": crypto.decrypt(row["claim_type_enc"]),
            "distance": crypto.decrypt(row["distance_enc"]),
            "from_zip": crypto.decrypt(row["from_zip_enc"]),
            "from_house": crypto.decrypt(row["from_house_enc"]),
            "to_zip": crypto.decrypt(row["to_zip_enc"]),
            "to_house": crypto.decrypt(row["to_house_enc"]),
            "approved": crypto.decrypt(row["approved_enc"]),
            "approved_by": crypto.decrypt(row["approved_by_enc"]),
            "salary_batch": crypto.decrypt(row["salary_batch_enc"]),
            "locked": crypto.decrypt_bool(row["locked_enc"]),
        }

    def get_by_id(self, claim_id):
        conn = get_connection()
        row = conn.execute(
            "SELECT * FROM claims WHERE id = ?", (claim_id,)
        ).fetchone()
        return self._row_to_dict(row)

    def list_by_owner(self, owner_user_id):
        # owner_user_id is versleuteld, dus we filteren in Python.
        conn = get_connection()
        rows = conn.execute("SELECT * FROM claims ORDER BY id").fetchall()
        result = []
        for row in rows:
            if _dec_id(row["owner_user_id_enc"]) == owner_user_id:
                result.append(self._row_to_dict(row))
        return result

    def list_all(self):
        conn = get_connection()
        rows = conn.execute("SELECT * FROM claims ORDER BY id").fetchall()
        result = []
        for row in rows:
            result.append(self._row_to_dict(row))
        return result

    def update_claim(self, claim_id, data):
        columns = []
        values = []
        for field, value in data.items():
            if field in _CLAIM_FIELDS:               # allow-list-controle
                columns.append(f"{_CLAIM_FIELDS[field]} = ?")
                values.append(crypto.encrypt(value))
        if not columns:
            return
        values.append(claim_id)
        conn = get_connection()
        conn.execute(
            f"UPDATE claims SET {', '.join(columns)} WHERE id = ?",
            tuple(values),
        )
        conn.commit()

    def set_approval(self, claim_id, status, approved_by, salary_batch, locked):
        conn = get_connection()
        conn.execute(
            """
            UPDATE claims
               SET approved_enc = ?, approved_by_enc = ?,
                   salary_batch_enc = ?, locked_enc = ?
             WHERE id = ?
            """,
            (
                crypto.encrypt(status),
                crypto.encrypt(approved_by),
                crypto.encrypt(salary_batch),
                crypto.encrypt_bool(locked),
                claim_id,
            ),
        )
        conn.commit()

    def delete_claim(self, claim_id):
        conn = get_connection()
        conn.execute("DELETE FROM claims WHERE id = ?", (claim_id,))
        conn.commit()


# ===========================================================================
# Logs
# ===========================================================================
class LogRepository:
    def add(self, entry, suspicious):
        conn = get_connection()
        conn.execute(
            "INSERT INTO logs (entry_enc, suspicious_enc, read_enc) VALUES (?, ?, ?)",
            (
                crypto.encrypt(json.dumps(entry)),
                crypto.encrypt_bool(suspicious),
                crypto.encrypt_bool(False),
            ),
        )
        conn.commit()

    def _row_to_dict(self, row):
        entry = json.loads(crypto.decrypt(row["entry_enc"]) or "{}")
        entry["no"] = row["id"]
        entry["suspicious"] = crypto.decrypt_bool(row["suspicious_enc"])
        entry["read"] = crypto.decrypt_bool(row["read_enc"])
        return entry

    def get_all(self):
        conn = get_connection()
        rows = conn.execute("SELECT * FROM logs ORDER BY id").fetchall()
        result = []
        for row in rows:
            result.append(self._row_to_dict(row))
        return result

    def count_unread_suspicious(self):
        # De vlaggen staan versleuteld, dus we tellen in Python.
        conn = get_connection()
        rows = conn.execute("SELECT suspicious_enc, read_enc FROM logs").fetchall()
        count = 0
        for row in rows:
            suspicious = crypto.decrypt_bool(row["suspicious_enc"])
            read = crypto.decrypt_bool(row["read_enc"])
            if suspicious and not read:
                count += 1
        return count

    def mark_all_read(self):
        conn = get_connection()
        rows = conn.execute("SELECT id, read_enc FROM logs").fetchall()
        for row in rows:
            if not crypto.decrypt_bool(row["read_enc"]):
                conn.execute(
                    "UPDATE logs SET read_enc = ? WHERE id = ?",
                    (crypto.encrypt_bool(True), row["id"]),
                )
        conn.commit()

    # --- Logs bewaren bij een backup-restore -------------------------------
    # Logregels mogen nooit verdwijnen door een restore. We werken met de rauwe
    # entry_enc, zodat we niets hoeven te ontsleutelen en de inhoud intact blijft.
    def get_all_raw(self):
        """Lees alle logregels rauw uit (nog versleuteld)."""
        conn = get_connection()
        rows = conn.execute(
            "SELECT entry_enc, suspicious_enc, read_enc FROM logs ORDER BY id"
        ).fetchall()
        result = []
        for row in rows:
            result.append({
                "entry_enc": row["entry_enc"],
                "suspicious_enc": row["suspicious_enc"],
                "read_enc": row["read_enc"],
            })
        return result

    def merge_raw(self, raw_rows):
        """Voeg na een restore de ontbrekende logregels weer toe (op entry_enc)."""
        conn = get_connection()
        existing = set()
        for row in conn.execute("SELECT entry_enc FROM logs").fetchall():
            existing.add(row["entry_enc"])
        for row in raw_rows:
            if row["entry_enc"] in existing:
                continue
            conn.execute(
                "INSERT INTO logs (entry_enc, suspicious_enc, read_enc) VALUES (?, ?, ?)",
                (row["entry_enc"], row["suspicious_enc"], row["read_enc"]),
            )
        conn.commit()


# ===========================================================================
# Restore-codes
# ===========================================================================
class RestoreCodeRepository:
    def create(self, code, manager_user_id, backup_name):
        conn = get_connection()
        conn.execute(
            """
            INSERT INTO restore_codes
                (code_idx, mgr_user_id_enc, backup_name_enc, used_enc, revoked_enc)
            VALUES (?, ?, ?, ?, ?)
            """,
            (crypto.blind_index(code), _enc_id(manager_user_id),
             crypto.encrypt(backup_name),
             crypto.encrypt_bool(False), crypto.encrypt_bool(False)),
        )
        conn.commit()

    def find_valid(self, code, manager_user_id):
        """Geef een ongebruikte, niet-ingetrokken code voor deze manager, of None."""
        conn = get_connection()
        row = conn.execute(
            "SELECT * FROM restore_codes WHERE code_idx = ?",
            (crypto.blind_index(code),),
        ).fetchone()
        if row is None:
            return None
        if _dec_id(row["mgr_user_id_enc"]) != manager_user_id:
            return None
        if crypto.decrypt_bool(row["used_enc"]) or crypto.decrypt_bool(row["revoked_enc"]):
            return None
        return {
            "id": row["id"],
            "manager_user_id": _dec_id(row["mgr_user_id_enc"]),
            "backup_name": crypto.decrypt(row["backup_name_enc"]),
        }

    def mark_used(self, code_id):
        conn = get_connection()
        conn.execute(
            "UPDATE restore_codes SET used_enc = ? WHERE id = ?",
            (crypto.encrypt_bool(True), code_id),
        )
        conn.commit()

    # --- Status bewaren bij een restore ------------------------------------
    # Een gebruikte of ingetrokken code mag nooit herleven doordat iemand een
    # oudere backup terugzet. We snapshotten de status en leggen 'm er na de
    # restore weer overheen (alleen aanzetten, nooit terug naar ongebruikt).
    def get_consumed_raw(self):
        """Geef code_idx + status van codes die al gebruikt of ingetrokken zijn."""
        conn = get_connection()
        rows = conn.execute(
            "SELECT code_idx, used_enc, revoked_enc FROM restore_codes"
        ).fetchall()
        consumed = []
        for row in rows:
            used = crypto.decrypt_bool(row["used_enc"])
            revoked = crypto.decrypt_bool(row["revoked_enc"])
            if used or revoked:
                consumed.append(
                    {"code_idx": row["code_idx"], "used": used, "revoked": revoked}
                )
        return consumed

    def merge_consumed(self, consumed_rows):
        """Herstel de gebruikt/ingetrokken-vlaggen na een restore (monotoon)."""
        conn = get_connection()
        for row in consumed_rows:
            existing = conn.execute(
                "SELECT id FROM restore_codes WHERE code_idx = ?",
                (row["code_idx"],),
            ).fetchone()
            if existing is None:
                continue
            if row["used"]:
                conn.execute(
                    "UPDATE restore_codes SET used_enc = ? WHERE id = ?",
                    (crypto.encrypt_bool(True), existing["id"]),
                )
            if row["revoked"]:
                conn.execute(
                    "UPDATE restore_codes SET revoked_enc = ? WHERE id = ?",
                    (crypto.encrypt_bool(True), existing["id"]),
                )
        conn.commit()

    def revoke(self, code, manager_user_id):
        conn = get_connection()
        row = conn.execute(
            "SELECT id, mgr_user_id_enc, used_enc FROM restore_codes WHERE code_idx = ?",
            (crypto.blind_index(code),),
        ).fetchone()
        if (row is None
                or _dec_id(row["mgr_user_id_enc"]) != manager_user_id
                or crypto.decrypt_bool(row["used_enc"])):
            return False
        conn.execute(
            "UPDATE restore_codes SET revoked_enc = ? WHERE id = ?",
            (crypto.encrypt_bool(True), row["id"]),
        )
        conn.commit()
        return True
