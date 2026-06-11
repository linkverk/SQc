"""
backup_service.py - Backup, restore en eenmalige restore-codes.

* Een backup is een ZIP met de (al versleutelde) database, in de lokale map
  `backups/`.
* Super-admin: backups maken en elke backup terugzetten; codes genereren/intrekken.
* Manager: backups maken, en alleen terugzetten met een geldige eenmalige code.

Een door de gebruiker aangeleverde backup-naam wordt teruggebracht tot de kale
bestandsnaam en gecontroleerd, zodat hij nooit uit `backups/` kan ontsnappen.
"""

import os
import zipfile
from datetime import datetime

import config
from data import database
from data.repositories import LogRepository, RestoreCodeRepository
from services import authorization as az
from services import generators

_DB_ARCNAME = "declaratie.db"


class BackupService:
    def __init__(self, log_service):
        self._codes = RestoreCodeRepository()
        self._logs = LogRepository()
        self._log = log_service

    def _ensure_dir(self):
        os.makedirs(config.BACKUP_DIR, exist_ok=True)

    def _safe_backup_path(self, backup_name):
        """Geef een absoluut pad binnen BACKUP_DIR terug, of raise bij traversal."""
        name = os.path.basename(backup_name)        # verwijder elk map-deel
        if name != backup_name or not name.endswith(".zip"):
            raise ValueError("Invalid backup name.")
        full = os.path.abspath(os.path.join(config.BACKUP_DIR, name))
        backup_dir = os.path.abspath(config.BACKUP_DIR)
        if os.path.commonpath([full, backup_dir]) != backup_dir:
            raise ValueError("Invalid backup name.")
        return full

    # --- maken / lijst ----------------------------------------------------
    def create_backup(self, actor):
        az.require(actor, az.BACKUP_CREATE)
        self._ensure_dir()
        database.get_connection().commit()   # zorg dat alles weggeschreven is
        name = "backup_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".zip"
        path = self._safe_backup_path(name)
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(config.DB_PATH, arcname=_DB_ARCNAME)
        self._log.log(actor["username"], "Backup created", info=f"file: {name}")
        return name

    def list_backups(self, actor):
        az.require(actor, az.BACKUP_CREATE)
        self._ensure_dir()
        zip_files = []
        for name in os.listdir(config.BACKUP_DIR):
            if name.endswith(".zip"):
                zip_files.append(name)
        zip_files.sort()
        return zip_files

    # --- terugzetten ------------------------------------------------------
    def _read_db_from_zip(self, path):
        """Lees de database-entry begrensd uit de zip (rem tegen zip-bomb)."""
        with zipfile.ZipFile(path, "r") as zf:
            if _DB_ARCNAME not in zf.namelist():
                raise ValueError("Backup is missing the database.")
            if zf.getinfo(_DB_ARCNAME).file_size > config.MAX_BACKUP_DB_BYTES:
                raise ValueError("Backup is too large to restore.")
            with zf.open(_DB_ARCNAME) as src:
                data = src.read(config.MAX_BACKUP_DB_BYTES + 1)
        if len(data) > config.MAX_BACKUP_DB_BYTES:
            raise ValueError("Backup is too large to restore.")
        return data

    def _restore_file(self, backup_name):
        path = self._safe_backup_path(backup_name)
        if not os.path.exists(path):
            raise ValueError("Backup file not found.")
        data = self._read_db_from_zip(path)
        # Bewaar logs en de verbruikt/ingetrokken-status van codes, want een
        # restore vervangt het hele bestand en die mogen niet verdwijnen/herleven.
        current_logs = self._logs.get_all_raw()
        current_codes = self._codes.get_consumed_raw()
        # Vervang het live database-bestand en heropen de verbinding.
        database.close_connection()
        with open(config.DB_PATH, "wb") as f:
            f.write(data)
        database.get_connection()
        # Zet de bewaarde logs en code-status er weer overheen.
        self._logs.merge_raw(current_logs)
        self._codes.merge_consumed(current_codes)

    def restore_any(self, actor, backup_name):
        """Super-admin: elke backup terugzetten."""
        az.require(actor, az.BACKUP_RESTORE_ANY)
        self._restore_file(backup_name)
        self._log.log(actor["username"], "Backup restored",
                      info=f"file: {backup_name}")

    def restore_with_code(self, actor, code):
        """Manager: terugzetten met een geldige eenmalige code."""
        az.require(actor, az.BACKUP_RESTORE_WITH_CODE)
        record = self._codes.find_valid(code, actor["id"])
        if record is None:
            self._log.log(actor["username"], "Invalid restore-code used",
                          info="restore denied", suspicious=True)
            raise ValueError("Invalid, used or revoked restore-code.")
        self._codes.mark_used(record["id"])      # eenmalig gebruik
        self._restore_file(record["backup_name"])
        self._log.log(actor["username"], "Backup restored with code",
                      info=f"file: {record['backup_name']}")

    # --- restore-codes genereren / intrekken ------------------------------
    def generate_restore_code(self, actor, manager_user_id, backup_name):
        az.require(actor, az.RESTORE_CODE_GENERATE)
        path = self._safe_backup_path(backup_name)   # draait ook de traversal-check
        if not os.path.exists(path):
            raise ValueError("Backup file not found.")
        code = generators.generate_restore_code()
        self._codes.create(code, manager_user_id, backup_name)
        self._log.log(actor["username"], "Restore-code generated",
                      info=f"manager_id: {manager_user_id}, file: {backup_name}")
        return code

    def revoke_restore_code(self, actor, code, manager_user_id):
        az.require(actor, az.RESTORE_CODE_REVOKE)
        ok = self._codes.revoke(code, manager_user_id)
        self._log.log(actor["username"], "Restore-code revoked",
                      info=f"manager_id: {manager_user_id}, success: {ok}")
        return ok
