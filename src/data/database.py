"""
database.py - SQLite-verbinding en het aanmaken van het schema.

* Eén gedeelde verbinding voor de hele sessie.
* Elke gevoelige kolom is versleuteld opgeslagen (achtervoegsel `_enc`), ook de
  koppelingen tussen tabellen. De `_idx`-kolommen zijn niet-omkeerbare keyed
  hashes (blind index) voor exacte opzoekingen.
* Omdat de foreign keys versleuteld zijn, gebruiken we geen SQL FOREIGN KEY /
  CASCADE; het opruimen van onderliggende rijen doen we handmatig.
"""

import sqlite3

import config

_connection = None


def get_connection():
    """Geef de gedeelde verbinding terug en open hem bij eerste gebruik."""
    global _connection
    if _connection is None:
        _connection = sqlite3.connect(config.DB_PATH)
        _connection.row_factory = sqlite3.Row
        _connection.execute("PRAGMA foreign_keys = ON")
    return _connection


def close_connection():
    """Sluit de gedeelde verbinding (bij afsluiten / na een restore)."""
    global _connection
    if _connection is not None:
        _connection.close()
        _connection = None


def initialize_database():
    """Maak alle tabellen aan als ze nog niet bestaan."""
    conn = get_connection()
    cur = conn.cursor()

    # Users (managers + werknemers; de super-admin is hardcoded, niet hier).
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            username_idx         TEXT NOT NULL UNIQUE,   -- blind index (opzoeken)
            username_enc         TEXT NOT NULL,          -- versleutelde gebruikersnaam
            password_hash        TEXT NOT NULL,          -- alleen argon2-hash
            role_enc             TEXT NOT NULL,
            first_name_enc       TEXT,
            last_name_enc        TEXT,
            registration_date_enc TEXT NOT NULL,
            must_change_password_enc TEXT NOT NULL
        )
        """
    )

    # Volledig werknemerrecord (Tabel 2). De tabel heet bewust 'staff' zodat de
    # woorden employee/manager nergens leesbaar in het bestand staan.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS staff (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id_enc     TEXT NOT NULL,         -- versleutelde koppeling -> users.id
            emp_no_idx      TEXT NOT NULL UNIQUE,  -- blind index van het werknemer-ID
            emp_no_enc      TEXT NOT NULL,
            birthday_enc    TEXT,
            gender_enc      TEXT,
            street_enc      TEXT,
            house_number_enc TEXT,
            zip_enc         TEXT,
            city_enc        TEXT,
            email_enc       TEXT,
            phone_enc       TEXT,
            doc_type_enc    TEXT,
            doc_number_enc  TEXT,
            bsn_enc         TEXT
        )
        """
    )

    # Claims (Tabel 3).
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS claims (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_user_id_enc TEXT NOT NULL,       -- versleutelde koppeling -> users.id
            claim_date_enc   TEXT,
            project_number_enc TEXT,
            emp_no_enc       TEXT,
            claim_type_enc   TEXT,
            distance_enc     TEXT,
            from_zip_enc     TEXT,
            from_house_enc   TEXT,
            to_zip_enc       TEXT,
            to_house_enc     TEXT,
            approved_enc     TEXT,                  -- Pending / Approved / Rejected
            approved_by_enc  TEXT,
            salary_batch_enc TEXT,
            locked_enc       TEXT NOT NULL
        )
        """
    )

    # Versleuteld activiteitenlog.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_enc      TEXT NOT NULL, -- versleutelde JSON
            suspicious_enc TEXT NOT NULL,
            read_enc       TEXT NOT NULL
        )
        """
    )

    # Eenmalige restore-codes (super-admin geeft een manager een specifieke backup).
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS restore_codes (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            code_idx        TEXT NOT NULL UNIQUE,  -- blind index van de code
            mgr_user_id_enc TEXT NOT NULL,         -- versleutelde koppeling -> users.id
            backup_name_enc TEXT NOT NULL,
            used_enc        TEXT NOT NULL,
            revoked_enc     TEXT NOT NULL
        )
        """
    )

    conn.commit()
