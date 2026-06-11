# DeclaratieApp backend system

Console-gebaseerde, veilige backend (Python 3 + SQLite3) voor CoreStaff Solutions.
Eindopdracht — Analysis 8: Software Quality (INFSWQ01-A | INFSWQ21-A).

## Hoe te draaien

```bash
pip install -r requirements.txt      # cryptography + argon2-cffi
python um_members.py
```

De database (`declaratie.db`) en de map `backups/` worden bij de eerste keer
draaien automatisch aangemaakt in deze map `src/`.

### Hardcoded Super Administrator (vereist door de casus)
* gebruikersnaam: `super_admin`
* wachtwoord: `Admin_123?`

## Architectuur (scheiding van verantwoordelijkheden)

```
um_members.py        startpunt: koppelt services + login-lus
config.py            constanten (super admin, steden, lockout, max lengte)
security/            crypto.py  (Fernet/AES symmetrische versleuteling + blind index)
                     hashing.py (Argon2 wachtwoord-hashing)
data/                database.py    (sqlite3-verbinding + schema)
                     repositories.py(CRUD; 100% parameterized queries)
validation/          validators.py  (whitelist-validatie voor elk veld)
services/            authorization.py (gecentraliseerde RBAC-permissietabel)
                     auth_service.py  (login, brute-force-detectie, sessie)
                     user_service.py  (werknemers & managers, zoeken)
                     claim_service.py (claim-levenscyclus + goedkeuring)
                     log_service.py   (versleuteld activiteitenlog)
                     backup_service.py(zip backup/restore + restore-codes)
                     generators.py    (veilig tijdelijk wachtwoord / id / code)
ui/                  console.py (invoer-hulpjes) + menus.py (rolmenu's)
```

## Waar elk beoordelingscriterium zit

| Criterium | Waar |
|-----------|------|
| **C1** Authenticatie & autorisatie | `services/auth_service.py` (Argon2-login, brute-force), `services/authorization.py` (één centrale permissietabel per rol) |
| **C2** Invoervalidatie (whitelisting) | `validation/validators.py` — elke `is_valid_*` doet een positieve `re.fullmatch`/vaste lijst, laatste regel `return False` ('deny by default'); de NULL-byte/lengte-laag `is_safe_text` draait ÉÉN keer op de input-boundary (`ui/console.read_field`) |
| **C3** SQL-injectie | `data/repositories.py` — elke query gebruikt `?`-placeholders; alleen kolomnamen uit een vaste allow-list worden ooit geïnterpoleerd |
| **C4** Afhandeling van foute invoer | `ui/console.read_field` vraagt opnieuw zolang `is_valid_*` False geeft; `ui/menus._run` vangt elke fout zodat niets crasht |
| **C5** Logging & backup | `services/log_service.py` (versleuteld log + suspicious-vlag + ongelezen-alert), `services/backup_service.py` (zip-backup, eenmalige restore-codes, path-traversal-verdediging) |

## De adversariële security-tests draaien

```bash
python tests/security_tests.py
```

98 checks gebaseerd op de cursusboeken (Huseby *Innocent Code*, Hoffman *Web
Application Security*): SQL-injectie (incl. second-order/stored), encoding- &
charset-trucs (NULL-byte, CRLF, ANSI escape, Arabisch-Indische / full-width
cijfers, homoglyphs), verticale & horizontale toegangscontrole, "never trust
input" / server-generated velden (incl. manipulatie gelogd als verdacht),
geauthenticeerde versleuteling (manipulatie-detecterend), wachtwoord-hashing,
keyed blind index, entropie van geheime identifiers, brute-force-lockout & user
enumeration, log forging, malformed-login-detectie (NULL-byte/stuurteken gelogd
als verdacht), path traversal (incl. de `....//`-collapse-truc),
restore-code binding/eenmalig gebruik/intrekken, versleuteling op schijf,
sessie-levenscyclus, en een source-hygiëne-scan op gevaarlijke aanroepen
(os.system/eval/exec/pickle/subprocess).

## Extra hardening (uit de auth- / cryptografie-colleges)

* **Constant-time** vergelijking (`hmac.compare_digest`) van het hardcoded
  Super Admin-wachtwoord — geen timing-zijkanaal.
* **Verdediging tegen user enumeration**: een onbekende gebruikersnaam draait
  alsnog een dummy Argon2-verify, zodat de login-timing niet verraadt of een
  gebruikersnaam bestaat.
* **Sessie-hervalidatie na restore** (`AuthService.revalidate_session`):
  een restore vervangt de hele database, dus het ingelogde account wordt opnieuw
  gecontroleerd en de sessie vervalt als het niet meer overeenkomt.

## Security-hoogtepunten voor de presentatie
* **Versleuteling op schijf:** elk gevoelig veld wordt met Fernet versleuteld
  (AES-128-CBC + HMAC) *voordat* het wordt weggeschreven, zodat de rauwe `.db` en
  de loginhoud op elk moment onleesbaar zijn in elk extern hulpmiddel.
* **Wachtwoorden:** alleen een Argon2id-hash wordt ooit opgeslagen — nooit het
  wachtwoord.
* **Gebruikersnamen:** versleuteld opgeslagen + een deterministische HMAC "blind
  index", zodat exacte, hoofdletterongevoelige opzoekingen en uniciteit blijven
  werken op versleutelde data.
* **Draagbare backups:** de symmetrische sleutel wordt afgeleid van een vast
  applicatiegeheim, zodat een versleutelde backup op een andere machine kan
  worden teruggezet en ontsleuteld.
