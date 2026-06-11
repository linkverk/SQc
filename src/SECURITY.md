# Security cheat sheet — boekprincipe → waar het in de code zit

Hulpmiddel voor de presentatie. Boeken: **TB2 Huseby *Innocent Code*** (kern),
**TB1 Hoffman *Web Application Security*** + de auth/cryptografie-colleges. Per
principe: het bestand en de functie om naar te wijzen.

> Let op: dit zijn de kernprincipes die de boeken onderwijzen, toegepast op dit
> systeem — geen letterlijke citaten.

## TB2 — Data doorgeven aan subsystemen (SQL / shell-injectie)
| Principe | Waar |
|---|---|
| Plak SQL nooit aan elkaar; gebruik parameterized queries | `data/repositories.py` — elke `execute(...)` gebruikt `?`-placeholders |
| Dynamische SQL alleen uit een vaste allow-list, nooit gebruikersinvoer | `repositories.py` `_EMPLOYEE_FIELDS`, `_CLAIM_FIELDS` (UPDATE-kolomnamen) |
| Vermijd shell-command-injectie | nergens `os.system`/`subprocess`/`shell=True` (gescand in `tests/security_tests.py` §R) |

## TB2 — Gebruikersinvoer ("all input is evil") / validatie
| Principe | Waar |
|---|---|
| Whitelist boven blacklist ('deny by default') | `validation/validators.py` — elke `is_valid_*` doet een positieve `re.fullmatch(...)` of vaste lijst; laatste regel is altijd `return False`, `return True` alleen bij een expliciete match |
| Blokkeer NULL-byte / stuurtekens / ANSI escape | `validators.is_safe_text`, ÉÉN keer op de input-boundary (`ui/console.read_field`) op alle invoer — niet per validator (overbodig naast de whitelist) |
| Blokkeer encoding-trucs (Arabisch-Indische / full-width cijfers, homoglyphs) | ASCII-only regex in elke validator (getest §C) |
| Lengtelimieten (buffer-overflow / DoS) | `config.MAX_INPUT_LENGTH` via `validators.is_safe_text` op de input-boundary; wachtwoord begrenst extra op lengte 12-50 |
| Pure vorm-whitelist datums (1 regex, checkt alleen de structuur) | `validators.is_valid_date_format` (YYYY-MM-DD) |
| Range- / semantische checks (los van de whitelist, elk 1 ding) | `validators.is_existing_date` (datum bestaat echt), `is_valid_age` (16-100, niet in toekomst), `is_within_claim_window` (max. 2 mnd oud / 14 dgn vooruit), `is_valid_distance` (>0, in regex) |
| Samenstellers (rijgen whitelist + checks aaneen, geen eigen check) | `validators.is_valid_birthday` (= date_format + existing_date + valid_age), `is_valid_claim_date` (= date_format + existing_date + within_claim_window) |
| User-generated input (typefouten) -> beleefd opnieuw vragen | `ui/console.read_field` + `is_valid_*` (Les 3 s31-32) |
| Server-generated input (keuzelijsten / identiteit / workflow) -> afbreken + loggen | `services/input_guard.assert_valid` (de `assertValid*` van s20) voor claim_type/gender/city/doc_type; `claim_service._abort_on_server_field_tampering` voor vervalste approval/lock-velden; beide raisen "Bad input. Incident logged." (getest §T, §V) |
| Hervalideer op elke vertrouwensgrens (niet alleen de UI) | `user_service._assert_fields` toetst account-/profielvelden (username, wachtwoord, namen, BSN, ...) nogmaals op de servicegrens; ongeldig = UI omzeild = manipulatie -> afbreken + verdacht loggen (getest §AD) |
| Lengtelimiet ook op bestandsinvoer (zip bomb / DoS) | `backup_service._restore_file` leest de DB-entry begrensd uit tegen `config.MAX_BACKUP_DB_BYTES` i.p.v. blind in het geheugen (getest §AE) |
| Netjes falen / fail closed (geen crash) | `ui/console.read_field` (opnieuw vragen) + `ui/menus._run` (catch-all) |

## TB2 — Logging
| Principe | Waar |
|---|---|
| Log beveiligingsrelevante gebeurtenissen | `services/log_service.py`, aangeroepen vanuit elke service-actie |
| Bescherm de loginhoud | logs versleuteld op schijf (`repositories.LogRepository` + `crypto`) |
| Voorkom log-injectie/forging | gestructureerde JSON-velden; een newline kan geen regel toevoegen (getest §M) |
| NULL-byte / stuurteken in login-invoer | geweigerd én als verdacht gelogd aan de login-grens (`auth_service._has_control_chars` + `login`); getest §W |
| Markeer/alarmeer verdachte activiteit | `suspicious`-vlag + ongelezen-alert bij login (`auth_service`, `um_members._show_suspicious_alert`) |

## TB2/TB1 — Authenticatie, wachtwoorden, cryptografie
| Principe | Waar |
|---|---|
| Sla nooit plaintext-wachtwoorden op; gesalte, trage hash | `security/hashing.py` — **Argon2id** (salt in de hash) |
| Gebruik bewezen crypto, bouw het niet zelf | `security/crypto.py` — **Fernet = AES-128-CBC + HMAC** |
| Geauthenticeerde versleuteling (manipulatie-detecterend) | `crypto.decrypt` geeft "" bij manipulatie (getest §H) |
| Symmetrische versleuteling van alle gevoelige data op schijf | elke `_enc`-kolom incl. **rol** (`role_enc`); geen CHECK-constraint of tabel-/kolomnaam lekt 'manager'/'employee' (tabel hernoemd naar `staff`, kolommen `emp_no_*`/`mgr_user_id`); rauwe `.db` bevat geen plaintext-PII (getest §P) |
| Geheime identifiers: niet te raden, hoge entropie | `services/generators.py` via `secrets` (restore-codes, tijdelijke wachtwoorden) |
| Weersta brute-force / dictionary (detecteren) | suspicious-markering na herhaalde mislukkingen (`auth_service`) |
| Weersta brute-force (voorkomen / "multiple wrong tries") | tijdelijke lockout per gebruikersnaam na `MAX_LOGIN_ATTEMPTS` (`auth_service._register_failure`); kort, zelfherstellend venster om DoS te vermijden (getest §S) |

## TB1 — Toegangscontrole & defense in depth
| Principe | Waar |
|---|---|
| Least privilege, gecentraliseerde autorisatie | `services/authorization.py` — één permissietabel per rol |
| Foutmeldingen lekken geen info | login zegt nooit welk veld fout was (`auth_service.login`) |
| Geen timing-zijkanaal bij geheime vergelijking | `hmac.compare_digest` voor super-admin (`auth_service._authenticate`) |
| Weersta user enumeration via timing | dummy Argon2-verify bij onbekende gebruiker (`hashing.dummy_verify`) |
| Maak sessie ongeldig als de context verandert | `auth_service.revalidate_session` na restore (`menus._check_session_after_restore`) |
| Defense in depth (gelaagd) | UI → validatie → service/autorisatie → repository → versleuteling |
| Path-traversal-verdediging | `backup_service._safe_backup_path` |

## Demo-tip
Draai `python tests/security_tests.py` (131 checks) en wijs naar de sectie die bij
elke examenvraag past.
