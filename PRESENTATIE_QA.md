# Presentatie Q&A — DeclaratieApp (Software Quality)

Oefendocument voor de mondelinge verdediging (criterium C6). Per verwachte
docentvraag: een kort antwoord, **waar** het in de code zit, en **waarom**.
Termen die de docent gebruikt staan vetgedrukt.

---

## 1. "Hoe heb je je SQL-queries geïmplementeerd? Is je applicatie veilig tegen SQL-injectie en waarom?" (C3, Les 2)

**Antwoord:** Elke query gebruikt **parameter-placeholders** (`?`). De gebruikersdata
gaat als aparte tuple mee naar SQLite en wordt daardoor nooit als SQL-code
geïnterpreteerd — er is geen contextwissel waar data ineens commando wordt.

- **Waar:** `data/repositories.py` — alle `conn.execute("... ?", (waarde,))`.
- Het **enige** dynamische deel dat ik ooit opbouw is een lijst kolom-/tabelnamen
  in een UPDATE/DELETE (`update_employee`, `update_claim`, `delete_user`). Die namen
  komen **uitsluitend uit een vaste allow-list in code** (`_EMPLOYEE_FIELDS`,
  `_CLAIM_FIELDS`, de tuple in `delete_user`), nooit uit invoer. Waarden worden nog
  steeds met `?` gebonden.
- **Waarom prepared statements i.p.v. zelf escapen?** Les 2: bij escapen mis je
  altijd wel een metakarakter (backslash-truc in MySQL/PostgreSQL). Met prepared
  statements zíjn er geen metakarakters — data en commando gaan gescheiden.
- **Demo:** login met `' OR '1'='1` → mislukt. (Testsuite sectie A.)

---

## 2. "Waar zit je input-validatielaag? Welk mechanisme gebruik je en waarom?" (C2, Les 3)

**Antwoord:** Een aparte laag `validation/validators.py` met **whitelisting**.

- **Mechanisme:** elke `is_valid_*`-functie beschrijft **positief** wat WEL mag —
  een `re.fullmatch`-patroon of een vaste lijst (`config.CITIES`, `GENDERS`, ...).
  De laatste regel is altijd `return False`: **deny by default**.
- **Waarom `re.fullmatch` en niet `^...$`?** `$` matcht ook vlak vóór een
  afsluitende newline, waardoor er een regel kon "ontsnappen" (CRLF-injectie).
  `fullmatch` eist dat de HÉLE invoer matcht.
- **Waarom whitelisting en niet blacklisting?** Les 3, sheet 28: blacklisting laat
  "het goede + het onbekende" door; whitelisting laat alleen "het goede" door en
  blokkeert het onbekende (deny by default, zoals een firewall).
- **Volgorde:** in `ui/console.read_field` draait eerst `is_safe_text` (boundary),
  dán de veld-whitelist `is_valid`, en pas dáárna wordt de waarde gebruikt →
  "validate before doing anything else" (sheet 22).

---

## 3. "Bescherm je tegen een buffer-overflow / extreem lange invoer?" (Les 3)

**Antwoord:** Ja, op twee niveaus.
- Eén algemene lengtelimiet `config.MAX_INPUT_LENGTH` (256) in
  `validators.is_safe_text`, toegepast op **alle** invoer op de input-grens
  (`read_field`). Langere invoer bekijken we nooit.
- Bovendien begrenst elk veld-patroon zelf de lengte (bijv. wachtwoord `{12,50}`,
  zoeksleutel `{1,50}`).
- **Waarom op de grens?** Les 3: "Check the Length — altijd, tegen database-fouten
  en buffer-overflows." (Demo: testsuite "overlong input rejected", sectie C.)

---

## 4. "Bescherm je tegen een NULL-byte-aanval en hoe?" (Les 3, sheet 22)

**Antwoord:** Ja, en op de juiste manier — niet als losse blacklist maar in lagen.
- **De whitelist vangt het al:** een NULL-byte (`\x00`) of stuurteken zit niet in
  de toegestane tekenset van een `re.fullmatch`, dus `is_valid_name("An\x00na")`
  is sowieso `False`. De whitelist *is* de NULL-byte-verdediging.
- **Plus een expliciete boundary-laag** `is_safe_text` (de door de les gevraagde
  "check for null-bytes"): weigert NULL-byte/stuurteken/te lange invoer één keer
  centraal voor álle invoer, vóór de veld-whitelist.
- **En loggen:** een NULL-byte is nooit een typefout maar een teken van een
  gemanipuleerde/niet-interactieve client. Daarom logt hij **verdacht** op élke
  input-grens — bij de login (`auth_service._has_control_chars`) én op elk ander
  veld via de hook `console.set_suspicious_input_handler` → `um_members.App`.
- **Demo:** sectie W (login) en sectie AC (gewoon veld).

---

## 5. "Hoe ga je om met user-generated vs server-generated foute invoer?" (Les 3, sheet 31-32)

**Antwoord:** Verschillend, precies zoals de les voorschrijft.
- **User-generated** (getypt in een tekstveld) mag een typefout zijn → we zijn
  beleefd: melding tonen en opnieuw vragen (`read_field` blijft vragen).
- **Server-generated** (keuzelijsten, identiteit, workflow-velden, verborgen
  waarden) hoort in normaal gebruik nooit fout te zijn. Is het toch fout, dan is
  het **manipulatie** → we zijn niet beleefd: we **breken de actie af en loggen het
  incident als verdacht** ("Bad input. Incident logged.").
  - **Waar:** `services/input_guard.assert_valid` en
    `claim_service._abort_on_server_field_tampering`.
- **Defense in depth — ook op de servicegrens:** de UI valideert al, maar elke
  service-methode hervalideert de account-/profielvelden nóg een keer
  (`user_service._assert_fields`). Komt een ongeldige waarde hier tóch binnen, dan
  is de UI omzeild → dat behandelen we als manipulatie: **afbreken + verdacht
  loggen** (niet beleefd opnieuw vragen). Huseby: valideer op elke vertrouwensgrens.
  (Demo: sectie AD.)
- **Waarom niet stiekem repareren?** Les 3, sheet 34-35: "do not massage invalid
  input to make it valid" — de `....//`-truc liet zien dat je dan zelf een gat
  maakt. (Demo: sectie U + V + G.)

---

## 6. "Waar zit je autorisatie en is die gecentraliseerd?" (C1, Les 3 sheet 23)

**Antwoord:** Eén centrale **Role-Based Access Control** in
`services/authorization.py`: één tabel `rol → set permissies`. Elke service-methode
begint met `az.require(actor, PERMISSIE)`.
- **Waarom centraal?** Geen verspreide `if role == "manager"`-checks die uit elkaar
  lopen; alles op één plek leesbaar en controleerbaar.
- **Autorisatie sámen met validatie** (sheet 23): de `require`-check staat bovenaan,
  vóór er met de invoer iets gebeurt.
- Een geweigerde autorisatie wordt **verdacht gelogd** (`menus._run`) — via het menu
  kan dat bijna niet ontstaan, dus áls het gebeurt is het manipulatie/bug.
- **Demo:** sectie E (verticaal), F (horizontaal: eigen claims), Z (cross-role).

---

## 7. "Laat de authenticatie-code zien." (C1, Les 4)

**Antwoord:** `services/auth_service.py`.
- Hardcoded Super Admin wordt als eerste gecheckt, met **constant-time vergelijking**
  (`hmac.compare_digest`) tegen een timing-zijkanaal.
- Database-gebruikers via **Argon2-hashverificatie**.
- Onbekende gebruikersnaam → toch een **dummy-verify** (`hashing.dummy_verify`) zodat
  het evenveel tijd kost als een bekende → geen **user-enumeration** via timing.
- We verklappen nooit of de gebruikersnaam óf het wachtwoord fout was.

---

## 8. "Hoe sla je wachtwoorden op?" (C1, Les 4)

**Antwoord:** Nooit in leesbare of omkeerbare vorm — alleen een **hash**.
- **Argon2id** (`security/hashing.py`), winnaar van de Password Hashing Competition,
  geheugen-hard.
- Argon2 genereert **per wachtwoord een willekeurige salt** en stopt die ín de
  hashstring → twee identieke wachtwoorden geven verschillende hashes, en ik hoef de
  salt niet apart op te slaan.
- **Waarom salt?** Les 4: zodat gelijke wachtwoorden niet herkenbaar zijn en
  rainbow-tables/dictionary-aanvallen niet in één klap werken.
- **Demo:** in de ruwe `.db` staat alleen `$argon2id$...` (sectie I + P).

---

## 9. "Welke encryptie gebruik je voor de gevoelige data en waarom symmetrisch?" (Les 4)

**Antwoord:** **Symmetrisch**, want de opdracht vraagt het en het is één
applicatie die voor zichzelf data opslaat en weer uitleest (geen tweede partij).
- **Fernet** uit `cryptography` (`security/crypto.py`): AES-128-CBC voor
  vertrouwelijkheid + HMAC-SHA256 voor **integriteit**, met een willekeurige IV per
  bericht → dezelfde waarde levert twee keer verschillende ciphertext op.
- **Elke gevoelige waarde apart** versleuteld vóór het schrijven, ontsleuteld na het
  lezen → "decrypt bij start / encrypt bij afsluiten" is verboden, dat doe ik dus
  niet. Op schijf staat altijd alleen ciphertext.
- **Blind index** (`crypto.blind_index`, keyed HMAC) voor exact opzoeken op een
  versleutelde kolom (gebruikersnaam), want versleutelde kolommen kun je niet in een
  `WHERE` gebruiken.
- **Sleutel:** afgeleid met **PBKDF2** uit een applicatiegeheim → op elke machine
  dezelfde sleutel, zodat een backup draagbaar is maar het `.db`-bestand zonder het
  programma onleesbaar blijft.

---

## 10. "Laat zien dat de data in de database versleuteld is." (Les 4)

**Antwoord:** Open `src/declaratie.db` in een teksteditor / DB-tool → alleen
ciphertext. Geen naam, BSN, stad, gebruikersnaam of rol leesbaar; zelfs de
koppelingen (foreign keys) zijn versleuteld. **Demo:** sectie P controleert dat
plaintext als `Anna`, `Rotterdam`, `987654321`, `manager` níét in de ruwe bytes
voorkomt.

---

## 11. "Hoe bepaal je of een activiteit verdacht (suspicious) of normaal is?" (C5, Les 3)

**Antwoord:** Verdacht = alles wat in normaal gebruik niet hoort te gebeuren:
- meerdere mislukte logins achter elkaar (brute-force, drempel
  `SUSPICIOUS_LOGIN_THRESHOLD`);
- een geblokkeerde (locked) gebruikersnaam die het blijft proberen;
- een NULL-byte/stuurteken in invoer (login of elk veld);
- server-generated tampering (verboden veld proberen te zetten);
- een geweigerde autorisatie;
- een ongeldige/ingetrokken restore-code.

Normaal = inloggen, claim toevoegen, zoeken, backup maken, enz.
- **Waar:** overal waar `self._log.log(..., suspicious=True)` staat.
- **Alert:** bij login van een Manager/Super Admin toont `_show_suspicious_alert` het
  aantal **ongelezen** verdachte regels.

---

## 12. "Is je logging veilig en alleen via de applicatie leesbaar?" (C5)

**Antwoord:** Ja.
- Elke logregel wordt als **versleutelde** JSON opgeslagen (`entry_enc`), plus
  versleutelde `suspicious`- en `read`-vlaggen → met een externe tool zie je niets.
- Alleen leesbaar via het menu, met permissie `VIEW_LOGS` (Manager/Super Admin).
- **Log forging via newline:** een newline is een stuurteken → geweigerd op de
  grens, dus een aanvaller kan geen extra (valse) logregel injecteren (sectie M).

---

## 13. "Hoe werkt je backup/restore en de eenmalige restore-code?" (C5)

**Antwoord:**
- Backup = ZIP met de (al versleutelde) database in `backups/`. Meerdere backups
  mogelijk. Geen extra encryptie nodig (data is al versleuteld).
- Super Admin: elke backup terugzetten. Manager: alleen de specifieke backup
  waarvoor de Super Admin een **eenmalige restore-code** gaf.
- Super Admin kan codes **genereren en intrekken**, maar mag zelf **geen** code
  gebruiken (RBAC).
- **Path-traversal:** een backup-naam wordt tot de kale bestandsnaam teruggebracht
  en het pad gecontroleerd binnen `backups/` (`_safe_backup_path`). (Sectie N + U.)
- **Zip-bomb / DoS bij restore:** de database-entry uit een backup-zip lezen we
  niet blind in het geheugen; we begrenzen de uitgepakte grootte op
  `config.MAX_BACKUP_DB_BYTES` (`_read_db_from_zip`) — dezelfde lengtelimiet-tegen-
  DoS-gedachte als `MAX_INPUT_LENGTH`, nu op bestandsniveau. (Sectie AE.)

**Belangrijke verdedigingen die de docent vorig keer probeerde:**
- **Logs mogen niet verdwijnen bij een restore** → `_restore_file` bewaart de
  huidige logs en voegt ze na de restore weer toe (`merge_raw`). Logs groeien alleen.
  (Sectie X.)
- **Sessie na restore** → `revalidate_session` logt je uit als je account niet meer
  in de teruggezette database bestaat/klopt. (Sectie Q.)
- **must_change_password na restore** → als de teruggezette data je account op een
  tijdelijk wachtwoord zet, word je uitgelogd zodat de flow bij de volgende login
  grijpt. (Sectie AB.)
- **Eenmalige/ingetrokken code mag niet herleven via een oude backup** → de
  gebruikt/ingetrokken-status overleeft een restore (`merge_consumed`, monotoon).
  (Sectie Y.)

---

## 14. "Welke libraries gebruik je en mag dat?"

**Antwoord:** Alleen de standaardbibliotheek + `sqlite3` + `re`, plus voor crypto/
hashing twee toegestane third-party libraries: `cryptography` (Fernet) en
`argon2-cffi` (Argon2id). Zie `requirements.txt`. Geen `os.system`, `subprocess`,
`eval`, `exec`, `pickle` (sectie R).

---

## 15. "Hoe is je code opgebouwd (scheiding van lagen)?"

**Antwoord:** Strikt gelaagd:
- `ui/` — praat met de gebruiker, verzamelt + valideert invoer (verzamelt nooit
  ongeldige data door naar beneden).
- `validation/` — whitelisting (`is_valid_*`) + de boundary-laag `is_safe_text`.
- `services/` — bedrijfslogica + autorisatie + logging (`auth`, `user`, `claim`,
  `backup`, `log`).
- `data/` — alle databasetoegang (repositories) + encryptiegrens.
- `security/` — `crypto` (Fernet/blind index) + `hashing` (Argon2).
- `config.py` — alle constanten op één plek.
De UI raakt de database nooit rechtstreeks aan.

---

## Snelle demo-checklist
1. Login als `super_admin` / `Admin_123?`.
2. Maak een manager + werknemer aan → laat het versleutelde `.db` zien.
3. Login als de werknemer → claim toevoegen, zoeken, bewerken.
4. Foute invoer tonen (zip in kleine letters, afstand 0, datum buiten venster).
5. SQL-injectie in de login → mislukt.
6. Backup maken, dingen doen, oudere backup terugzetten → logs blijven staan.
7. Logs tonen met de verdachte regels + de alert.
8. `python tests/security_tests.py` → alles groen.
