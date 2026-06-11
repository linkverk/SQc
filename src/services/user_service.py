"""
user_service.py - Bedrijfslogica voor accounts en werknemers.

Elke methode krijgt `actor` = de ingelogde gebruiker en begint met de
autorisatie-check. Daarna hervalideren we de velden op deze servicegrens
(defense in depth): de UI valideert al, maar komt een ongeldige waarde hier
toch binnen, dan is de UI omzeild -> dat is manipulatie, dus afbreken + loggen.
"""

from datetime import datetime

import config
from data.repositories import UserRepository, EmployeeRepository
from security import hashing
from services import authorization as az
from services import generators
from services.input_guard import assert_valid
from validation import validators as v


# Validators voor de account-/naamvelden.
_ACCOUNT_FIELD_VALIDATORS = {
    "username": v.is_valid_username,
    "password": v.is_valid_password,
    "first_name": v.is_valid_name,
    "last_name": v.is_valid_name,
}

# Validators voor de profielvelden (Tabel 2). 'phone' staat hier niet bij: die
# wordt server-side samengesteld uit 8 al-gevalideerde cijfers.
_PROFILE_FIELD_VALIDATORS = {
    "birthday": v.is_valid_birthday,
    "street": v.is_valid_name,
    "house_number": v.is_valid_house_number,
    "zip": v.is_valid_zip,
    "email": v.is_valid_email,
    "doc_number": v.is_valid_doc_number,
    "bsn": v.is_valid_bsn,
    "gender": v.is_valid_gender,
    "city": v.is_valid_city,
    "doc_type": v.is_valid_doc_type,
}


class UserService:
    def __init__(self, log_service):
        self._users = UserRepository()
        self._employees = EmployeeRepository()
        self._log = log_service

    def _now(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def username_available(self, username):
        return not self._users.username_exists(username)

    def _assert_fields(self, actor, values, validator_map, action):
        """Assert elk veld met een validator (abort + log bij manipulatie).

        Velden zonder validator (bijv. een geinjecteerde 'role') slaan we over;
        die negeert de repository-allow-list sowieso.
        """
        if not values:
            return
        for field_name, value in values.items():
            if value is None:
                continue
            is_valid = validator_map.get(field_name)
            if is_valid is not None:
                assert_valid(self._log, actor, field_name, value, is_valid, action)

    # --- Werknemers -------------------------------------------------------
    def add_employee(self, actor, username, password, first_name, last_name,
                     profile):
        """Maak een werknemeraccount + werknemerrecord. Geeft het employee_id."""
        az.require(actor, az.EMPLOYEE_ADD)
        self._assert_fields(
            actor,
            {"username": username, "password": password,
             "first_name": first_name, "last_name": last_name},
            _ACCOUNT_FIELD_VALIDATORS, "adding an employee")
        self._assert_fields(actor, profile, _PROFILE_FIELD_VALIDATORS,
                            "adding an employee")
        if self._users.username_exists(username):
            raise ValueError("That username is already taken.")

        user_id = self._users.create_user(
            username=username,
            password_hash=hashing.hash_password(password),
            role=config.ROLE_EMPLOYEE,
            first_name=first_name,
            last_name=last_name,
            registration_date=self._now(),
        )
        employee_id = generators.generate_employee_id(
            self._employees.employee_id_exists
        )
        self._employees.create_employee(user_id, employee_id, profile)
        self._log.log(actor["username"], "New employee created",
                      info=f"username: {username}, employee_id: {employee_id}")
        return employee_id

    def update_employee(self, actor, employee_user_id, names=None, profile=None):
        az.require(actor, az.EMPLOYEE_UPDATE)
        if names:
            self._assert_fields(actor, names, _ACCOUNT_FIELD_VALIDATORS,
                                "updating an employee")
        self._assert_fields(actor, profile, _PROFILE_FIELD_VALIDATORS,
                            "updating an employee")
        target = self._users.get_by_id(employee_user_id)
        if target is None or target["role"] != config.ROLE_EMPLOYEE:
            raise ValueError("Employee not found.")
        if names:
            self._users.update_profile(
                employee_user_id,
                names.get("first_name", target["first_name"]),
                names.get("last_name", target["last_name"]),
            )
        if profile:
            self._employees.update_employee(employee_user_id, profile)
        self._log.log(actor["username"], "Employee updated",
                      info=f"username: {target['username']}")

    def delete_employee(self, actor, employee_user_id):
        az.require(actor, az.EMPLOYEE_DELETE)
        target = self._users.get_by_id(employee_user_id)
        if target is None or target["role"] != config.ROLE_EMPLOYEE:
            raise ValueError("Employee not found.")
        self._users.delete_user(employee_user_id)  # cascade werknemer + claims
        self._log.log(actor["username"], "Employee deleted",
                      info=f"username: {target['username']}")

    def reset_employee_password(self, actor, employee_user_id):
        az.require(actor, az.EMPLOYEE_RESET_PASSWORD)
        target = self._users.get_by_id(employee_user_id)
        if target is None or target["role"] != config.ROLE_EMPLOYEE:
            raise ValueError("Employee not found.")
        temp = generators.generate_temp_password()
        self._users.update_password(employee_user_id,
                                    hashing.hash_password(temp),
                                    must_change_password=1)
        self._log.log(actor["username"], "Employee password reset",
                      info=f"username: {target['username']}")
        return temp

    # --- Managers (alleen super-admin) ------------------------------------
    def add_manager(self, actor, username, password, first_name, last_name):
        az.require(actor, az.MANAGER_ADD)
        self._assert_fields(
            actor,
            {"username": username, "password": password,
             "first_name": first_name, "last_name": last_name},
            _ACCOUNT_FIELD_VALIDATORS, "adding a manager")
        if self._users.username_exists(username):
            raise ValueError("That username is already taken.")
        self._users.create_user(
            username=username,
            password_hash=hashing.hash_password(password),
            role=config.ROLE_MANAGER,
            first_name=first_name,
            last_name=last_name,
            registration_date=self._now(),
        )
        self._log.log(actor["username"], "New manager created",
                      info=f"username: {username}")

    def update_manager(self, actor, manager_user_id, names):
        az.require(actor, az.MANAGER_UPDATE)
        self._assert_fields(actor, names, _ACCOUNT_FIELD_VALIDATORS,
                            "updating a manager")
        target = self._users.get_by_id(manager_user_id)
        if target is None or target["role"] != config.ROLE_MANAGER:
            raise ValueError("Manager not found.")
        self._users.update_profile(
            manager_user_id,
            names.get("first_name", target["first_name"]),
            names.get("last_name", target["last_name"]),
        )
        self._log.log(actor["username"], "Manager updated",
                      info=f"username: {target['username']}")

    def delete_manager(self, actor, manager_user_id):
        az.require(actor, az.MANAGER_DELETE)
        target = self._users.get_by_id(manager_user_id)
        if target is None or target["role"] != config.ROLE_MANAGER:
            raise ValueError("Manager not found.")
        self._users.delete_user(manager_user_id)
        self._log.log(actor["username"], "Manager deleted",
                      info=f"username: {target['username']}")

    def reset_manager_password(self, actor, manager_user_id):
        az.require(actor, az.MANAGER_RESET_PASSWORD)
        target = self._users.get_by_id(manager_user_id)
        if target is None or target["role"] != config.ROLE_MANAGER:
            raise ValueError("Manager not found.")
        temp = generators.generate_temp_password()
        self._users.update_password(manager_user_id,
                                    hashing.hash_password(temp),
                                    must_change_password=1)
        self._log.log(actor["username"], "Manager password reset",
                      info=f"username: {target['username']}")
        return temp

    # --- Eigen account ----------------------------------------------------
    def update_own_password(self, actor, old_password, new_password):
        az.require(actor, az.PASSWORD_UPDATE_OWN)
        # Het oude wachtwoord checken we tegen de hash; het nieuwe moet aan de
        # wachtwoordregels voldoen.
        self._assert_fields(actor, {"password": new_password},
                            _ACCOUNT_FIELD_VALIDATORS, "changing own password")
        fresh = self._users.get_by_id(actor["id"])
        if fresh is None or not hashing.verify_password(
                fresh["password_hash"], old_password):
            raise ValueError("Current password is incorrect.")
        self._users.update_password(actor["id"],
                                    hashing.hash_password(new_password),
                                    must_change_password=0)
        self._log.log(actor["username"], "Own password changed")

    def update_own_account(self, actor, first_name=None, last_name=None,
                           new_username=None):
        az.require(actor, az.ACCOUNT_UPDATE_OWN)
        self._assert_fields(
            actor,
            {"username": new_username, "first_name": first_name,
             "last_name": last_name},
            _ACCOUNT_FIELD_VALIDATORS, "updating own account")
        if new_username and new_username.lower() != actor["username"].lower():
            if self._users.username_exists(new_username):
                raise ValueError("That username is already taken.")
            self._users.update_username(actor["id"], new_username)
            actor["username"] = new_username
        if first_name is not None or last_name is not None:
            new_first = first_name
            if new_first is None:
                new_first = actor.get("first_name", "")
            new_last = last_name
            if new_last is None:
                new_last = actor.get("last_name", "")
            self._users.update_profile(actor["id"], new_first, new_last)
        self._log.log(actor["username"], "Own account updated")

    def delete_own_account(self, actor):
        az.require(actor, az.ACCOUNT_DELETE_OWN)
        self._users.delete_user(actor["id"])
        self._log.log(actor["username"], "Own account deleted")

    # --- Lijsten & zoeken (een deel van een waarde mag) -------------------
    def list_role(self, actor, role):
        if role == config.ROLE_EMPLOYEE:
            az.require(actor, az.EMPLOYEE_SEARCH)
        else:
            az.require(actor, az.MANAGER_UPDATE)   # managers tonen = super-admin
        return self._users.list_by_role(role)

    def search_employees(self, actor, key):
        """Geef werknemers terug waarvan een ontsleuteld veld de sleutel bevat."""
        az.require(actor, az.EMPLOYEE_SEARCH)
        key = key.lower()
        results = []
        for emp in self._employees.list_all():
            user = self._users.get_by_id(emp["user_id"])
            if user is None:
                continue
            merged = dict(emp)                       # maak een kopie
            merged["username"] = user["username"]
            merged["first_name"] = user["first_name"]
            merged["last_name"] = user["last_name"]
            parts = []
            for value in merged.values():
                parts.append(str(value))
            haystack = " ".join(parts).lower()
            if key in haystack:
                results.append(merged)
        self._log.log(actor["username"], "Searched employees", info=f'key: "{key}"')
        return results

    def get_employee_overview(self, actor, employee_user_id):
        az.require(actor, az.EMPLOYEE_SEARCH)
        user = self._users.get_by_id(employee_user_id)
        emp = self._employees.get_by_user_id(employee_user_id)
        if user is None or emp is None:
            return None
        overview = dict(emp)                          # maak een kopie
        overview["username"] = user["username"]
        overview["first_name"] = user["first_name"]
        overview["last_name"] = user["last_name"]
        overview["registration_date"] = user["registration_date"]
        return overview
