"""
authorization.py - Role-Based Access Control op een plek.

Een vaste tabel koppelt elke rol aan precies de acties die hij mag uitvoeren.
Elke service vraagt `require(user, PERMISSION)` voordat hij iets doet.
"""

import config


# --- Permissie-namen ------------------------------------------------------
PASSWORD_UPDATE_OWN = "password.update_own"
ACCOUNT_UPDATE_OWN = "account.update_own"
ACCOUNT_DELETE_OWN = "account.delete_own"

CLAIM_ADD = "claim.add"
CLAIM_EDIT_OWN = "claim.edit_own"
CLAIM_VIEW_OWN = "claim.view_own"
CLAIM_MODIFY = "claim.modify"          # projectnummer + reisafstand
CLAIM_APPROVE = "claim.approve"
CLAIM_SET_SALARY_BATCH = "claim.salary_batch"
CLAIM_SEARCH = "claim.search"

EMPLOYEE_ADD = "employee.add"
EMPLOYEE_UPDATE = "employee.update"
EMPLOYEE_DELETE = "employee.delete"
EMPLOYEE_RESET_PASSWORD = "employee.reset_password"
EMPLOYEE_SEARCH = "employee.search"

MANAGER_ADD = "manager.add"
MANAGER_UPDATE = "manager.update"
MANAGER_DELETE = "manager.delete"
MANAGER_RESET_PASSWORD = "manager.reset_password"

BACKUP_CREATE = "backup.create"
BACKUP_RESTORE_ANY = "backup.restore_any"
BACKUP_RESTORE_WITH_CODE = "backup.restore_with_code"
RESTORE_CODE_GENERATE = "restore_code.generate"
RESTORE_CODE_REVOKE = "restore_code.revoke"

VIEW_LOGS = "logs.view"


# --- Welke rol mag wat ----------------------------------------------------
_EMPLOYEE_PERMS = {
    PASSWORD_UPDATE_OWN,
    CLAIM_ADD, CLAIM_EDIT_OWN, CLAIM_VIEW_OWN,
}

_MANAGER_PERMS = {
    PASSWORD_UPDATE_OWN, ACCOUNT_UPDATE_OWN, ACCOUNT_DELETE_OWN,
    CLAIM_MODIFY, CLAIM_APPROVE, CLAIM_SET_SALARY_BATCH, CLAIM_SEARCH,
    EMPLOYEE_ADD, EMPLOYEE_UPDATE, EMPLOYEE_DELETE,
    EMPLOYEE_RESET_PASSWORD, EMPLOYEE_SEARCH,
    BACKUP_CREATE, BACKUP_RESTORE_WITH_CODE, VIEW_LOGS,
}

# Super-admin: alle manager-acties + managerbeheer + volledige backup-controle,
# maar GEEN eigen wachtwoord/account wijzigen en GEEN restore-with-code.
_SUPER_PERMS = {
    CLAIM_MODIFY, CLAIM_APPROVE, CLAIM_SET_SALARY_BATCH, CLAIM_SEARCH,
    EMPLOYEE_ADD, EMPLOYEE_UPDATE, EMPLOYEE_DELETE,
    EMPLOYEE_RESET_PASSWORD, EMPLOYEE_SEARCH,
    MANAGER_ADD, MANAGER_UPDATE, MANAGER_DELETE, MANAGER_RESET_PASSWORD,
    BACKUP_CREATE, BACKUP_RESTORE_ANY,
    RESTORE_CODE_GENERATE, RESTORE_CODE_REVOKE, VIEW_LOGS,
}

PERMISSIONS = {
    config.ROLE_EMPLOYEE: _EMPLOYEE_PERMS,
    config.ROLE_MANAGER: _MANAGER_PERMS,
    config.ROLE_SUPER_ADMIN: _SUPER_PERMS,
}


class AuthorizationError(Exception):
    """De huidige gebruiker mist de vereiste permissie."""


def has_permission(user, permission):
    if user is None:
        return False
    return permission in PERMISSIONS.get(user.get("role"), set())


def require(user, permission):
    if not has_permission(user, permission):
        raise AuthorizationError("You are not allowed to perform this action.")
