"""
claim_service.py - Bedrijfslogica voor reis-/thuiswerk-declaraties (Tabel 3).

* Werknemer: claims toevoegen, en eigen claims wijzigen/verwijderen zolang ze
  niet aan een salaris-batch hangen (locked == False).
* Het employee_id op een claim komt van de ingelogde werknemer, nooit getypt.
* Manager / super-admin: alleen projectnummer + reisafstand wijzigen, en
  goed-/afkeuren. Een goedgekeurde claim zit in een salaris-batch en is daarna
  voor iedereen onwijzigbaar.
"""

import config
from data.repositories import ClaimRepository, EmployeeRepository
from services import authorization as az
from services.input_guard import assert_valid
from validation import validators as v


# Velden die een werknemer nooit zelf op een claim mag zetten: de server bepaalt
# ze (goedkeuringsworkflow / ingelogde identiteit). Komen ze toch in de invoer
# voor, dan is dat manipulatie -> afbreken + loggen.
_SERVER_CONTROLLED_CLAIM_FIELDS = {
    "approved", "approved_by", "salary_batch", "locked",
    "owner_user_id", "employee_id", "id",
}


class ClaimService:
    def __init__(self, log_service):
        self._claims = ClaimRepository()
        self._employees = EmployeeRepository()
        self._log = log_service

    def _abort_on_server_field_tampering(self, actor, data, action):
        """Breek af als de invoer een server-gestuurd veld probeert te zetten."""
        forbidden = []
        for field_name in data:
            if field_name in _SERVER_CONTROLLED_CLAIM_FIELDS:
                forbidden.append(field_name)
        forbidden.sort()
        if forbidden:
            self._log.log(
                actor["username"], "Suspicious input - operation aborted",
                info=f"attempt to set server-controlled field(s) "
                     f"{', '.join(forbidden)} while {action}",
                suspicious=True,
            )
            raise ValueError("Bad input. Incident logged.")

    # --- Acties van de werknemer ------------------------------------------
    def add_claim(self, actor, data):
        az.require(actor, az.CLAIM_ADD)
        emp = self._employees.get_by_user_id(actor["id"])
        if emp is None:
            raise ValueError("No employee record is linked to this account.")
        self._abort_on_server_field_tampering(actor, data, "adding a claim")
        assert_valid(self._log, actor, "claim_type", data.get("claim_type", ""),
                     v.is_valid_claim_type, "adding a claim")
        data = dict(data)
        data["employee_id"] = emp["employee_id"]   # server-set
        # Bij een Home Office-claim blijven de reisvelden leeg.
        if data.get("claim_type") == "Home Office":
            for field in ("distance", "from_zip", "from_house", "to_zip", "to_house"):
                data[field] = ""
        claim_id = self._claims.create_claim(actor["id"], data)
        self._log.log(actor["username"], "Claim added",
                      info=f"claim_id: {claim_id}, type: {data.get('claim_type')}")
        return claim_id

    def _owned_unlocked(self, actor, claim_id):
        """Geef de eigen, nog niet vergrendelde claim terug (of raise)."""
        claim = self._claims.get_by_id(claim_id)
        if claim is None or claim["owner_user_id"] != actor["id"]:
            raise ValueError("Claim not found.")
        if claim["locked"]:
            raise ValueError("This claim is already in a salary batch and can no "
                             "longer be changed.")
        return claim

    def update_own_claim(self, actor, claim_id, data):
        az.require(actor, az.CLAIM_EDIT_OWN)
        self._owned_unlocked(actor, claim_id)
        self._abort_on_server_field_tampering(actor, data, "updating a claim")
        assert_valid(self._log, actor, "claim_type", data.get("claim_type", ""),
                     v.is_valid_claim_type, "updating a claim")
        if data.get("claim_type") == "Home Office":
            for field in ("distance", "from_zip", "from_house", "to_zip", "to_house"):
                data[field] = ""
        self._claims.update_claim(claim_id, data)
        self._log.log(actor["username"], "Claim updated", info=f"claim_id: {claim_id}")

    def delete_own_claim(self, actor, claim_id):
        az.require(actor, az.CLAIM_EDIT_OWN)
        self._owned_unlocked(actor, claim_id)
        self._claims.delete_claim(claim_id)
        self._log.log(actor["username"], "Claim deleted", info=f"claim_id: {claim_id}")

    def list_own_claims(self, actor):
        az.require(actor, az.CLAIM_VIEW_OWN)
        return self._claims.list_by_owner(actor["id"])

    def search_own_claims(self, actor, key):
        az.require(actor, az.CLAIM_VIEW_OWN)
        return self._filter(self._claims.list_by_owner(actor["id"]), key)

    # --- Acties van manager / super-admin ---------------------------------
    def _not_in_salary_batch(self, claim):
        """Een claim in een salaris-batch is afgehandeld en mag door niemand meer."""
        if claim["locked"]:
            raise ValueError("This claim is already in a salary batch and can "
                             "no longer be changed.")

    def modify_claim(self, actor, claim_id, project_number=None, distance=None):
        az.require(actor, az.CLAIM_MODIFY)
        claim = self._claims.get_by_id(claim_id)
        if claim is None:
            raise ValueError("Claim not found.")
        self._not_in_salary_batch(claim)
        data = {}
        if project_number is not None:
            data["project_number"] = project_number
        if distance is not None and claim["claim_type"] == "Travel":
            data["distance"] = distance
        if data:
            self._claims.update_claim(claim_id, data)
        self._log.log(actor["username"], "Claim modified by manager",
                      info=f"claim_id: {claim_id}")

    def approve_claim(self, actor, claim_id, salary_batch):
        az.require(actor, az.CLAIM_APPROVE)
        claim = self._claims.get_by_id(claim_id)
        if claim is None:
            raise ValueError("Claim not found.")
        self._not_in_salary_batch(claim)
        self._claims.set_approval(claim_id, "Approved", actor["username"],
                                  salary_batch, locked=1)
        self._log.log(actor["username"], "Claim approved",
                      info=f"claim_id: {claim_id}, salary_batch: {salary_batch}")

    def reject_claim(self, actor, claim_id):
        az.require(actor, az.CLAIM_APPROVE)
        claim = self._claims.get_by_id(claim_id)
        if claim is None:
            raise ValueError("Claim not found.")
        self._not_in_salary_batch(claim)
        self._claims.set_approval(claim_id, "Rejected", actor["username"], "", locked=0)
        self._log.log(actor["username"], "Claim rejected", info=f"claim_id: {claim_id}")

    def list_all_claims(self, actor):
        az.require(actor, az.CLAIM_SEARCH)
        return self._claims.list_all()

    def search_claims(self, actor, key):
        az.require(actor, az.CLAIM_SEARCH)
        results = self._filter(self._claims.list_all(), key)
        self._log.log(actor["username"], "Searched claims", info=f'key: "{key}"')
        return results

    def get_claim(self, actor, claim_id):
        claim = self._claims.get_by_id(claim_id)
        if claim is None:
            return None
        # Werknemers mogen alleen hun eigen claim zien.
        if not az.has_permission(actor, az.CLAIM_SEARCH):
            if claim["owner_user_id"] != actor["id"]:
                raise az.AuthorizationError("You may only view your own claims.")
        return claim

    # --- filter op gedeeltelijke sleutel ----------------------------------
    def _filter(self, claims, key):
        key = key.lower()
        result = []
        for claim in claims:
            parts = []
            for value in claim.values():
                parts.append(str(value))
            haystack = " ".join(parts).lower()
            if key in haystack:
                result.append(claim)
        return result
