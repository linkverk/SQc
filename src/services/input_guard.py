"""
input_guard.py - assert_valid voor server-generated input.

Getypte invoer mag een typefout bevatten (die vangt de UI beleefd op). Maar
keuzelijst-/workflow-waarden horen nooit fout te zijn: is zo'n waarde toch
ongeldig, dan is het manipulatie -> we breken de actie af en loggen het.
"""


def assert_valid(log_service, actor, field_name, value, is_valid, action):
    """Breek af + log als een server-generated waarde ongeldig is."""
    if not is_valid(value):
        log_service.log(
            actor["username"], "Suspicious input - operation aborted",
            info=f"invalid server-generated value for '{field_name}' while {action}",
            suspicious=True,
        )
        raise ValueError("Bad input. Incident logged.")
