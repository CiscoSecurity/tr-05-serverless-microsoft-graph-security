import pytest
import random

from tests.functional.library.constants import OBSERVABLE_DICT


@pytest.mark.parametrize("relay_endpoint", (
        "health",
        "deliberate_observables",
        "refer_observables",
        "observe_observables",
        "respond_observables",
        "respond_trigger"
))
def test_positive_relay_api(relay_endpoint, relay_api):
    """ Test relay api mock in Graph Security

    ID: CCTRI-357-2791fe6b-896a-4e8b-b2f6-0f8fce2b00fb

    Steps:
        1. Send request to endpoint

    Expectedresults:
        1. Status code == 200

    Importance: Critical
    """
    observable_value, observable_type = random.choice(
        list(OBSERVABLE_DICT.items()))
    observables = [{'value': observable_value, 'type': observable_type}]
    # Check status
    assert relay_api.__getattribute__(relay_endpoint)(
        payload=observables).status_code == 200
