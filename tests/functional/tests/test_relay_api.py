import pytest
import random

from ctrlibrary.core import settings
from tests.functional.library.relay_api import (
    relay_health,
    relay_deliberate_observables,
    relay_refer_observables,
    relay_observe_observables,
    relay_respond_observables,
    relay_respond_trigger
)
from tests.functional.library.constants import OBSERVABLE_DICT


@pytest.mark.parametrize("relay_endpoint", (
        relay_health,
        relay_deliberate_observables,
        relay_refer_observables,
        relay_observe_observables,
        relay_respond_observables,
        relay_respond_trigger
))
def test_positive_relay_api(relay_endpoint, session_headers):
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
    assert relay_endpoint(
        payload=observables,
        **{'headers': session_headers}).status_code == 200


@pytest.mark.skip('Not implemented')
@pytest.mark.parametrize("relay_endpoint", (
        relay_health,
        relay_deliberate_observables,
        relay_refer_observables,
        relay_observe_observables,
        relay_respond_observables,
        relay_respond_trigger
))
def test_negative_disable_basic_auth_for_relay_endpoints(relay_endpoint):
    """ Basic auth must be disable in relay API for Graph Security

    ID: CCTRI-355-f4a774dc-5b49-4b7d-958d-9c483e7fb325

    Steps:
        1. Send request to relay endpoint with basic auth

    Expectedresults:
        1. Status code == 401
        2. Error message == "Basic Auth is not supported"

    Importance: Major
    """
    response = relay_endpoint(**{'auth': (
        settings.server.app_login, settings.server.app_password)})

    assert response.status_code == 401
    assert (response.json()['errors'][0][
                'message'] == 'Basic Auth is not supported')
