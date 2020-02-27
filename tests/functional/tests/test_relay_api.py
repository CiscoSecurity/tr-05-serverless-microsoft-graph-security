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
def test_positive_lambda_relay_api(relay_endpoint, relay_api):
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


def test_positive_lambda_relay_observe_observables_domain(relay_api):
    """ Test relay observe observables api mock for domain in Graph Security

    ID: CCTRI-354-4c96ad24-5a16-449b-9120-0af449d546c6

    Steps:
        1. Send request with domain type to endpoint observe observables

    Expectedresults:
        1. Check data in body respond

    Importance: Critical
    """
    observable = 'www.febrikam.com'
    observable_type = 'domain'

    expected_observable = {
        'description': (
            'A Windows process has connected to a newly registered domain.'
        ),
        'external_ids': ['F007461A-C92F-48E5-A734-89A4E5F38A15'],
        'schema_version': '1.0.12',
        'sensor': 'endpoint',
        'severity': 'Low',
        'source': 'Microsoft Graph Security',
        'title': 'Connection to newly registered domain',
        'type': 'sighting'
    }

    # Get sightings
    observables = [{"value": observable, "type": observable_type}]
    sightings = relay_api.observe_observables(
        payload=observables).json()['data']['sightings']

    # Check respond data
    assert sightings['count'] == 1
    sighting = sightings['docs'][0]
    assert sighting['observables'] == observables
    assert set(sighting['observed_time'].keys()) == {'start_time', 'end_time'}

    for key in expected_observable.keys():
        assert expected_observable[key] == sighting[key]


def test_positive_sighting_complex_sightings(relay_api):
    """Perform testing for relay observe/observables. Make attempt to
    get several Sightings in one request.

    ID: CCTRI-354-a992a318-4447-4675-b09f-a10db12f06b5

    Steps:
        1. Create Two Observables.
        2. Get Sightings for Observables.

    Expectedresults:
        1. Entities created successfully.
        2. Checked data in body respond shown correctly.

    Importance: Critical
    """
    observable_1 = '/path/users/3/update'
    observable_2 = 'www.febrikam.com'
    observable_type_1 = 'file_path'
    observable_type_2 = 'domain'
    observables = [{"value": observable_1, "type": observable_type_1},
                   {"value": observable_2, "type": observable_type_2}]

    sightings = relay_api.observe_observables(
        payload=observables).json()['data']['sightings']

    # Check respond data
    assert sightings['count'] == 2

    assert (sightings['docs'][0]['observables'] +
            sightings['docs'][1]['observables']) == observables


def test_domain_negative_observable_does_not_exist(relay_api):
    """Perform testing for relay observe/observables. Make attempt to
    get observable which doesn't exist in Graph Security

    ID: CCTRI-354-432f0e0a-4806-4fda-906f-2d21e2015eee

    Steps:
        1. Send request with domain type to endpoint observe observables witch
        does not exist.

    Expectedresults:
        1. Got empty result

    Importance: Low
    """
    observable = 'qweeeeeeertrty.com'
    observables = [{'value': observable, 'type': 'domain'}]

    # Check respond data
    sightings = relay_api.observe_observables(
        payload=observables).json()
    assert sightings['data'] == {}


def test_negative_observable_empty_body(relay_api):
    """Make attempt to send empty body in Graph Security

    ID: CCTRI-354-68390ef3-a090-4015-a9a7-a29b39431c52

    Steps:
        1. Send request with domain type to endpoint observe observables witch
        does not exist.

    Expectedresults:
        1. Status code == 400
        2. Error message == "Invalid JSON format."

    Importance: Low
    """
    response = relay_api.observe_observables(payload=None)

    assert response.status_code == 400
    assert (response.json()['message'] == 'Invalid JSON format.')
