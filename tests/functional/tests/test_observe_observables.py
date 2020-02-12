

def test_positive_relay_observe_observables_domain(relay_api):
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


def test_positive_relay_observe_observables_ip(relay_api):
    """ Test relay observe observables api mock for IP in Graph Security

    ID: CCTRI-467-4a8ae2af-56d8-478d-bb5a-b6da0a55c882

    Steps:
        1. Send request with IP type to endpoint observe observables

    Expectedresults:
        1. Check data in body respond

    Importance: Critical
    """
    observable = '10.8.168.41'
    observable_type = 'ip'

    expected_observable = {
        'description': (
            'SQL Injection, Cross-Site Scripting. We observed the following '
            'suspicious value enter the application through the HTTP Request '
            'Parameter "userid":POST /WebGoat/SqlInjection/attack5b HTTP/1.0 '
            'userid=4+OR+1%3D1 This value was again observed altering the '
            'meaning of the SQL query executed within '
            'org.hsqldb.jdbc.JDBCStatement.executeQuery(Unknown Source):'
            'SELECT * FROM user_data WHERE userid = 4 OR 1=1.'
        ),
        'external_ids': ['257F2933-A145-4061-9464-2D964A91EB91'],
        'schema_version': '1.0.12',
        'sensor': 'endpoint',
        'severity': 'High',
        'source': 'Microsoft Graph Security',
        'title': 'Active attack EXPLOITED in QA',
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


def test_positive_relay_observe_observables_url(relay_api):
    """ Test relay observe observables api mock for url in Graph Security

    ID: CCTRI-468-dfcd642e-f02b-428b-9695-168e7d59d533


    Steps:
        1. Send request with url type to endpoint observe observables

    Expectedresults:
        1. Check data in body respond

    Importance: Critical
    """
    observable = 'http://register.fabricam.com/start.php'
    observable_type = 'url'

    expected_observable = {
        'description': (
            'Analysis of host data detected a powershell script running on '
            'LAP-DOUGLASF that has features in common with known suspicious '
            'scripts. This script could either be legitimate activity, or an '
            'indication of a compromised host.'
        ),
        'external_ids': ['D16B2923-2134-4F94-9FF1-B40761EA3E1D'],
        'schema_version': '1.0.12',
        'sensor': 'endpoint',
        'severity': 'Medium',
        'source': 'Microsoft Graph Security',
        'title': 'Suspicious Powershell Activity Detected',
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


def test_positive_relay_observe_observables_hostname(relay_api):
    """ Test relay observe observables api mock for hostname in Graph Security

    ID: CCTRI-472-67881b85-20d7-4f11-94d6-dd228d72753c

    Steps:
        1. Send request with hostname type to endpoint observe observables

    Expectedresults:
        1. Check data in body respond

    Importance: Critical
    """
    observable = 'DT-ALDOM'
    observable_type = 'hostname'

    expected_observable = {
        'description': (
            'The system process c:\\windows\\fonts\\csrss.exe was observed '
            'running in an abnormal context. Malware often use this process '
            'name to masquerade its malicious activity.'
        ),
        'external_ids': ['597E99F8-50B6-4D7B-A45A-A35BDB35EFF8'],
        'schema_version': '1.0.12',
        'sensor': 'endpoint',
        'severity': 'Medium',
        'source': 'Microsoft Graph Security',
        'title': 'Suspicious system process executed',
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


def test_positive_relay_observe_observables_sha256(relay_api):
    """ Test relay observe observables api mock for file hash in Graph Security

    ID: CCTRI-469-a879c402-cb6f-441c-8c0c-458a6e456217

    Steps:
        1. Send request with file hash type to endpoint observe observables

    Expectedresults:
        1. Check data in body respond

    Importance: Critical
    """
    observable = (
        '091835b16192e526ee1b8a04d0fcef534544cad306672066f2ad6973a4b18b19')
    observable_type = 'sha256'

    expected_observable = {
        'description': (
            'Attackers can implant the right-to-left-override (RLO) in a '
            'filename to change the order of the characters in the filename '
            'and make it appear legitimate.  This technique is used in '
            'different social engineering attacks to convince the user to run'
            ' the file, and may also be used for hiding purposes.  The file '
            'photoviewgpj.ps1 disguises itself as photoview1sp.jpg'
        ),
        'external_ids': ['EF76CDE9-C3C4-4A83-9707-9EF003C379BB'],
        'schema_version': '1.0.12',
        'sensor': 'endpoint',
        'severity': 'Medium',
        'source': 'Microsoft Graph Security',
        'title': 'Right-to-Left-Override (RLO) technique observed',
        'type': 'sighting'
    }

    # Get sightings
    observables = [{"value": observable, "type": observable_type}]
    sightings = relay_api.observe_observables(
        payload=observables).json()['data']['sightings']

    # Check respond data
    assert sightings['count'] == 2
    sighting = sightings['docs'][0]
    assert sighting['observables'] == observables
    assert set(sighting['observed_time'].keys()) == {'start_time', 'end_time'}

    for key in expected_observable.keys():
        assert expected_observable[key] == sighting[key]


def test_positive_relay_observe_observables_path(relay_api):
    """ Test relay observe observables api mock for file path in Graph Security

    ID: CCTRI-471-a7435d3f-2160-43c6-b8de-a2da65f9c40d

    Steps:
        1. Send request with file path type to endpoint observe observables

    Expectedresults:
        1. Check data in body respond

    Importance: Critical
    """
    observable = 'C:\\Windows\\SYSTEM32\\ntdll.dll'
    observable_type = 'file_path'

    expected_observable = {
        'description': (
            'A process suspiciously tried to access the export address table '
            '(EAT) to look for potentially useful APIs. This might indicate an'
            ' exploitation attempt. The process svchost.exe, with process ID '
            '404, tried accessing the Export Address table for module '
            'C:\\\\Windows\\\\SYSTEM32\\\\ntdll.dll and was blocked'
        ),
        'external_ids': ['0F72C58F-1D01-4284-BB32-C53DD45B5C01'],
        'schema_version': '1.0.12',
        'sensor': 'endpoint',
        'severity': 'High',
        'source': 'Microsoft Graph Security',
        'title': 'Exploit Guard blocked dynamic code execution',
        'type': 'sighting'
    }

    # Get sightings
    observables = [{"value": observable, "type": observable_type}]
    sightings = relay_api.observe_observables(
        payload=observables).json()['data']['sightings']

    # Check respond data
    assert sightings['count'] == 2
    sighting = sightings['docs'][0]
    assert sighting['observables'] == observables
    assert set(sighting['observed_time'].keys()) == {'start_time', 'end_time'}

    for key in expected_observable.keys():
        assert expected_observable[key] == sighting[key]


def test_positive_relay_observe_observables_file_name(relay_api):
    """ Test relay observe observables api mock for file name in Graph Security

    ID: CCTRI-470-ef6c5b84-ac4e-463d-bf3f-bf8dd08b7a07

    Steps:
        1. Send request with file name type to endpoint observe observables

    Expectedresults:
        1. Check data in body respond

    Importance: Critical
    """
    observable = 'photoview1sp.jpg'
    observable_type = 'file_name'

    expected_observable = {
        'description': (
            'Attackers can implant the right-to-left-override (RLO) in a '
            'filename to change the order of the characters in the filename '
            'and make it appear legitimate.  This technique is used in '
            'different social engineering attacks to convince the user to run '
            'the file, and may also be used for hiding purposes.  The file '
            'photoviewgpj.ps1 disguises itself as photoview1sp.jpg'),
        'external_ids': ['EF76CDE9-C3C4-4A83-9707-9EF003C379BB'],
        'schema_version': '1.0.12',
        'sensor': 'endpoint',
        'severity': 'Medium',
        'source': 'Microsoft Graph Security',
        'title': 'Right-to-Left-Override (RLO) technique observed',
        'type': 'sighting'
    }

    # Get sightings
    observables = [{"value": observable, "type": observable_type}]
    sightings = relay_api.observe_observables(
        payload=observables).json()['data']['sightings']

    # Check respond data
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
