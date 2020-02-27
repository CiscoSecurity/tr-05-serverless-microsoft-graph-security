from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from ctrlibrary.core.utils import get_observables


def test_positive_enrich_observe_observables_sha256(module_headers):
    """Perform testing for enrich observe observables endpoint for sha256 in
    Graph Security module

    CCTRI-354-38e92acf-45e2-4ff6-b5f4-c7e7f4e20f2d

    Steps:
        1. Send request with observable that has SHA256 type to observe
            observables endpoint

    Expectedresults:
        1. Check that data in response body contains expected information
            from Microsoft Graph Security module

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
        'schema_version': '1.0.12',
        'sensor': 'endpoint',
        'severity': 'Medium',
        'source': 'Microsoft Graph Security',
        'title': 'Right-to-Left-Override (RLO) technique observed',
        'type': 'sighting'
    }

    # Get sightings
    observables = [{"value": observable, "type": observable_type}]
    response = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    direct_observables = get_observables(response, 'Microsoft Graph Security')

    # Check respond data
    sightings = direct_observables['data']['sightings']
    assert sightings['count'] == 2
    sighting = sightings['docs'][0]
    assert sighting['observables'] == observables

    for key in expected_observable.keys():
        assert expected_observable[key] == sighting[key]


def test_positive_enrich_observe_observables_domain(module_headers):
    """ Perform testing for enrich observe observables endpoint for domain in
    Graph Security module

    CCTRI-354-91094c36-a118-48a6-9ba9-5f73a1f63208

    Steps:
        1. Send request with observable that has domain type to observe
            observables endpoint

    Expectedresults:
        1. Check that data in response body contains expected information
            from Microsoft Graph Security module

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
    response = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers})['data']
    direct_observables = get_observables(response, 'Microsoft Graph Security')

    # Check respond data
    sightings = direct_observables['data']['sightings']
    assert sightings['count'] == 1
    sighting = sightings['docs'][0]
    assert sighting['observables'] == observables
    assert set(sighting['observed_time'].keys()) == {'start_time', 'end_time'}

    for key in expected_observable.keys():
        assert expected_observable[key] == sighting[key]


def test_positive_enrich_observe_observables_ip(module_headers):
    """ Perform testing for enrich observe observables endpoint for IP in
    Graph Security module

    ID: CCTRI-467-63340fd2-3ed5-44f5-b274-c5595322dc43

    Steps:
        1. Send request with observable that has IP type to observe
            observables endpoint

    Expectedresults:
        1. Check that data in response body contains expected information
            from Microsoft Graph Security module

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
    response = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    direct_observables = get_observables(response, 'Microsoft Graph Security')

    # Check respond data
    sightings = direct_observables['data']['sightings']
    assert sightings['count'] == 1
    sighting = sightings['docs'][0]
    assert sighting['observables'] == observables
    assert set(sighting['observed_time'].keys()) == {'start_time', 'end_time'}

    for key in expected_observable.keys():
        assert expected_observable[key] == sighting[key]


def test_positive_enrich_observe_observables_url(module_headers):
    """ Perform testing for enrich observe observables endpoint for URL in
    Graph Security module

    ID: CCTRI-468-dfcd642e-f02b-428b-9695-168e7d59d533

    Steps:
        1. Send request with observable that has URL type to observe
            observables endpoint

    Expectedresults:
        1. Check that data in response body contains expected information
            from Microsoft Graph Security module

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
    response = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    direct_observables = get_observables(response, 'Microsoft Graph Security')

    # Check respond data
    sightings = direct_observables['data']['sightings']
    assert sightings['count'] == 1
    sighting = sightings['docs'][0]
    assert sighting['observables'] == observables
    assert set(sighting['observed_time'].keys()) == {'start_time', 'end_time'}

    for key in expected_observable.keys():
        assert expected_observable[key] == sighting[key]


def test_positive_enrich_observe_observables_hostname(module_headers):
    """ Perform testing for enrich observe observables endpoint for HOSTNAME in
    Graph Security module

    ID: CCTRI-472-67881b85-20d7-4f11-94d6-dd228d72753c

    Steps:
        1. Send request with observable that has HOSTNAME type to observe
            observables endpoint

    Expectedresults:
        1. Check that data in response body contains expected information
            from Microsoft Graph Security module

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
    response = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    direct_observables = get_observables(response, 'Microsoft Graph Security')

    # Check respond data
    sightings = direct_observables['data']['sightings']
    assert sightings['count'] == 1
    sighting = sightings['docs'][0]
    assert sighting['observables'] == observables
    assert set(sighting['observed_time'].keys()) == {'start_time', 'end_time'}

    for key in expected_observable.keys():
        assert expected_observable[key] == sighting[key]


def test_positive_enrich_observe_observables_file_path(module_headers):
    """ Perform testing for enrich observe observables endpoint for FILE_PATH
    in Graph Security module

    ID: CCTRI-471-a7435d3f-2160-43c6-b8de-a2da65f9c40d

    Steps:
        1. Send request with observable that has FILE_PATH type to observe
            observables endpoint

    Expectedresults:
        1. Check that data in response body contains expected information
            from Microsoft Graph Security module

    Importance: Critical
    """
    observable = 'C:\\Windows\\SYSTEM32\\ntdll.dll'
    observable_type = 'file_path'

    expected_observable = {
        'schema_version': '1.0.12',
        'sensor': 'endpoint',
        'source': 'Microsoft Graph Security',
        'type': 'sighting'
    }

    # Get sightings
    observables = [{"value": observable, "type": observable_type}]
    response = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    direct_observables = get_observables(response, 'Microsoft Graph Security')

    # Check respond data
    sightings = direct_observables['data']['sightings']
    assert sightings['count'] == 2
    sighting = sightings['docs'][0]
    assert sighting['observables'] == observables
    assert set(sighting['observed_time'].keys()) == {'start_time', 'end_time'}

    for key in expected_observable.keys():
        assert expected_observable[key] == sighting[key]


def test_positive_enrich_observe_observables_file_name(module_headers):
    """ Perform testing for enrich observe observables endpoint for file_name
    in Graph Security module

    ID: CCTRI-470-ef6c5b84-ac4e-463d-bf3f-bf8dd08b7a07

    Steps:
        1. Send request with observable that has file_name type to observe
            observables endpoint

    Expectedresults:
        1. Check that data in response body contains expected information
            from Microsoft Graph Security module

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
        'schema_version': '1.0.12',
        'sensor': 'endpoint',
        'severity': 'Medium',
        'source': 'Microsoft Graph Security',
        'title': 'Right-to-Left-Override (RLO) technique observed',
        'type': 'sighting'
    }

    # Get sightings
    observables = [{"value": observable, "type": observable_type}]
    response = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    direct_observables = get_observables(response, 'Microsoft Graph Security')

    # Check respond data
    sightings = direct_observables['data']['sightings']
    sighting = sightings['docs'][0]
    assert sighting['observables'] == observables
    assert set(sighting['observed_time'].keys()) == {'start_time', 'end_time'}

    for key in expected_observable.keys():
        assert expected_observable[key] == sighting[key]
