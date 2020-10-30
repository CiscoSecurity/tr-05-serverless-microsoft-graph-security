import pytest
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from ctrlibrary.core.utils import get_observables
from tests.functional.library.constants import MODULE_NAME


@pytest.mark.parametrize(
    'observable, observable_type',
    (('test.org', 'domain'),
     ('4.3.1.4', 'ip'),
     ('23E83E60311A7F2892A8DD30CA07B6ADAE56BC2A246EDE2E9B5200EF7C2D61F6',
      'sha256'),
     ('test', 'hostname'),
     ('http://register.fabricam.com', 'url'),
     (r'C:\Users\Users\Downloads\Malware', 'file_path'),
     ('test.exe', 'file_name'))
)
def test_positive_smoke_empty_observables(module_headers, observable,
                                          observable_type):
    """Perform testing for enrich observe observables endpoint to check that
     observable, on which Microsoft Graph Security doesn't have information,
     will return empty data

    ID: CCTRI-1707-335903f4-b387-4ad9-8f8b-badfb1ae7f8c

    Steps:
        1. Send request to enrich observe observables endpoint

    Expectedresults:
        1. Response body contains empty data dict from Microsoft Graph Security
         module

    Importance: Critical
    """
    observables = [{"value": observable, "type": observable_type}, ]
    response = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )

    direct_observables = get_observables(response, MODULE_NAME)

    assert direct_observables['module'] == MODULE_NAME
    assert direct_observables['module_instance_id']
    assert direct_observables['module_type_id']

    assert direct_observables['data'] == {}
