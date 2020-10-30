import pytest
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from ctrlibrary.core.utils import get_observables
from tests.functional.library.constants import MODULE_NAME


@pytest.mark.parametrize(
    'observable, observable_type',
    (('willaimsclarke.com', 'domain'),
     ('61.23.79.168', 'ip'),
     ('091835b16192e526ee1b8a04d0fcef534544cad306672066f2ad6973a4b18b19',
      'sha256'),
     ('lap-douglasf', 'hostname'),
     ('http://willaimsclarke.com/lee/fre.php', 'url'),
     (r'C:\Windows\SYSTEM32\ntdll.dll', 'file_path'),
     ('ntdll.dll', 'file_name'))
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

    microsoft_graph_security_data = response['data']

    direct_observables = get_observables(microsoft_graph_security_data,
                                         MODULE_NAME)

    assert direct_observables['module'] == MODULE_NAME
    assert direct_observables['module_instance_id']
    assert direct_observables['module_type_id']

    assert direct_observables['data'] == {}
