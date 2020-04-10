import json

from api.mappings import \
    Domain, Mapping, FileName, FilePath, SHA256, IP, URL, Hostname


def test_mapping_of():
    assert isinstance(Mapping.of('domain'), Domain)
    assert isinstance(Mapping.of('file_name'), FileName)
    assert isinstance(Mapping.of('file_path'), FilePath)
    assert isinstance(Mapping.of('sha256'), SHA256)
    assert isinstance(Mapping.of('ip'), IP)
    assert isinstance(Mapping.of('url'), URL)
    assert isinstance(Mapping.of('hostname'), Hostname)
    assert Mapping.of('whatever') is None


def test_domain_filter():
    mapping = Domain()
    url = mapping.filter('http://danger.com')

    assert url == (
        f"/security/alerts?$filter=networkConnections"
        f"/any(x: x/destinationDomain eq 'http%3A%2F%2Fdanger.com')"
    )


def test_domain_map():
    assert_maps_correctly(Domain(), 'domain.json')


def test_file_name_filter():
    mapping = FileName()
    url = mapping.filter('danger.exe')

    assert url == (
        f"/security/alerts?$filter="
        f"fileStates/any(x: x/name eq 'danger.exe')"
    )


def test_file_name_map():
    assert_maps_correctly(FileName(), 'file_name.json')


def test_file_path_filter():
    mapping = FilePath()
    url = mapping.filter('c://danger.exe')

    assert url == (
        f"/security/alerts?$filter="
        f"fileStates/any(x: x/path eq 'c://danger.exe')"
    )


def test_file_path_map():
    assert_maps_correctly(FilePath(), 'file_path.json')


def test_sha256_filter():
    mapping = SHA256()
    url = mapping.filter('deadbeef')

    assert url == (
        f"/security/alerts?$filter="
        f"fileStates/any(x: x/fileHash/hashValue eq 'deadbeef')"
    )


def test_sha256_map():
    assert_maps_correctly(SHA256(), 'sha256.json')


def test_ip_filter():
    mapping = IP()
    url = mapping.filter('127.0.0.1')

    assert url == (
        f"/security/alerts?$filter="
        f"networkConnections/any(x: "
        f"x/sourceAddress eq '127.0.0.1' or "
        f"x/destinationAddress eq '127.0.0.1'"
        f")"
    )


def test_ip_map():
    assert_maps_correctly(IP(), 'ip.json')


def test_url_filter():
    mapping = URL()
    url = mapping.filter('http://danger.com')

    assert url == (
        f"/security/alerts?$filter="
        f"networkConnections/any(x: x/destinationUrl eq 'http://danger.com')"
    )


def test_url_map():
    assert_maps_correctly(URL(), 'url.json')


def test_hostname_filter():
    mapping = Hostname()
    url = mapping.filter('danger')

    assert url == (
        f"/security/alerts?$filter="
        f"hostStates/any(x: x/netBiosName eq 'danger')"
    )


def test_hostname_map():
    assert_maps_correctly(Hostname(), 'hostname.json')


def assert_maps_correctly(mapping, path):
    with open('tests/unit/data/' + path) as file:
        data = json.loads(file.read())
        output = mapping.map(data['observable'], data['input'])

        assert output.pop('id').startswith('transient:')
        assert output == data['output']
