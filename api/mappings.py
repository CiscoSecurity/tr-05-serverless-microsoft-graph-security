from abc import ABCMeta, abstractmethod
from urllib.parse import quote
from uuid import uuid4

from . import relations
from .client import get_data
from .utils import url_join


class Mapping(metaclass=ABCMeta):

    @classmethod
    def of(cls, type_):
        """Returns an instance of `Mapping` for the specified type."""

        for subcls in Mapping.__subclasses__():
            if subcls.type() == type_:
                return subcls()

        return None

    def get(self, base_url, observable, limit):
        """Retrieves Graph Security alerts and maps them to CTIM."""

        url = url_join(base_url, self.filter(observable)) + f'&$top={limit}'

        response = get_data(url)

        return [
            self.sighting(observable, x) for x in response.get('value', [])
        ]

    @classmethod
    @abstractmethod
    def type(cls):
        """Returns the observable type that the mapping is able to process."""

    @abstractmethod
    def filter(self, observable):
        """Returns a relative URL to Graph Security to query alerts."""

    def sighting(self, observable, data):
        """Maps a Graph Security response to a CTIM sighting."""

        return {
            'id': f'transient:sighting-{uuid4()}',
            'confidence': confidence(data),
            'count': 1,
            'description': data['description'],
            'external_ids': [
                data['id']
            ],
            'external_references': [
                {
                    'source_name': data['vendorInformation']['provider'],
                    'url': url
                }
                for url in data['sourceMaterials']
            ],
            'observables': [
                {
                    'type': self.type(),
                    'value': observable
                }
            ],
            'observed_time': {
                'end_time': data['eventDateTime'],
                'start_time': data['eventDateTime']
            },
            'relations': [],
            'schema_version': '1.0.12',
            'sensor': sensor(data['vendorInformation']),
            'severity': severity(data),
            'source': 'Microsoft Graph Security',
            'targets': [
                {
                    'observables': [
                        {
                            'type': type_,
                            'value': host[value]
                        }
                        for type_, value in [
                            ('ip', 'privateIpAddress'),
                            ('ip', 'publicIpAddress'),
                            ('hostname', 'netBiosName'),
                            ('domain', 'fqdn'),
                        ]
                        if host[value]
                    ],
                    'observed_time': {
                        'start_time': data['eventDateTime'],
                        'end_time': data['eventDateTime']
                    },
                    'type': 'endpoint'
                }
                for host in data['hostStates']
            ],
            'timestamp': data['eventDateTime'],
            'title': data['title'],
            'type': 'sighting'
        }


class Domain(Mapping):

    @classmethod
    def type(cls):
        return 'domain'

    def filter(self, observable):
        return (
            f"/security/alerts?$filter="
            f"networkConnections/any(x: x/destinationDomain eq '{observable}')"
        )

    def sighting(self, observable, data):
        mapped = super(Domain, self).sighting(observable, data)
        mapped['relations'] = relations.network_connections(data)

        return mapped


class FileName(Mapping):

    @classmethod
    def type(cls):
        return 'file_name'

    def filter(self, observable):
        return f"/security/alerts?$filter=" \
               f"fileStates/any(x: x/name eq '{observable}')"

    def sighting(self, observable, data):
        mapped = super(FileName, self).sighting(observable, data)
        mapped['relations'] = relations.file_states(data)

        return mapped


class FilePath(Mapping):

    @classmethod
    def type(cls):
        return 'file_path'

    def filter(self, observable):
        return f"/security/alerts?$filter=" \
               f"fileStates/any(x: x/path eq '{observable}')"

    def sighting(self, observable, data):
        mapped = super(FilePath, self).sighting(observable, data)
        mapped['relations'] = relations.file_states(data)

        return mapped


class SHA256(Mapping):

    @classmethod
    def type(cls):
        return 'sha256'

    def filter(self, observable):
        return f"/security/alerts?$filter=" \
               f"fileStates/any(x: x/fileHash/hashValue eq '{observable}')"

    def sighting(self, observable, data):
        mapped = super(SHA256, self).sighting(observable, data)
        mapped['relations'] = relations.file_states(data)

        return mapped


class IP(Mapping):

    @classmethod
    def type(cls):
        return 'ip'

    def filter(self, observable):
        return (
            f"/security/alerts?$filter="
            f"networkConnections/any(x: "
            f"x/sourceAddress eq '{observable}' or "
            f"x/destinationAddress eq '{observable}'"
            f")"
        )

    def sighting(self, observable, data):
        mapped = super(IP, self).sighting(observable, data)
        mapped['relations'] = relations.network_connections(data)

        return mapped


class URL(Mapping):

    @classmethod
    def type(cls):
        return 'url'

    def filter(self, observable):
        return f"/security/alerts?$filter=" \
               f"networkConnections/any(x: x/destinationUrl eq " \
               f"'{quote(observable, safe='')}')"

    def sighting(self, observable, data):
        mapped = super(URL, self).sighting(observable, data)
        mapped['relations'] = relations.network_connections(data)

        return mapped


class Hostname(Mapping):

    @classmethod
    def type(cls):
        return 'hostname'

    def filter(self, observable):
        return f"/security/alerts?$filter="\
               f"hostStates/any(x: x/netBiosName eq '{observable}')"

    def sighting(self, observable, data):
        mapped = super(Hostname, self).sighting(observable, data)
        mapped['relations'] = relations.network_connections(data)

        return mapped


def severity(data):
    mapping = {
        'unknown': 'Unknown',
        'informational': 'Info',
        'low': 'Low',
        'medium': 'Medium',
        'high': 'High'
    }

    value = data['severity']

    if value in mapping:
        return mapping[value]
    else:
        raise ValueError(f'Unsupported severity: "{value}".')


def confidence(data):
    value = data.get('confidence', None)
    if value is None:
        return 'None'

    segments = [
        (33, 'Low'),
        (66, 'Medium'),
        (100, 'High')
    ]

    for bound, result in segments:
        if value <= bound:
            return result

    return 'Unknown'


def sensor(data):
    provider = data['provider']
    sub_provider = data['subProvider']

    if provider == 'Windows Defender ATP':
        return 'endpoint'

    if provider == 'Palo Alto Networks':
        if sub_provider == 'NGFW':
            return 'network.firewall'
        if sub_provider == 'NG Firewall':
            return 'network.firewall'
        if sub_provider == 'Traps':
            return 'endpoint'

    return 'endpoint'
