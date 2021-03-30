from http import HTTPStatus

import requests
from flask import session, current_app
from requests.exceptions import SSLError, ConnectionError

from api.errors import (
    CriticalResponseError, GraphSSLError, GraphConnectionError,
    AuthorizationError
)

# The Graph Security API accepts the 'User-Agent'
# header in the following format:
#     {CompanyName}-{ProductName}/{Version}

agent = 'Cisco-SecureXThreatResponseMicrosoftGraphSecurity/1.0.0'


def token(credentials, fresh=False):
    """Returns an authorization token."""
    try:
        if fresh or 'token' not in session:
            url = current_app.config['AUTH_URL'] % credentials['tenant_id']

            data = {
                'client_id': credentials['application_id'],
                'client_secret': credentials['client_secret'],
                'grant_type': 'client_credentials',
                'scope': current_app.config['AUTH_SCOPE']
            }

            response = requests.get(url, data=data,
                                    headers={'User-Agent': agent})

            if not response.ok:
                if response.status_code == HTTPStatus.NOT_FOUND:
                    raise AuthorizationError(
                        'Specified Tenant ID was not found'
                    )
                raise CriticalResponseError(response)

            response = response.json()
            session['token'] = response['access_token']

        return session['token']

    except ConnectionError:
        raise GraphConnectionError(current_app.config['AUTH_URL'])


def headers(credentials, fresh=False):
    """Returns headers with an authorization token."""
    return {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token(credentials, fresh),
        'Content-Type': 'application/json',
        'User-Agent': agent
    }


def get_data(url, credentials):
    try:
        response = requests.get(url, headers=headers(credentials))

        # Refresh the token if expired.
        if response.status_code == HTTPStatus.UNAUTHORIZED:
            response = requests.get(
                url, headers=headers(credentials, fresh=True)
            )

        if response.ok:
            return response.json()

        if response.status_code == HTTPStatus.NOT_FOUND:
            return {}

        raise CriticalResponseError(response)

    except SSLError as error:
        raise GraphSSLError(error)
    except ConnectionError:
        raise GraphConnectionError(current_app.config['API_URL'])
