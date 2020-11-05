import requests
from flask import session, current_app

# The Graph Security API accepts the 'User-Agent'
# header in the following format:
#     {CompanyName}-{ProductName}/{Version}
from api.utils import get_credentials

agent = 'Cisco-CiscoThreatResponseMicrosoftGraphSecurity/1.0.0'


def token(fresh=False):
    """Returns an authorization token."""

    if fresh or 'token' not in session:
        credentials = get_credentials()

        url = current_app.config['AUTH_URL'] % credentials['tenant_id']

        data = {
            'client_id': credentials['application_id'],
            'client_secret': credentials['client_secret'],
            'grant_type': 'client_credentials',
            'scope': current_app.config['AUTH_SCOPE']
        }

        response = requests.get(url, data=data, headers={'User-Agent': agent})
        response.raise_for_status()
        response = response.json()

        session['token'] = response['access_token']

    return session['token']


def headers(fresh=False):
    """Returns headers with an authorization token."""
    return {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token(fresh),
        'Content-Type': 'application/json',
        'User-Agent': agent
    }
