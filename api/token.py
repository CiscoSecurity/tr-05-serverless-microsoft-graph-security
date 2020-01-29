import requests
from authlib.jose import jwt
from flask import session, current_app, request


def token(fresh=False):
    """Returns an authorization token."""

    if fresh or 'token' not in session:
        scheme, payload = request.headers['Authorization'].split(None, 1)

        if scheme.lower() != 'bearer':
            raise ValueError('Expected the scheme to be "Bearer".')

        credentials = jwt.decode(payload, current_app.config['SECRET_KEY'])

        app_id = credentials['application_id']
        tenant = credentials['tenant_id']
        secret = credentials['client_secret']

        url = current_app.config['AUTH_URL'] % tenant

        data = {
            'client_id': app_id,
            'client_secret': secret,
            'grant_type': 'client_credentials',
            'scope': current_app.config['AUTH_SCOPE']
        }

        response = requests.get(url, data=data)
        response.raise_for_status()
        response = response.json()

        session['token'] = response['access_token']

    return session['token']


def headers(fresh=False):
    """Returns headers with an authorization token."""
    return {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token(fresh)
    }
