import json
from http import HTTPStatus
from unittest.mock import MagicMock

import jwt
from pytest import fixture

from api.errors import INVALID_ARGUMENT
from app import app
from tests.unit.mock_for_tests import (
    EXPECTED_RESPONSE_OF_JWKS_ENDPOINT, PRIVATE_KEY,
    RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY
)


@fixture(scope='session')
def client():
    app.rsa_private_key = PRIVATE_KEY

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def get_public_key():
    mock_response = MagicMock()
    payload = EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    mock_response.json = lambda: payload
    return mock_response


@fixture(scope='session')
def get_wrong_public_key():
    mock_response = MagicMock()
    payload = RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY
    mock_response.json = lambda: payload
    return mock_response


@fixture(scope='session')
def valid_jwt(client):
    def _make_jwt(
            jwks_host='visibility.amp.cisco.com',
            aud='http://localhost',
            kid='02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            wrong_structure=False,
            missing_jwks_host=False
    ):
        payload = {
            'application_id': 'xxx',
            'tenant_id': 'xxx',
            'client_secret': 'xxx',
            'jwks_host': jwks_host,
            'aud': aud,
        }

        if wrong_structure:
            payload.pop('client_secret')
        if missing_jwks_host:
            payload.pop('jwks_host')

        return jwt.encode(
            payload, client.application.rsa_private_key, algorithm='RS256',
            headers={
                'kid': kid
            }
        )

    return _make_jwt


def graph_api_response_mock(status_code, text=None, json_=None):
    mock_response = MagicMock()

    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    mock_response.text = text
    mock_response.json = lambda: json_ or {}

    return mock_response


@fixture(scope='session')
def graph_response_unauthorized_creds():
    return graph_api_response_mock(
        HTTPStatus.UNAUTHORIZED,
        json_={
            'error': 'invalid_client',
            'error_description':
                'AADSTS7000215: Invalid client secret is provided.'
        }
    )


@fixture(scope='session')
def graph_response_not_found():
    return graph_api_response_mock(
        HTTPStatus.NOT_FOUND,
        json_={
            'error': {
                'code': 'ResourceNotFound',
                'message': 'Resource not found'
                }
        }
    )


@fixture(scope='session')
def graph_response_service_unavailable():
    return graph_api_response_mock(
        HTTPStatus.SERVICE_UNAVAILABLE
    )


@fixture(scope='session')
def graph_response_data():
    with open('tests/unit/data/file_name.json', 'r') as file:
        data = json.loads(file.read())
        return graph_api_response_mock(
            HTTPStatus.OK,
            json_={'value': [data['input']]}
        )


@fixture(scope='session')
def graph_response_token():
    return graph_api_response_mock(
        HTTPStatus.OK,
        json_={'access_token': 'token'}
    )


@fixture(scope='module')
def sslerror_expected_payload():
    return {
        'errors': [
            {
                'code': 'unknown',
                'message': 'Unable to verify SSL certificate:'
                           ' Self signed certificate',
                'type': 'fatal'
            }
        ]
    }


@fixture(scope='module')
def invalid_json_expected_payload():
    return {
        'errors': [
            {
                'code': INVALID_ARGUMENT,
                'message':
                    'Invalid JSON payload received. {"0": {"value": '
                    '["Missing data for required field."]}}',
                'type': 'fatal'}
        ]
    }


@fixture(scope='module')
def service_unavailable_expected_payload():
    return {
        'errors': [
            {
                'type': 'fatal',
                'code': 'service unavailable',
                'message': 'Service temporarily unavailable.'
                           ' Please try again later.',
            }
        ]
    }
