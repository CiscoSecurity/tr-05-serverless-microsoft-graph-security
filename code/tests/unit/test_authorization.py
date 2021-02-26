from http import HTTPStatus
from unittest.mock import patch

from pytest import fixture
from requests.exceptions import InvalidURL, ConnectionError
from api.utils import (
    NO_AUTH_HEADER,
    WRONG_AUTH_TYPE,
    WRONG_JWKS_HOST,
    WRONG_PAYLOAD_STRUCTURE,
    JWKS_HOST_MISSING,
    WRONG_KEY,
    WRONG_JWT_STRUCTURE,
    WRONG_AUDIENCE,
    KID_NOT_FOUND
)
from api.errors import AUTH_ERROR
from .utils import headers


def routes():
    yield '/health'
    yield '/observe/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def valid_json():
    return [{'type': 'domain', 'value': 'ibm.com'}]


@fixture(scope='module')
def authorization_errors_expected_payload(route: str):

    def _make_payload_message(message):
        payload = {
            'errors': [
                {
                    'code': AUTH_ERROR,
                    'message': f'Authorization failed: {message}',
                    'type': 'fatal'}
            ],
        }
        if route.endswith('/trigger'):
            payload.update({'data': {'status': 'failure'}})
        return payload

    return _make_payload_message


def test_call_with_authorization_header_failure(
        route, client, valid_json,
        authorization_errors_expected_payload
):
    response = client.post(route, json=valid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        NO_AUTH_HEADER
    )


def test_call_with_wrong_authorization_type(
        route, client, valid_jwt, valid_json,
        authorization_errors_expected_payload
):
    response = client.post(
        route, json=valid_json,
        headers={'Authorization': 'Basic blabla'}
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_AUTH_TYPE
    )


def test_call_with_wrong_jwt_structure(
        route, client, valid_json,
        authorization_errors_expected_payload,
        get_public_key
):
    with patch('requests.get') as request_mock:
        request_mock.side_effect = get_public_key
        response = client.post(
            route, headers=headers('this_is_not_a_jwt'), json=valid_json
        )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_JWT_STRUCTURE
    )


def test_call_with_wrong_kid(
        route, client, valid_json,
        authorization_errors_expected_payload,
        get_public_key, valid_jwt
):
    with patch('requests.get') as request_mock:
        request_mock.side_effect = get_public_key
        response = client.post(
            route, headers=headers(valid_jwt(kid='wrong_kid')), json=valid_json
        )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
       KID_NOT_FOUND
    )


def test_call_with_wrong_jwks_host(
    route, client, valid_json, valid_jwt,
    authorization_errors_expected_payload
):
    for error in (ConnectionError, InvalidURL):
        with patch('requests.get') as request_mock:
            request_mock.side_effect = error()

            response = client.post(
                route, json=valid_json, headers=headers(valid_jwt())
            )

        assert response.status_code == HTTPStatus.OK
        assert response.json == authorization_errors_expected_payload(
            WRONG_JWKS_HOST
        )


def test_call_with_wrong_jwt_payload_structure(
        route, client, valid_json, valid_jwt,
        authorization_errors_expected_payload,
        get_public_key
):
    with patch('requests.get') as request_mock:
        request_mock.return_value = get_public_key

        response = client.post(
            route, json=valid_json,
            headers=headers(valid_jwt(wrong_structure=True))
        )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_PAYLOAD_STRUCTURE)


def test_call_without_jwks_host(
        route, client, valid_json, valid_jwt,
        authorization_errors_expected_payload,
        get_public_key
):
    with patch('requests.get') as request_mock:
        request_mock.side_effect = get_public_key

    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt(missing_jwks_host=True))
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        JWKS_HOST_MISSING)


def test_call_with_wrong_audience(
        route, client, valid_json, valid_jwt, get_public_key,
        authorization_errors_expected_payload,
):
    with patch('requests.get') as request_mock:
        request_mock.return_value = get_public_key

        response = client.post(
            route, json=valid_json,
            headers=headers(valid_jwt(aud='wrong_aud'))
        )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_AUDIENCE
    )


def test_call_with_wrong_public_key(
        route, client, valid_json, valid_jwt, get_wrong_public_key,
        authorization_errors_expected_payload,
):
    with patch('requests.get') as request_mock:
        request_mock.return_value = get_wrong_public_key

        response = client.post(
            route, json=valid_json,
            headers=headers(valid_jwt())
        )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_KEY
    )


def test_call_with_unauthorized_creds(
        route, client, valid_jwt, valid_json,
        graph_response_unauthorized_creds, get_public_key,
        authorization_errors_expected_payload
):
    with patch('api.client.token') as token_mock, \
            patch('requests.get') as requests_mock:
        token_mock.return_value = 'TOKEN'
        requests_mock.side_effect = (
                [get_public_key] + [graph_response_unauthorized_creds]*2
        )

        response = client.post(
            route, headers=headers(valid_jwt()),
            json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert token_mock.call_count == 2
        assert response.json == authorization_errors_expected_payload(
            'AADSTS7000215: Invalid client secret is provided.'
        )
