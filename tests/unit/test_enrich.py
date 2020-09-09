from http import HTTPStatus
from unittest.mock import patch, MagicMock

from pytest import fixture
from requests.exceptions import SSLError

from tests.unit.utils import headers


@fixture(scope='module')
def valid_json():
    return [{'type': 'email', 'value': 'ignore'},
            {'type': 'file_name', 'value': 'file.bin'}]


def test_deliberate_call_success(
        client, valid_jwt, valid_json
):
    response = client.post(
        '/deliberate/observables', headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == {'data': {}}


def test_refer_call_success(
        client, valid_jwt, valid_json
):
    response = client.post(
        '/refer/observables', headers=headers(valid_jwt), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == {'data': []}


OBSERVE_OBSERVABLES_ROUTE = '/observe/observables'
TOKEN = 'token'


def test_enrich_call_with_invalid_jwt(
        client, invalid_jwt, valid_json, fatal_error_expected_payload
):
    response = client.post(
        OBSERVE_OBSERVABLES_ROUTE, headers=headers(invalid_jwt),
        json=valid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == fatal_error_expected_payload


@fixture(scope='module')
def invalid_json():
    return [{'type': 'domain'}]


def test_enrich_call_with_invalid_json(
        client, valid_jwt, invalid_json, fatal_error_expected_payload
):
    response = client.post(
        OBSERVE_OBSERVABLES_ROUTE, headers=headers(valid_jwt),
        json=invalid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == fatal_error_expected_payload


def test_enrich_call_success(
        client, valid_json, valid_jwt, graph_response_data
):
    with patch('api.token.token') as token_mock, \
            patch('requests.get') as requests_mock:
        token_mock.return_value = TOKEN
        requests_mock.return_value = graph_response_data

        response = client.post(
            OBSERVE_OBSERVABLES_ROUTE, headers=headers(valid_jwt),
            json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json.get('data')
        assert response.json.get('errors') is None
        token_mock.assert_called_once()


def test_enrich_call_with_ssl_error(
        client, valid_json, valid_jwt, sslerror_expected_payload
):
    with patch('api.token.token') as token_mock, \
            patch('requests.get') as requests_mock:
        token_mock.return_value = TOKEN
        mock_exception = MagicMock()
        mock_exception.reason.args.__getitem__().verify_message \
            = 'self signed certificate'
        requests_mock.side_effect = SSLError(mock_exception)

        response = client.post(
            OBSERVE_OBSERVABLES_ROUTE, headers=headers(valid_jwt),
            json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == sslerror_expected_payload
        token_mock.assert_called_once()


def test_enrich_call_with_http_error(
        client, valid_json, valid_jwt,
        graph_response_service_unavailable,
        service_unavailable_expected_payload
):
    with patch('api.token.token') as token_mock, \
            patch('requests.get') as requests_mock:
        token_mock.return_value = TOKEN
        requests_mock.return_value = graph_response_service_unavailable

        response = client.post(
            OBSERVE_OBSERVABLES_ROUTE, headers=headers(valid_jwt),
            json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == service_unavailable_expected_payload
        token_mock.assert_called_once()


def test_enrich_call_with_unauthorized_creds(
        client, valid_jwt, valid_json,
        graph_response_unauthorized_creds,
        unauthorised_creds_expected_payload
):
    with patch('api.token.token') as token_mock, \
            patch('requests.get') as requests_mock:
        token_mock.return_value = TOKEN
        requests_mock.return_value = graph_response_unauthorized_creds

        response = client.post(
            OBSERVE_OBSERVABLES_ROUTE, headers=headers(valid_jwt),
            json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == unauthorised_creds_expected_payload
        assert token_mock.call_count == 2


def test_enrich_call_success_with_extended_error_handling(
        client, valid_json, valid_jwt,
        graph_response_data, graph_response_service_unavailable,
        service_unavailable_expected_payload
):
    with patch('api.token.token') as token_mock, \
            patch('requests.get') as requests_mock:
        token_mock.return_value = TOKEN
        requests_mock.side_effect = [graph_response_data,
                                     graph_response_service_unavailable]

        response = client.post(
            OBSERVE_OBSERVABLES_ROUTE, headers=headers(valid_jwt),
            json=[*valid_json, {'type': 'domain', 'value': 'google.com'}]
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json.pop('data')
        assert response.json == service_unavailable_expected_payload
        assert token_mock.call_count == 2
