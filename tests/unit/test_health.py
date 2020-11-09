from http import HTTPStatus
from unittest.mock import patch, MagicMock

from pytest import fixture
from requests.exceptions import SSLError

from .utils import headers


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_health_call_with_http_error(
    route, client, valid_jwt,
        graph_response_token,
        graph_response_service_unavailable, graph_response_unauthorized_creds,
        service_unavailable_expected_payload

):
    with patch('requests.get') as get_mock:
        get_mock.side_effect = [graph_response_token,
                                graph_response_unauthorized_creds,
                                graph_response_token,
                                graph_response_service_unavailable]
        response = client.post(
            route, headers=headers(valid_jwt)
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == service_unavailable_expected_payload


def test_health_call_with_ssl_error(
        route, client, valid_jwt,
        sslerror_expected_payload
):
    with patch('requests.get') as get_mock:
        mock_exception = MagicMock()
        mock_exception.reason.args.__getitem__().verify_message \
            = 'self signed certificate'
        get_mock.side_effect = SSLError(mock_exception)

        response = client.post(
            route, headers=headers(valid_jwt)
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == sslerror_expected_payload


def test_health_call_success(route, client, valid_jwt, graph_response_token):
    with patch('requests.get') as requests_mock:
        requests_mock.return_value = graph_response_token
        response = client.post(route, headers=headers(valid_jwt))

        assert response.status_code == HTTPStatus.OK
        assert response.json == {'data': {'status': 'ok'}}
