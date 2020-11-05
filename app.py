from http import HTTPStatus

from flask import Flask, jsonify
from requests import HTTPError
from requests.exceptions import SSLError

from api import health, enrich, respond
from api.errors import TRFormattedError
from api.utils import add_error, jsonify_result

app = Flask(__name__)
app.config.from_object('config.Config')

app.register_blueprint(health.api)
app.register_blueprint(enrich.api)
app.register_blueprint(respond.api)


@app.errorhandler(TRFormattedError)
def handle_tr_formatted_error(error):
    app.logger.error(error.json)
    add_error(error)
    return jsonify_result()


@app.errorhandler(HTTPError)
def handle_http(ex: HTTPError):
    code = ex.response.status_code
    message = ex.response.json()
    message = (message.get("error_description")
               or message.get("error", {}).get("message"))

    possible_detailed_errors = {
        HTTPStatus.TOO_MANY_REQUESTS: {
            'code': 'too many requests',
            'message': 'Too many requests to Microsoft Graph Security '
                       'have been made. Please try again later.'
        },
        HTTPStatus.UNAUTHORIZED: {
            'code': 'authorization error',
            'message': f'Authorization failed: {message}'
        },
        HTTPStatus.SERVICE_UNAVAILABLE: {
            'code': 'service unavailable',
            'message': 'Service temporarily unavailable. '
                       'Please try again later.'
        }

    }

    def empty():
        return jsonify({})

    def error(**kwargs):
        payload = {'errors': [{'type': 'fatal', **kwargs}]}

        if hasattr(ex, 'data'):
            payload.update(ex.data)

        app.logger.error(payload)
        return jsonify(payload)

    if code in (HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND):
        return empty()

    if code in possible_detailed_errors:
        return error(**possible_detailed_errors[code])

    return handle_error(ex)


@app.errorhandler(SSLError)
def handle_ssl(ex: SSLError):
    error = ex.args[0].reason.args[0]
    message = getattr(error, 'verify_message', error.args[0]).capitalize()

    payload = {
        'errors': [
            {
                'type': 'fatal',
                'code': 'unknown',
                'message': f'Unable to verify SSL certificate: {message}'
            }
        ]
    }

    app.logger.error(payload)
    return jsonify(payload)


@app.errorhandler(Exception)
def handle_error(exception):
    app.logger.error(exception)
    code = getattr(exception, 'code', 500)
    message = getattr(exception, 'description', 'Something went wrong.')
    reason = '.'.join([
        exception.__class__.__module__,
        exception.__class__.__name__,
    ])

    response = jsonify(code=code, message=message, reason=reason)
    return response, code


if __name__ == '__main__':
    app.run()
