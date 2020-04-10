from http import HTTPStatus

from flask import Flask, jsonify
from requests import HTTPError

from api import health, enrich, respond


app = Flask(__name__)
app.config.from_object('config.Config')

app.register_blueprint(health.api)
app.register_blueprint(enrich.api)
app.register_blueprint(respond.api)


@app.errorhandler(HTTPError)
def handle(ex: HTTPError):
    code = ex.response.status_code

    def data(value):
        return jsonify({'data': value})

    def error(**kwargs):
        return jsonify({'errors': [{'type': 'fatal', **kwargs}]})

    if code == HTTPStatus.BAD_REQUEST:
        return data({})
    if code == HTTPStatus.NOT_FOUND:
        return data({})
    if code == HTTPStatus.UNAUTHORIZED:
        return error(code='access denied',
                     message='Access to Microsoft Graph Security denied.')
    if code == HTTPStatus.SERVICE_UNAVAILABLE:
        return error(code='service unavailable',
                     message='Service temporarily unavailable. '
                             'Please try again later.')

    return error(code='oops',
                 message='Something went wrong.')


@app.errorhandler(Exception)
def handle(ex: Exception):
    code = getattr(ex, 'code', 500)
    message = getattr(ex, 'description', 'Something went wrong.')

    return jsonify(message=message, code=code), code


if __name__ == '__main__':
    app.run()
