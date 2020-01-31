from http import HTTPStatus

import requests
from flask import Blueprint, jsonify, current_app

from .token import headers
from .url import join

api = Blueprint('health', __name__)


@api.route('/health', methods=['POST'])
def health():
    url = join(current_app.config['API_URL'], '/security/alerts?$top=0')
    response = requests.get(url, headers=headers())

    # Refresh the token if expired.
    if response.status_code == HTTPStatus.UNAUTHORIZED.value:
        response = requests.get(url, headers=headers(fresh=True))

    if response.ok:
        return jsonify({'data': {'status': 'ok'}})
    else:
        error = response.json()
        error['type'] = 'error'

        return jsonify({'errors': [error]})
