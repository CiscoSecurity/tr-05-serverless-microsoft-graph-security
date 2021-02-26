from flask import Blueprint, current_app

from .client import get_data
from .utils import jsonify_data, url_join, get_credentials

api = Blueprint('health', __name__)


@api.route('/health', methods=['POST'])
def health():
    credentials = get_credentials()
    url = url_join(current_app.config['API_URL'], '/security/alerts?$top=0')
    get_data(url, credentials)
    return jsonify_data({'status': 'ok'})
