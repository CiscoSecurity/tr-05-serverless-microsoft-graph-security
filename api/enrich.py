from flask import Blueprint, request, jsonify, current_app
from werkzeug.exceptions import BadRequest

from . import schema
from .mappings import Mapping

api = Blueprint('enrich', __name__)


@api.route('/observe/observables', methods=['POST'])
def observe():
    observables = json(request, schema.observables)

    url = current_app.config['API_URL']
    limit = current_app.config['CTR_ENTITIES_LIMIT']

    def _observe(observable_):
        type_ = observable_['type']
        value = observable_['value']

        mapping = Mapping.of(type_)

        return mapping.get(url, value, limit) if mapping is not None else []

    sightings = []
    for observable in observables:
        sightings.extend(_observe(observable))

    if sightings:
        return jsonify({
            'data': {
                'sightings': {
                    'count': len(sightings),
                    'docs': sightings
                }
            }
        })
    else:
        return jsonify({'data': {}})


@api.route('/deliberate/observables', methods=['POST'])
def deliberate():
    return jsonify({'data': {}})


@api.route('/refer/observables', methods=['POST'])
def refer():
    return jsonify({'data': []})


def json(request_, schema_):
    """Parses the body of a request as JSON according to a provided schema."""

    body = request_.get_json(force=True, silent=True, cache=False)
    error = schema_.validate(body) or None

    if error is not None:
        raise BadRequest('Invalid JSON format.')

    return body
