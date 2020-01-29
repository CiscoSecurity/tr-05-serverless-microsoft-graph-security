from itertools import chain

from flask import Blueprint, request, jsonify, current_app
from werkzeug.exceptions import BadRequest

from . import schema
from .mappings import Mapping

api = Blueprint('enrich', __name__)


@api.route('/observe/observables', methods=['POST'])
def observe():
    observables = json(request, schema.observables)

    def _observe(observable):
        type_ = observable['type']
        value = observable['value']

        url = current_app.config['API_URL']

        mapping = Mapping.of(type_)

        return mapping.get(url, value) if mapping is not None else []

    data = (_observe(x) for x in observables)
    data = chain.from_iterable(data)
    data = list(data)

    if data:
        return jsonify({
            'data': {
                'sightings': {
                    'count': len(data),
                    'docs': data
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
