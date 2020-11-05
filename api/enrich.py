from functools import partial

from flask import Blueprint, jsonify, current_app

from .mappings import Mapping
from .schema import ObservableSchema
from .utils import get_json

api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


@api.route('/observe/observables', methods=['POST'])
def observe():
    observables = get_observables()

    url = current_app.config['API_URL']
    limit = current_app.config['CTR_ENTITIES_LIMIT']

    def observe(observable):
        type_ = observable['type']
        value = observable['value']

        mapping = Mapping.of(type_)

        return mapping.get(url, value, limit) if mapping is not None else []

    def data(sightings):
        if sightings:
            return {
                'data': {
                    'sightings': {
                        'count': len(sightings),
                        'docs': sightings
                    }
                }
            }
        else:
            return {'data': {}}

    sightings = []

    try:
        for observable in observables:
            sightings.extend(observe(observable))
    except Exception as ex:
        if sightings:
            setattr(ex, 'data', data(sightings))

        raise

    return jsonify(data(sightings))


@api.route('/deliberate/observables', methods=['POST'])
def deliberate():
    return jsonify({'data': {}})


@api.route('/refer/observables', methods=['POST'])
def refer():
    return jsonify({'data': []})
