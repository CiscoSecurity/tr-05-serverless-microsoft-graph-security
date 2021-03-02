from functools import partial

from flask import Blueprint, current_app, g

from .mappings import Mapping
from .schema import ObservableSchema
from .utils import get_json, jsonify_result, jsonify_data, get_credentials

api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


@api.route('/observe/observables', methods=['POST'])
def observe():
    observables = get_observables()
    credentials = get_credentials()

    url = current_app.config['API_URL']
    limit = current_app.config['CTR_ENTITIES_LIMIT']

    def observe(observable):
        type_ = observable['type']
        value = observable['value']

        mapping = Mapping.of(type_)

        return (mapping.get(url, value, limit, credentials)
                if mapping is not None else [])

    g.sightings = []

    for observable in observables:
        g.sightings.extend(observe(observable))

    return jsonify_result()


@api.route('/deliberate/observables', methods=['POST'])
def deliberate():
    return jsonify_data({})


@api.route('/refer/observables', methods=['POST'])
def refer():
    return jsonify_data([])
