import json
import secrets


class Config:
    settings = json.load(open('container_settings.json', 'r'))
    VERSION = settings['VERSION']

    API_URL = 'https://graph.microsoft.com/v1.0/'

    AUTH_URL = 'https://login.microsoftonline.com/%s/oauth2/v2.0/token'
    AUTH_SCOPE = 'https://graph.microsoft.com/.default'

    CTR_ENTITIES_DEFAULT_LIMIT = 100

    SECRET_KEY = secrets.token_urlsafe(32)
