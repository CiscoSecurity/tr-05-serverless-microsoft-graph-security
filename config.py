import os


class Config:
    API_URL = 'https://graph.microsoft.com/v1.0/'

    AUTH_URL = 'https://login.microsoftonline.com/%s/oauth2/v2.0/token'
    AUTH_SCOPE = 'https://graph.microsoft.com/.default'

    SECRET_KEY = os.environ.get('SECRET_KEY', '')
