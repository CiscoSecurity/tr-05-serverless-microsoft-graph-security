# coding: utf-8
"""Configurations for py.test runner"""

import pytest

from ctrlibrary.core import settings


def pytest_collection_modifyitems():
    if not settings.configured:
        settings.configure()
    return settings


@pytest.fixture(scope='session')
def session_headers():
    return {'Authorization': 'Bearer {}'.format(
        settings.server.app_client_password)}
