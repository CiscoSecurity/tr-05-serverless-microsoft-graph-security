from ctrlibrary.core import client, settings
from ctrlibrary.threatresponse.endpoints import (
    RELAY_REFER_OBSERVABLES,
    RELAY_OBSERVE_OBSERVABLES,
    RELAY_DELIBERATE_OBSERVABLES,
    RELAY_RESPOND_OBSERVABLES,
    RELAY_RESPOND_TRIGGER,
    RELAY_HEALTH
)
from tests.functional.library.endpoints import APP_ATQC


def relay_deliberate_observables(payload='', **kwargs):
    """Perform POST call to Microsoft Graph relay endpoint using
    deliberate observables statement
    """
    return client.post(
        url='/'.join((
            settings.server.app_hostname,
            APP_ATQC,
            RELAY_DELIBERATE_OBSERVABLES
        )),
        json=payload,
        **kwargs
    )


def relay_refer_observables(payload='', **kwargs):
    """Perform POST call to Microsoft Graph relay endpoint using
    enrich refer observables statement
    """
    return client.post(
        url='/'.join((
            settings.server.app_hostname,
            APP_ATQC,
            RELAY_REFER_OBSERVABLES
        )),
        json=payload,
        **kwargs
    )


def relay_observe_observables(payload='', **kwargs):
    """Perform POST call to Microsoft Graph relay endpoint using observe
    observables statement
    """

    return client.post(
        url='/'.join((
            settings.server.app_hostname,
            APP_ATQC,
            RELAY_OBSERVE_OBSERVABLES
        )),
        json=payload,
        **kwargs
    )


def relay_respond_observables(payload='', **kwargs):
    """Perform POST call to  Microsoft Graph relay endpoint using respond
    observables statement
    """

    return client.post(
        url='/'.join((
            settings.server.app_hostname,
            APP_ATQC,
            RELAY_RESPOND_OBSERVABLES
        )),
        json=payload,
        **kwargs
    )


def relay_respond_trigger(payload='', **kwargs):
    """Perform POST call to  Microsoft Graph relay endpoint using respond
    trigger statement
    """
    return client.post(
        url='/'.join((
            settings.server.app_hostname,
            APP_ATQC,
            RELAY_RESPOND_TRIGGER
        )),
        json=payload,
        **kwargs
    )


def relay_health(payload='', **kwargs):
    """Perform POST call to  Microsoft Graph relay endpoint using health
    statement
    """
    return client.post(
        url='/'.join((
            settings.server.app_hostname,
            APP_ATQC,
            RELAY_HEALTH
        )),
        json=payload,
        **kwargs
    )
