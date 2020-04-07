# Microsoft Graph Security Relay API

The API is just a simple Flask (WSGI) application which can be easily
packaged and deployed as an AWS Lambda Function working behind an AWS API
Gateway proxy using [Zappa](https://github.com/Miserlou/Zappa).

An already deployed Relay API (e.g., packaged as an AWS Lambda Function) can
be pushed to Threat Response as a Relay Module using the
[Threat Response Relay CLI](https://github.com/threatgrid/tr-lambda-relay).

## Installation

```bash
pip install -U -r requirements.txt
```

## Deployment

As an AWS Lambda Function:
- Deploy: `zappa deploy dev`.
- Check: `zappa status dev`.
- Update: `zappa update dev`.
- Monitor: `zappa tail dev --http`.

As a TR Relay Module:
- Create: `relay add`.
- Update: `relay edit`.
- Delete: `relay remove`.

**Note.** For convenience, each TR Relay CLI command may be prefixed with
`env $(cat .env | xargs)` to automatically read the required environment
variables from a `.env` file (i.e.`TR_API_CLIENT_ID`, `TR_API_CLIENT_PASSWORD`,
`URL`, `JWT`) and pass them to the corresponding command.

## Details

The Microsoft Graph Security Relay API implements the following list of endpoints:
* `/observe/observables`,
* `/health`.

Even though the API is still able to handle requests to other Relay API endpoints 
(i.e., `/refer/observables`, `/deliberate/observables`, `/respond/observables` and `/respond/trigger`), 
it is programmed only to return empty responses.

The `/observe/observables` endpoint only supports observables of types listed below:
* `sha256`,
* `file_name`,
* `file_path`,
* `ip`,
* `domain`,
* `hostname`,
* `url`.

Other types of observables will not be handled (though no error will be raised either), 
and observables of such types will simply be ignored.

When querying the `/observe/observables` endpoint, 
the module performs a request to the Microsoft Graph Security API to retrieve security alerts 
related to the provided observables. These alerts are then mapped to the CTIM 
[sightings](https://github.com/threatgrid/ctim/blob/master/doc/structures/sighting.md).

The module requires a registered Microsoft Graph application to work.
Please read the [documentation](https://docs.microsoft.com/en-us/graph/security-authorization) 
for the details of the registration process.
The application must be provided with the `SecurityActions.Read.All` permission to be able to query 
the Microsoft Graph Security API for security alerts.

Requests to the module must be performed with a JSON Web Token containing credentials of your application:
```json
{
    "application_id": "...",
    "tenant_id": "...",
    "client_secret": "..."
}
```
