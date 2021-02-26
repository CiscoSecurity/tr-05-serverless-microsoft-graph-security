[![Gitter Chat](https://img.shields.io/badge/gitter-join%20chat-brightgreen.svg)](https://gitter.im/CiscoSecurity/Threat-Response "Gitter Chat")

# Microsoft Graph Security Relay (Cisco Hosted)

A Cisco SecureX Concrete Relay implementation using
[Microsoft Graph Security](https://www.microsoft.com/en-us/security/business/graph-security-api)
as a third-party Cyber Threat Intelligence service provider.

The Relay itself is just a simple application written in Python that can be easily packaged and deployed.  This relay is now Cisco Hosted and no longer requires AWS Lambda.

The code is provided here purely for educational purposes.

**NOTE.** The Relay uses [Open Data Protocol (OData) filters](https://docs.microsoft.com/en-us/graph/query-parameters#filter-parameter) 
(in particular lambda operator `any`) while querying data from Microsoft Graph Security API. 
Microsoft Graph Security API is a federation service that merges data from various Microsoft alert providers.
As some providers do not fully support OData query filters yet (e.g. Office 365 Security and Compliance, Microsoft Defender ATP), this means alerts from such providers will not be included in the Relay output.

## Rationale

- We need an application that will translate API requests from SecureX Threat Response to the third-party integration, and vice versa.
- We need an application that can be completely self contained within a virtualized container using Docker.

## Testing (Optional)

If you want to test the application you will require Docker and several dependencies from the [requirements.txt](code/requirements.txt) file:
```
pip install --upgrade --requirement code/requirements.txt
```

You can perform two kinds of testing:

- Run static code analysis checking for any semantic discrepancies and [PEP 8](https://www.python.org/dev/peps/pep-0008/) compliance:

  `flake8 code`

- Run the suite of unit tests and measure the code coverage:
  `cd code`
  `coverage run --source api/ -m pytest --verbose tests/unit/ && coverage report`

**NOTE.** If you need input data for testing purposes you can use data from the
[observables.json](code/observables.json) file.

### Building the Docker Container
In order to build the application, we need to use a `Dockerfile`.  

 1. Open a terminal.  Build the container image using the `docker build` command.

```
docker build -t tr-05-microsoft-graph .
```

 2. Once the container is built, and an image is successfully created, start your container using the `docker run` command and specify the name of the image we have just created.  By default, the container will listen for HTTP requests using port 9090.

```
docker run -dp 9090:9090 --name tr-05-microsoft-graph tr-05-microsoft-graph
```

 3. Watch the container logs to ensure it starts correctly.

```
docker logs tr-05-microsoft-graph
```

 4. Once the container has started correctly, open your web browser to http://localhost:9090.  You should see a response from the container.

```
curl http://localhost:9090
```

## Implementation Details

### Implemented Relay Endpoints

- `POST /health`
  - Verifies the Authorization Bearer JWT and decodes it to restore the
  original credentials.
  - Authenticates to the underlying external service to check that the provided
  credentials are valid and the service is available at the moment.

- `POST /observe/observables`
  - Accepts a list of observables and filters out unsupported ones.
  - Verifies the Authorization Bearer JWT and decodes it to restore the
  original credentials.
  - Makes a series of requests to the underlying external service to query for
  some cyber threat intelligence data on each supported observable.
  - Maps the fetched data into appropriate CTIM entities.
  - Returns a list per each of the following CTIM entities (if any extracted):
    - `Sighting`.
    
- `POST /version`
  - Returns the current version of the application.

### Supported Types of Observables

- `ip`
- `domain`
- `hostname`
- `url`
- `file_name`
- `file_path`
- `sha256`

### JWT Payload Structure

```json
{
    "application_id": "<APPLICATION-ID>",
    "tenant_id": "<TENANT-ID>",
    "client_secret": "<CLIENT-SECRET>"
}
```

**NOTE.** Your application must be granted [permission](https://docs.microsoft.com/en-us/graph/permissions-reference)
 to list [alerts](https://docs.microsoft.com/en-us/graph/api/resources/alert?view=graph-rest-1.0). 
 One of the following permissions is required (sorted from least to most privileged):

| Permission Type                    | Permission                                                    |
|------------------------------------|---------------------------------------------------------------|
| Delegated (work or school account) | `SecurityEvents.Read.All` <br> `SecurityEvents.ReadWrite.All` |
| Application                        | `SecurityEvents.Read.All` <br> `SecurityEvents.ReadWrite.All` |


### CTIM Mapping Specifics

Each Microsoft Graph Security [alert](https://docs.microsoft.com/en-us/graph/api/resources/alert?view=graph-rest-1.0) 
related to a supported observable is mapped to a single CTIM `Sighting` in a straightforward way.
For example, `description` of an alert is mapped to `description` of a sighting.

However, there are a few things that should be noted.

- `confidence` of an alert is represented as an integer value ranging from 0 to 100.
  This value is mapped to `confidence` of a `Sighting` as follows:
  - A range from 0  to 33  (inclusive) corresponds to `Low`.
  - A range from 34 to 66  (inclusive) corresponds to `Medium`.
  - A range from 67 to 100 (inclusive) corresponds to `High`.

- `targets` of a `Sighting` are based on `hostStates` of an alert. Each `hostState` is mapped to `target`, 
  so that the `target.observables` field contains the following fields from `hostState`:
  - `hostState.publicIpAddress` as `ip`;
  - `hostState.privateIpAddress` as `ip`;
  - `hostState.netBiosName` as `hostname`;
  - `hostState.fqdn` as `domain`.

- `sensor` of a `Sighting` is based on `vendorInformation.provider` and `vendorInformation.subProvider` of an alert.
  The mapping is defined as follows:

  | Provider             | Subprovider       | Sensor             |
  |----------------------|-------------------|--------------------|
  | Palo Alto Networks   | NGFW              | `network.firewall` |
  | Palo Alto Networks   | NG Firewall       | `network.firewall` |

  Any other combination of `vendorInformation.provider` and `vendorInformation.subProvider` is mapped to `endpoint`.
