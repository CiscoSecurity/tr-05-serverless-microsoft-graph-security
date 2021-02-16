[![Gitter Chat](https://img.shields.io/badge/gitter-join%20chat-brightgreen.svg)](https://gitter.im/CiscoSecurity/Threat-Response "Gitter Chat")
[![Travis CI Build Status](https://travis-ci.com/CiscoSecurity/tr-05-serverless-microsoft-graph-security.svg?branch=develop)](https://api.travis-ci.com/CiscoSecurity/tr-05-serverless-microsoft-graph-security)

# Microsoft Graph Security Relay

Concrete Relay implementation using
[Microsoft Graph Security](https://www.microsoft.com/en-us/security/business/graph-security-api)
as a third-party Cyber Threat Intelligence service provider.

The Relay itself is just a simple application written in Python that can be
easily packaged and deployed as an AWS Lambda Function using
[Zappa](https://github.com/Miserlou/Zappa).

**NOTE.** The Relay uses [Open Data Protocol (OData) filters](https://docs.microsoft.com/en-us/graph/query-parameters#filter-parameter) 
(in particular lambda operator `any`) while querying data from Microsoft Graph Security API. 
Microsoft Graph Security API is a federation service that merges data from various Microsoft alert providers.
As some providers do not fully support OData query filters yet (e.g. Office 365 Security and Compliance, Microsoft Defender ATP), this means alerts from such providers will not be included in the Relay output.

## Rationale

1. We need an application that will translate API requests from SecureX Threat Response
to the third-party integration, and vice versa. This application is provided
here in the GitHub repository, and we are going to install it in AWS Lambda
using Zappa.

2. AWS Lambda allows us to deploy our application without deploying a dedicated
server or paying for so called "idle" cycles. AWS handles instantiation and
resource provisioning; all we need to do is define the access rights and upload
our application.

3. Zappa is a helper tool that will package our application and publish it to
AWS as a Lambda function. It abstracts a large amount of manual configuration
and requires only a very simple configuration file, which we have provided and
will explain how to customize it during this process.

## Step 0: AWS Setup

To get started, you have to set up your AWS environment first by carefully
following the instructions from the [AWS HOWTO](aws/HOWTO.md). In addition, the
document also covers how to configure the [Zappa Settings](zappa_settings.json)
by explaining the relationships between the values there and your AWS setup.

## Step 1: Requirements Installation

First of all, make sure that you already have Python 3 installed by typing
```
python3 --version
```
in your command-line shell.

The application has been implemented and tested using `Python 3.7`. You may try
to use any higher versions if you wish as they should be backward-compatible.

After that, you have to create a "virtual environment" to isolate the
application-specific requirements from the libraries globally installed to your
system. Here are the steps to follow:

1. Create a virtual environment named `venv`:

   `python3 -m venv venv`

2. Activate the virtual environment:
   - Linux/Mac: `source venv/bin/activate`
   - Windows: `venv\Scripts\activate.bat`

3. Upgrade PIP (optional):

   `pip install --upgrade pip`

**NOTE**. The virtual environment has to be created only once, you just have
to make sure to activate it each time you are working on or playing with the
application (modern IDEs can automatically do that for you). You can deactivate
a previously activated virtual environment by simply typing `deactivate` in
your command-line shell.

Finally, install the libraries required for the application to function from
the [requirements.txt](requirements.txt) file:

```
pip install --upgrade --requirement requirements.txt
```

## Step 2: Application Deployment

### AWS Lambda Function

To `deploy` your application to AWS as a Lambda function for the first time,
run the following command:
```
zappa deploy dev
```

**NOTE**. Here `dev` is just the name of the default stage. You may define as
many stages as you like. Each Zappa command requires a stage to be specified so
make sure to replace `dev` with the name of your custom stage when necessary.

**NOTE**. If you are experiencing any problems with running the command then
check the [AWS Common Errors](aws/CommonErrors.md) guide on troubleshooting
of some most common types of errors.

Once the Lambda has been deployed, make sure to save the public `URL` to your
Lambda returned by Zappa. It will look like this:
```
https://<RANDOM_ID>.execute-api.<AWS_REGION>.amazonaws.com/<STAGE>
```

You can check the `status` of your deployment with the corresponding command:
```
zappa status dev
```

Notice that you have to `deploy` your Lambda only once. Each time you make
changes to the source code or to the settings file you just have to `update`
the Lambda by running the following command:
```
zappa update dev
```

As a bonus, you can also monitor your Lambda's HTTP traffic in near real-time
with the `tail` command:
```
zappa tail dev --http
```

If you do not need your Lambda anymore you can run the following command to
get rid of it altogether and clean up the underlying resources:
```
zappa undeploy dev
```

**NOTE**. The `deploy` command always returns a brand new `URL`. The `update`
command does not change the current `URL`. The `undeploy` command destroys the
old `URL` forever.

### JWT

Before you can start using the live Lambda, you have to encode your third-party
credentials into a JWT using a generated secret key.

In brief, [JSON Web Token (JWT)](https://en.wikipedia.org/wiki/JSON_Web_Token)
is a way of encoding any JSON data into a signed token. The signature ensures
the integrity of the data, i.e. the fact that it has not been changed in any
way in transit between the sender and the recipient.

The JWT standard supports many different algorithms for signing tokens but we
are interested in HS256. The algorithm requires to generate (and securely store
somewhere) a 256-bit (i.e. 64-character) string a.k.a. the secret key.

Once the secret key has been generated and used for encoding your third-party
credentials into a JWT, the token has to be provided on each request to the
application as the `Authorization: Bearer <JWT>` header (this will be
automatically done for you if you create a corresponding module in SecureX Threat
Response). Unless the signature verification fails, the application will decode
the token to restore your original third-party credentials and will try to
authenticate to the corresponding third-party service on your behalf.

We recommend taking a look at [JWT.IO](https://jwt.io/), it is a good resource
for learning how JWTs work.

### SecureX Threat Response Module

Now, the only things left to do are:

- Generate a secret key and encode your credentials into a token. Let us name
those `SECRET_KEY` and `JWT` respectively so that we can refer to them later
on.

- Set the `SECRET_KEY` environment variable for your Lambda using the
corresponding value from the previous step.

- Create a corresponding SecureX Threat Response module based on your Lambda.

To simplify the JWT-related stuff, we have prepared for you the
[SecureX Threat Response JWT Generator](https://github.com/CiscoSecurity/tr-05-jwt-generator)
tool that provides only a single easy-to-use `jwt` command. Since the tool is
included into the [requirements.txt](requirements.txt) file, at this point it
should already have been installed along with the other dependencies.

Follow the steps below to finish the deployment procedure:

1. Run the `jwt` command of the tool specifying a Zappa stage, e.g. `jwt dev`.
It will prompt you to enter your third-party credentials according to the `jwt`
structure defined in the [Module Settings](module_settings.json).

2. The command will generate a `SECRET_KEY`/`JWT` pair for you based on your
just entered credentials. Make sure to save both.

3. The command will also build the link to the AWS Console page with your
Lambda's environment variables. Go set the `SECRET_KEY` environment variable
there. This is important since the Lambda has to know the `SECRET_KEY` so that
it can verify and decode the `JWT` from incoming requests. If you do not
understand how to set the `SECRET_KEY` environment variable then check the
[AWS Environment Variables](aws/EnvironmentVariables.md) guide on passing
arbitrary environment variables to Lambdas.

4. The command will also build the links to the SecureX Threat Response pages (in all
available regions) with the corresponding module creation forms. Select the
link corresponding to your SecureX Threat Response region. The form there will require
you to enter both your Lambda's `URL` and your `JWT` (along with a unique name)
to finally create your SecureX Threat Response module.

That is it! Your Serverless Relay is ready to use! Congratulations!

## Step 3: Testing (Optional)

If you want to test the application you have to install a couple of extra
dependencies from the [test-requirements.txt](test-requirements.txt) file:
```
pip install --upgrade --requirement test-requirements.txt
```

You can perform two kinds of testing:

- Run static code analysis checking for any semantic discrepancies and
[PEP 8](https://www.python.org/dev/peps/pep-0008/) compliance:

  `flake8 .`

- Run the suite of unit tests and measure the code coverage:

  `coverage run --source api/ -m pytest --verbose tests/unit/ && coverage report`

If you want to test the live Lambda you may use any HTTP client (e.g. Postman),
just make sure to send requests to your Lambda's `URL` with the `Authorization`
header set to `Bearer <JWT>`.

**NOTE.** If you need input data for testing purposes you can use data from the
[observables.json](observables.json) file.

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

### Supported Environment Variables

- `CTR_ENTITIES_LIMIT`
  - Restricts the maximum number of CTIM entities of each type returned in a
  single response per each requested observable.
  - Applies to the following CTIM entities:
    - `Sighting`.
  - Must be a positive integer. Defaults to `100` (if unset or incorrect).

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
