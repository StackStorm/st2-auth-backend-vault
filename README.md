# HashiCorp Vault authentication backend for StackStorm

[![Build Status](https://travis-ci.org/EncoreTechnologies/st2-auth-backend-vault.svg?branch=master)](https://travis-ci.org/EncoreTechnologies/st2-auth-backend-vault.svg?branch=master) [![Join our community Slack](https://stackstorm-community.herokuapp.com/badge.svg)](https://stackstorm.com/community-signup) [![Forum](https://img.shields.io/discourse/https/forum.stackstorm.com/posts.svg)](https://forum.stackstorm.com/)

## Overview

The HashiCorp Vault backend checks credentials and authenticates users against a
HashiCorp Vault instance. Vault itself supports multiple different 
[authentication methods](https://www.vaultproject.io/docs/auth/index.html)
detailed in their documentation. This backend can be configured to authenticate
with any of the currently available Vault auth methods, however only one Vault 
Auth Method can be configured at a time.

**Supported auth methods:**
* [app_id](#app_id)
* [app_role](#app_role)
* [aws](#aws)
* [azure](#azure)
* [gcp](#gcp)
* [github](#github)
* [kubernetes](#kubernetes)
* [ldap](#ldap)
* [okta](#okta)
* [radius](#radius)
* [token](#token)
* [userpass](#userpass)

## Configuration Options

| option           | required | default | description                                              |
|------------------|----------|---------|----------------------------------------------------------|
| vault_url        | true     |         | URL to the Vault API (ex: https://vault.domain.tld:8200) |
| auth_method      | true     |         | Name of the Vault auth method to use when authenticating |
| path             | false    | None    | Alternate path/mount-point for the auth method. This is only needed if you did something like `vault auth enable -path=mycustompath userpass`, then you would set this variable equal to `'mycustompath'`. Otherwise the default path for the auth method is used. |
| ssl_verify       | false    | True    | Verify the SSL server certificates of the Vault server   |
| ssl_ca_cert      | false    | None    | Filesystem path to the SSL CA cert to use for SSL verification. Specifying this value automatically enables the `ssl_verify` parameter turning on SSL verification. |
| ssl_client_cert  | false    | None    | Filesystem path to the SSL client certificate to use when communicating with the Vault API. If the client cert is split into a `.cert` and `.key` file then this is the path to the `.cert` file. Otherwise, if you have a bundled certificate and key in a `.pem` file, then this is the path to that `.pem` file. | 
| ssl_client_key   | false    | None    | Filesystem path to the SSL client certificate key to use when communicating with the Vault API. If the client cert is split into a `.cert` and `.key` file then this is the path to the `.key` file. Otherwise, do not specify this parameter |

### Configuration Example

Please refer to the authentication section in the StackStorm
[documentation](http://docs.stackstorm.com) for basic setup concept. The
following is an example of the auth section in the StackStorm configuration file
communicating with the Vault backend using the [userpass](#userpass) auth method.

```
[auth]
mode = standalone
backend = vault
backend_kwargs = {"vault_url": "https://vault.domain.tld:8200", "auth_method": "userpass"}
enable = True
logging = /path/to/st2auth.logging.conf
api_url = https://myhost.example.com:9101
debug = False
```

### <a name="app_id"></a> Auth Method: App ID

App ID is an auth method where you can authenticate using an application
ID and a user ID. For more information on the App ID auth method, see the
[Vault App ID documentation](https://www.vaultproject.io/docs/auth/app-id.html).

To utilize this method with StackStorm we will utilize the `username` and `password`
parameters passed into the `st2auth` service and map them to the following 
parameters for this  auth method:

| st2auth param | App ID param |
|---------------|--------------|
| username      | app_id       |
| password      | user_id      |

Here's an example of authenticating, using this auth method, with a `curl` command:

``` shell
curl -k -X POST -u <app_id>:<user_id> https://stackstorm.domain.tld/auth/v1/tokens
```

Here's an example of authenticating, using this auth method, with the `st2 login` command:

``` shell
$ st2 login <app_id>
Password: <user_id>
```

The configuration for this auth method will look like the following:

```
[auth]
mode = standalone
backend = vault
backend_kwargs = {"vault_url": "https://vault.domain.tld:8200", "auth_method": "app_id"}
enable = True
logging = /path/to/st2auth.logging.conf
api_url = https://myhost.example.com:9101
debug = False
```

### <a name="app_role"></a> Auth Method: App Role

App Role is an auth method where you can authenticate an application
with a Vault-defined role using a generated secret. For more information on the
App Role auth method, see the
[Vault App Role documentation](https://www.vaultproject.io/docs/auth/approle.html).

To utilize this method with StackStorm we will utilize the `username` and `password`
parameters passed into the `st2auth` service and map them to the following 
parameters for this  auth method:

| st2auth param | App Role param |
|---------------|----------------|
| username      | role_id        |
| password      | secret_id      |

Here's an example of authenticating, using this auth method, with a `curl` command:

``` shell
curl -k -X POST -u <role_id>:<secret_id> https://stackstorm.domain.tld/auth/v1/tokens
```

Here's an example of authenticating, using this auth method, with the `st2 login` command:

``` shell
$ st2 login <role_id>
Password: <secret_id>
```

The configuration for this auth method will look like the following:

```
[auth]
mode = standalone
backend = vault
backend_kwargs = {"vault_url": "https://vault.domain.tld:8200", "auth_method": "app_role"}
enable = True
logging = /path/to/st2auth.logging.conf
api_url = https://myhost.example.com:9101
debug = False
```

### <a name="aws"></a> Auth Method: AWS

AWS is an auth method where you can authenticate using AWS IAM access key and secret keys .
For more information on the AWS auth method, see the
[Vault AWS documentation](https://www.vaultproject.io/docs/auth/aws.html).

To utilize this method with StackStorm we will utilize the `username` and `password`
parameters passed into the `st2auth` service and map them to the following 
parameters for this  auth method:

| st2auth param | AWS param  |
|---------------|------------|
| username      | access_key |
| password      | secret_key |

Here's an example of authenticating, using this auth method, with a `curl` command:

``` shell
curl -k -X POST -u <access_key>:<secret_key> https://stackstorm.domain.tld/auth/v1/tokens
```

Here's an example of authenticating, using this auth method, with the `st2 login` command:

``` shell
$ st2 login <access_key>
Password: <secret_key>
```

The configuration for this auth method will look like the following:

```
[auth]
mode = standalone
backend = vault
backend_kwargs = {"vault_url": "https://vault.domain.tld:8200", "auth_method": "aws"}
enable = True
logging = /path/to/st2auth.logging.conf
api_url = https://myhost.example.com:9101
debug = False
```

### <a name="azure"></a> Auth Method: Azure

Azure is an auth method where you can authenticate against Azure Active Directory.
This works by creating a role in Vault that maps a name to a set of tenant information.
The password is a signed JWT token from Azure Active Directory.
For more information on the Azure auth method, see the
[Vault Azure documentation](https://www.vaultproject.io/docs/auth/azure.html).

To utilize this method with StackStorm we will utilize the `username` and `password`
parameters passed into the `st2auth` service and map them to the following 
parameters for this  auth method:

| st2auth param | Azure param |
|---------------|-------------|
| username      | role_name   |
| password      | jwt_token   |

Here's an example of authenticating, using this auth method, with a `curl` command:

``` shell
curl -k -X POST -u <role_name>:<jwt_token> https://stackstorm.domain.tld/auth/v1/tokens
```

Here's an example of authenticating, using this auth method, with the `st2 login` command:

``` shell
$ st2 login <role_name>
Password: <jwt_token>
```

The configuration for this auth method will look like the following:

```
[auth]
mode = standalone
backend = vault
backend_kwargs = {"vault_url": "https://vault.domain.tld:8200", "auth_method": "azure"}
enable = True
logging = /path/to/st2auth.logging.conf
api_url = https://myhost.example.com:9101
debug = False
```

### <a name="gcp"></a> Auth Method: GCP

GCP is an auth method where you can authenticate using Google credentials.
This works by creating a role in Vault that maps a name to a set of tenant information.
The password is a signed JWT token from the Google authentication entity.
For more information on the GCP auth method, see the
[Vault GCP documentation](https://www.vaultproject.io/docs/auth/gcp.html).

To utilize this method with StackStorm we will utilize the `username` and `password`
parameters passed into the `st2auth` service and map them to the following 
parameters for this  auth method:

| st2auth param | GCP param |
|---------------|-----------|
| username      | role_name |
| password      | jwt_token |

Here's an example of authenticating, using this auth method, with a `curl` command:

``` shell
curl -k -X POST -u <role_name>:<jwt_token> https://stackstorm.domain.tld/auth/v1/tokens
```

Here's an example of authenticating, using this auth method, with the `st2 login` command:

``` shell
$ st2 login <role_name>
Password: <jwt_token>
```

The configuration for this auth method will look like the following:

```
[auth]
mode = standalone
backend = vault
backend_kwargs = {"vault_url": "https://vault.domain.tld:8200", "auth_method": "gcp"}
enable = True
logging = /path/to/st2auth.logging.conf
api_url = https://myhost.example.com:9101
debug = False
```

### <a name="github"></a> Auth Method: GitHub

GitHub is an auth method where you can authenticate using a GitHub token. 
For more information on the GitHub auth method, see the
[Vault GitHub documentation](https://www.vaultproject.io/docs/auth/github.html).

To utilize this method with StackStorm we will utilize the `username` and `password`
parameters passed into the `st2auth` service and map them to the following 
parameters for this auth method:


| st2auth param | GitHub param |
|---------------|--------------|
| username      | <unused>     |
| password      | token        |

**NOTE** In this auth method, the `username` is NOT used. The `password` is
         used for the GitHub token. Simply pass in any string as the `username`
         and then the GitHub token as the `password`.
         
Here's an example of authenticating, using this auth method, with a `curl` command:

``` shell
curl -k -X POST -u unused:<token> https://stackstorm.domain.tld/auth/v1/tokens
```

Here's an example of authenticating, using this auth method, with the `st2 login` command:

``` shell
$ st2 login unused
Password: <token>
```

The configuration for this auth method will look like the following:

```
[auth]
mode = standalone
backend = vault
backend_kwargs = {"vault_url": "https://vault.domain.tld:8200", "auth_method": "github"}
enable = True
logging = /path/to/st2auth.logging.conf
api_url = https://myhost.example.com:9101
debug = False
```

### <a name="kubernetes"></a> Auth Method: Kubernetes

Kubernetes is an auth method where you can authenticate against a Kubernetes cluster
Service Account Token.
This works by creating a role in Vault that maps a name to the service account information.
The password is a signed JWT token for the Kubernetes service account.
For more information on the Kubernetes auth method, see the
[Vault Kubernetes documentation](https://www.vaultproject.io/docs/auth/kubernetes.html).

To utilize this method with StackStorm we will utilize the `username` and `password`
parameters passed into the `st2auth` service and map them to the following 
parameters for this  auth method:

| st2auth param | Kubernetes param |
|---------------|------------------|
| username      | role_name        |
| password      | jwt_token        |

Here's an example of authenticating, using this auth method, with a `curl` command:

``` shell
curl -k -X POST -u <role_name>:<jwt_token> https://stackstorm.domain.tld/auth/v1/tokens
```

Here's an example of authenticating, using this auth method, with the `st2 login` command:

``` shell
$ st2 login <role_name>
Password: <jwt_token>
```

The configuration for this auth method will look like the following:

```
[auth]
mode = standalone
backend = vault
backend_kwargs = {"vault_url": "https://vault.domain.tld:8200", "auth_method": "kubernetes"}
enable = True
logging = /path/to/st2auth.logging.conf
api_url = https://myhost.example.com:9101
debug = False
```

### <a name="ldap"></a> Auth Method: LDAP

LDAP is an auth method where you can authenticate against an existing LDAP
server using username and password.
LDAP binding information is configured within Vault when setting up the auth method.
For more information on the LDAP auth method, see the
[Vault LDAP documentation](https://www.vaultproject.io/docs/auth/ldap.html).

To utilize this method with StackStorm we will utilize the `username` and `password`
parameters passed into the `st2auth` service and map them to the following 
parameters for this  auth method:

| st2auth param | LDAP param |
|---------------|------------|
| username      | username   |
| password      | password   |

Here's an example of authenticating, using this auth method, with a `curl` command:

``` shell
curl -k -X POST -u <username>:<password> https://stackstorm.domain.tld/auth/v1/tokens
```

Here's an example of authenticating, using this auth method, with the `st2 login` command:

``` shell
$ st2 login <username>
Password: <password>
```

The configuration for this auth method will look like the following:

```
[auth]
mode = standalone
backend = vault
backend_kwargs = {"vault_url": "https://vault.domain.tld:8200", "auth_method": "ldap"}
enable = True
logging = /path/to/st2auth.logging.conf
api_url = https://myhost.example.com:9101
debug = False
```

### <a name="okta"></a> Auth Method: Okta

Okta is an auth method where you can authenticate against the Okta authentication
service using a username and password.
Okta account information is configured within Vault when setting up the auth method.
For more information on the Okta auth method, see the
[Vault Okta documentation](https://www.vaultproject.io/docs/auth/okta.html).

To utilize this method with StackStorm we will utilize the `username` and `password`
parameters passed into the `st2auth` service and map them to the following 
parameters for this  auth method:

| st2auth param | Okta param |
|---------------|------------|
| username      | username   |
| password      | password   |

Here's an example of authenticating, using this auth method, with a `curl` command:

``` shell
curl -k -X POST -u <username>:<password> https://stackstorm.domain.tld/auth/v1/tokens
```

Here's an example of authenticating, using this auth method, with the `st2 login` command:

``` shell
$ st2 login <username>
Password: <password>
```

The configuration for this auth method will look like the following:

```
[auth]
mode = standalone
backend = vault
backend_kwargs = {"vault_url": "https://vault.domain.tld:8200", "auth_method": "okta"}
enable = True
logging = /path/to/st2auth.logging.conf
api_url = https://myhost.example.com:9101
debug = False
```

### <a name="radius"></a> Auth Method: RADIUS

RADIUS is an auth method where you can authenticate against an existing RADIUS 
server that accepts the PAP authentication scheme.
RADIUS server information is configured within Vault when setting up the auth method.
For more information on the Radius auth method, see the
[Vault Radius documentation](https://www.vaultproject.io/docs/auth/radius.html).

To utilize this method with StackStorm we will utilize the `username` and `password`
parameters passed into the `st2auth` service and map them to the following 
parameters for this  auth method:

| st2auth param | RADIUS param |
|---------------|--------------|
| username      | username    |
| password      | password    |

Here's an example of authenticating, using this auth method, with a `curl` command:

``` shell
curl -k -X POST -u <username>:<password> https://stackstorm.domain.tld/auth/v1/tokens
```

Here's an example of authenticating, using this auth method, with the `st2 login` command:

``` shell
$ st2 login <username>
Password: <password>
```

The configuration for this auth method will look like the following:

```
[auth]
mode = standalone
backend = vault
backend_kwargs = {"vault_url": "https://vault.domain.tld:8200", "auth_method": "radius"}
enable = True
logging = /path/to/st2auth.logging.conf
api_url = https://myhost.example.com:9101
debug = False
```

### <a name="token"></a> Auth Method: Token

Token is an auth method where you can authenticate using a Vault Token (built-in).
For more information on the Token auth method, see the
[Vault Token documentation](https://www.vaultproject.io/docs/auth/token.html).

To utilize this method with StackStorm we will utilize the `username` and `password`
parameters passed into the `st2auth` service and map them to the following 
parameters for this  auth method:

| st2auth param | Token param |
|---------------|-------------|
| username      | <unused>  |
| password      | token       |

Here's an example of authenticating, using this auth method, with a `curl` command:

``` shell
curl -k -X POST -u unused:<token> https://stackstorm.domain.tld/auth/v1/tokens
```

Here's an example of authenticating, using this auth method, with the `st2 login` command:

``` shell
$ st2 login unused
Password: <token>
```

The configuration for this auth method will look like the following:

```
[auth]
mode = standalone
backend = vault
backend_kwargs = {"vault_url": "https://vault.domain.tld:8200", "auth_method": "token"}
enable = True
logging = /path/to/st2auth.logging.conf
api_url = https://myhost.example.com:9101
debug = False
```

### <a name="userpass"></a> Auth Method: Userpass

Userpass is an auth method where you can authenticate using a Vault uername
and password.
For more information on the Userpass auth method, see the
[Vault Userpass documentation](https://www.vaultproject.io/docs/auth/userpass.html).

To utilize this method with StackStorm we will utilize the `username` and `password`
parameters passed into the `st2auth` service and map them to the following 
parameters for this  auth method:

| st2auth param | Userpass param |
|---------------|----------------|
| username      | username       |
| password      | password       |

Here's an example of authenticating, using this auth method, with a `curl` command:

``` shell
curl -k -X POST -u <username>:<password> https://stackstorm.domain.tld/auth/v1/token
```

Here's an example of authenticating, using this auth method, with the `st2 login` command:

``` shell
$ st2 login <username>
Password: <password>
```

The configuration for this auth method will look like the following:

```
[auth]
mode = standalone
backend = vault
backend_kwargs = {"vault_url": "https://vault.domain.tld:8200", "auth_method": "userpass"}
enable = True
logging = /path/to/st2auth.logging.conf
api_url = https://myhost.example.com:9101
debug = False
```


### Development

To easily startup a Vault server simply run:

``` shell
vagrant up
```

This boots up a Docker container running Vault.

You can run commands within this container like so:

``` shell
vagrant docker-exec -- vault status
```

If you, for some reason, need to enter the container simply run:

``` shell
vagrant docker-exec -it -- /bin/sh
```

To stop the container:

``` shell
vagrant destroy
```

#### Development - Unit tests

Unit tests do not require the Vault container, instead the API is mocked out.
To execute the unit tests we'll setup a virtualenv, install tox, then run tox.

``` shell
virtualenv virtualenv
source ./virtualenv/bin/activate
pip install tox
tox -e py27,py36
```

You can also run the linting tests, after the virtualenv is activated:

``` shell
tox -e lint
```

Or, you can run them both together:

``` shell
tox -e py27,py36,lint
```

#### Development - Integration tests

Our integration tests rely on an instance of Vault running in a Docker container
that is started and managed by Vagrant. To execute these tests you will need
the following installed:

* Docker - install instructions [here](https://docs.docker.com/install/)
* Vagrant - install instructions [here](https://www.vagrantup.com/docs/installation/)

Once these dependencies have been installed we will tell Vagrant to start up
our Vault container, and then execute our integration tests using tox (our
virtualenv must be activated like above):

```shell
# start docker container with Vagrant
vagrant up

# setup virtualenv+tox
virtualenv virtualenv
source ./virtualenv/bin/activate
pip install tox

# run tests
tox -e integration

# stop docker container
vagrant destroy
```
