# HashiCorp Vault authentication backend for StackStorm

[![Build Status](https://api.travis-ci.org/StackStorm/st2-auth-backend-vault.svg?branch=master)](https://travis-ci.org/StackStorm/st2-auth-backend-vault) [![IRC](https://img.shields.io/irc/%23stackstorm.png)](http://webchat.freenode.net/?channels=stackstorm)

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

Azure is an auth method where you can authenticate using an Azure role and JWT token.
For more information on the AWS auth method, see the
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

GCP is an auth method where you can authenticate using an Google Cloud Platform
role and JWT token. For more information on the GCP auth method, see the
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
curl -k -X POST -u nouser:<token> https://stackstorm.domain.tld/auth/v1/tokens
```

Here's an example of authenticating, using this auth method, with the `st2 login` command:

``` shell
$ st2 login nouser
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

Kubernetes is an auth method where you can authenticate using an Google Cloud Platform
role and JWT token. For more information on the GCP auth method, see the
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

* [kubernetes](https://www.vaultproject.io/docs/auth/kubernetes.html)
* [ldap](https://www.vaultproject.io/docs/auth/ldap.html)
* [okta](https://www.vaultproject.io/docs/auth/okta.html)
* [radius](https://www.vaultproject.io/docs/auth/radius.html)
* [token](https://www.vaultproject.io/docs/auth/token.html)
* [userpass](https://www.vaultproject.io/docs/auth/userpass.html)
