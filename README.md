# HashiCorp Vault authentication backend for StackStorm

[![Build Status](https://api.travis-ci.org/StackStorm/st2-auth-backend-vault.svg?branch=master)](https://travis-ci.org/StackStorm/st2-auth-backend-vault) [![IRC](https://img.shields.io/irc/%23stackstorm.png)](http://webchat.freenode.net/?channels=stackstorm)

### Overview

The HashiCorp Vault backend checks credentials and authenticates users against a
HashiCorp Vault instance. Vault itself supports multiple different 
[authentication methods](https://www.vaultproject.io/docs/auth/index.html)
detailed in their documentation. This backend can be configured to authenticate
with any of the currently available Vault auth methods, however only one Vault 
Auth Method can be configured at a time.

**Supported auth methods:**
* [app_id](https://www.vaultproject.io/docs/auth/app-id.html)
* [app_role](https://www.vaultproject.io/docs/auth/approle.html)
* [aws](https://www.vaultproject.io/docs/auth/aws.html)
* [azure](https://www.vaultproject.io/docs/auth/azure.html)
* [gcp](https://www.vaultproject.io/docs/auth/gcp.html)
* [github](https://www.vaultproject.io/docs/auth/github.html)
* [kubernetes](https://www.vaultproject.io/docs/auth/kubernetes.html)
* [ldap](https://www.vaultproject.io/docs/auth/ldap.html)
* [okta](https://www.vaultproject.io/docs/auth/okta.html)
* [radius](https://www.vaultproject.io/docs/auth/radius.html)
* [token](https://www.vaultproject.io/docs/auth/token.html)
* [userpass](https://www.vaultproject.io/docs/auth/userpass.html)

### Configuration Options

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
communicating with the Vault backend using the `userpass` auth method.

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

### Auth Method - App ID

App ID is an auth method where you can authenticate using an application
ID and a user ID. For more information on the App ID auth method, see the [App ID documentation](https://www.vaultproject.io/docs/auth/app-id.html).

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





* [app_role](https://www.vaultproject.io/docs/auth/approle.html)
* [aws](https://www.vaultproject.io/docs/auth/aws.html)
* [azure](https://www.vaultproject.io/docs/auth/azure.html)
* [gcp](https://www.vaultproject.io/docs/auth/gcp.html)
* [github](https://www.vaultproject.io/docs/auth/github.html)
* [kubernetes](https://www.vaultproject.io/docs/auth/kubernetes.html)
* [ldap](https://www.vaultproject.io/docs/auth/ldap.html)
* [okta](https://www.vaultproject.io/docs/auth/okta.html)
* [radius](https://www.vaultproject.io/docs/auth/radius.html)
* [token](https://www.vaultproject.io/docs/auth/token.html)
* [userpass](https://www.vaultproject.io/docs/auth/userpass.html)
