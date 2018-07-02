# OpenStack Keystone authentication plugin for StackStorm Community edition

[![Build Status](https://api.travis-ci.org/StackStorm/st2-auth-backend-keystone.svg?branch=master)](https://travis-ci.org/StackStorm/st2-auth-backend-keystone) [![IRC](https://img.shields.io/irc/%23stackstorm.png)](http://webchat.freenode.net/?channels=stackstorm)

The OpenStack Keystone backend reads credentials and authenticates user against an OpenStack
Keystone instance. This backend was originally contributed to st2 repo by [itaka](
https://github.com/Itxaka) under [PR #1732](https://github.com/StackStorm/st2/pull/1732),
[PR #1737](https://github.com/StackStorm/st2/pull/1737), and 
[PR #1984](https://github.com/StackStorm/st2/pull/1984).

### Configuration Options

| option           | required | default | description                                              |
|------------------|----------|---------|----------------------------------------------------------|
| keystone_url     | yes      |         | Keystone public URL (i.e. "http://example.com:5000")     |
| keystone_version | no       | 2       | Keystone API version                                     |

### Configuration Example

Please refer to the authentication section in the StackStorm
[documentation](http://docs.stackstorm.com) for basic setup concept. The
following is an example of the auth section in the StackStorm configuration file for the flat-file
backend.

```
[auth]
mode = standalone
backend = keystone
backend_kwargs = {"keystone_url": "http://identity.example.com:5000", "keystone_version": 2}
enable = True
use_ssl = True
cert = /path/to/ssl/cert/file
key = /path/to/ssl/key/file
logging = /path/to/st2auth.logging.conf
api_url = https://myhost.example.com:9101
debug = False
```

## Copyright, License, and Contributors Agreement

Copyright 2015 StackStorm, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this work except in
compliance with the License. You may obtain a copy of the License in the [LICENSE](LICENSE) file,
or at: [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

By contributing you agree that these contributions are your own (or approved by your employer) and 
you grant a full, complete, irrevocable copyright license to all users and developers of the
project, present and future, pursuant to the license of the project.
