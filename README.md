# mod_token_binding

A pluggable module implementation of Token Binding for the Apache HTTPd web server version 2.4.x.

## Overview

This module implements the Token Binding protocol as defined in [https://github.com/TokenBinding/Internet-Drafts](https://github.com/TokenBinding/Internet-Drafts) on HTTPs connections setup to `mod_ssl` running in an Apache webserver.
 
It then sets environment variables and headers with the results of that process so that other modules and applications running on top of (or behind) it can use that to bind their tokens and cookies to the so-called Token Binding ID. The environment variables/headers are:

- `Sec-Provided-Token-Binding-ID`  
  The Provided Token Binding ID that the browser uses towards your Apache server conforming to [draft-ietf-tokbind-ttrp-05](https://tools.ietf.org/html/draft-ietf-tokbind-ttrp-05#section-2.2).
- `Sec-Referred-Token-Binding-ID`  
  The Referred Token Binding ID (if any) that the User Agent used on the "leg" to a remote entity that you federate with conforming to [draft-ietf-tokbind-ttrp-05](https://tools.ietf.org/html/draft-ietf-tokbind-ttrp-05#section-2.2).
- `Sec-Token-Binding-Context`  
  The key parameters negotiated on the Provided Token Binding ID conforming to [draft-campbell-tokbind-tls-term-00](https://tools.ietf.org/html/draft-campbell-tokbind-tls-term-00#section-2) (with a `Sec-` prefix added to the header).

## Quickstart

There’s a sample `Dockerfile` under `test/docker` to get you to a quick functional server setup with all of the prerequisites listed above. It reverse proxies requests to `http://httpbin.org/headers` to show the resulting request headers.
Build and run this container on a Docker-equipped system with `./autogen.sh && ./configure && make docker` and then browse to [https://localhost:4433](https://localhost:4433)`.

## Application

Since version 2.3.1 [mod_auth_openidc](https://github.com/zmartzone/mod_auth_openidc) can be configured to use the negotiated environment variables to bind its session (and state) cookie(s) to the TLS connection and to perform OpenID Connect Token Bound Authentication for an ID Token as defined in [http://openid.net/specs/openid-connect-token-bound-authentication-1_0.html](http://openid.net/specs/openid-connect-token-bound-authentication-1_0.html) using its `OIDCTokenBindingPolicy` directive as described in [https://github.com/zmartzone/mod_auth_openidc/blob/v2.3.5/auth_openidc.conf#L211](https://github.com/zmartzone/mod_auth_openidc/blob/v2.3.5/auth_openidc.conf#L211).

## Requirements

- OpenSSL 1.1.x  
  support for Extended Master Secret  
  with a patch to fix resume with custom extensions:  
  https://github.com/zmartzone/token_bind/blob/master/example/custom_ext_resume.patch
- HTTPd 2.4.x with mod_ssl (>= 2.4.26 for OpenSSL 1.1.x support)  
- Google's Token Bind library  
  with a patch to expose the `getNegotiatedVersion` function:
  https://github.com/zmartzone/token_bind/tree/expose-negotiated-version  

## Installation and Configuration

Edit the configuration file for your web server. Depending on
your distribution, it may be named '/etc/apache/httpd.conf' or something
different.

You need to add a LoadModule directive for mod_token_binding. This will
look similar to this:

```apache
LoadModule token_binding_module /usr/lib/apache2/modules/mod_token_binding.so
```

You can then optionally configure mod_token_binding with specific configuration primitives.
For an exhaustive overview of all configuration primitives, see `token_binding.conf` in this directory.
That file can also function as an include file for Apache.

## Support

#### Community Support
For generic questions, see the Wiki pages with Frequently Asked Questions at:  
  [https://github.com/zmartzone/mod_token_binding/wiki](https://github.com/zmartzone/mod_token_binding/wiki)  
Any questions/issues should go to issues tracker.

#### Commercial Services
For commercial Support contracts, Professional Services, Training and use-case specific support you can contact:  
  [sales@zmartzone.eu](mailto:sales@zmartzone.eu)  

Disclaimer
----------

*This software is open sourced by ZmartZone IAM. For commercial support
you can contact [ZmartZone IAM](https://www.zmartzone.eu) as described above in the [Support](#support) section.*
