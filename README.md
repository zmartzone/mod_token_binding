# mod_token_binding
Toking Binding for Apache HTTP Server 2.x

Requires:
- OpenSSL 1.1.x  
  support for Extended Master Secret  
  with a patch to fix resume with custom extensions:  
  https://github.com/zmartzone/token_bind/blob/master/example/custom_ext_resume.patch
- HTTPd 2.4.x-openssl-1.1.0-compat  
  with a patch to install the Token Binding Extension handler:  
  https://github.com/zmartzone/httpd/commit/0faae87c00d94ce4392b177e83f397f2fcc4abb3
- Google's Token Bind library  
  https://github.com/zmartzone/token_bind  

## Overview

This module implements the Token Binding protocol as defined in [https://github.com/TokenBinding/Internet-Drafts](https://github.com/TokenBinding/Internet-Drafts) on HTTPs connections setup to `mod_ssl` running in an Apache webserver.
 
It then sets environment variables with the results of that process so that other modules and applications running on top of it can use that to bind their tokens and cookies to the so-called Token Binding ID. The environment variables are:

- `Token-Binding-ID-Provided`  
  The Provided Token Binding ID that the browser uses towards your Apache server.
- `Token-Binding-ID-Referred`  
  The Referred Token Binding ID (if any) that the User Agent used on the "leg" to a remote entity that you federate with.
- `Token-Binding-Context`  
  The key parameters negotiated on the Provided Token Binding ID conform [https://tools.ietf.org/html/draft-campbell-tokbind-tls-term-00#section-2](https://tools.ietf.org/html/draft-campbell-tokbind-tls-term-00#section-2).

One could also pass these results to the backend in a header as with e.g.:
```
RequestHeader set Token-Binding-Context "%{Token-Binding-Context}e"
```

## Quickstart

There’s a sample `Dockerfile` under `test/docker` to get you to a quick functional server setup with all of the prerequisites listed above and a very light-weight HTML sample application (processing server side includes).

## Application

Since version 2.2.0 [mod_auth_openidc](https://github.com/pingidentity/mod_auth_openidc) can be configured to use the negotiated environment variables to bind its session cookie to the TLS connection and to perform OpenID Connect Token Bound Authentication for an ID Token as defined in [http://openid.net/specs/openid-connect-token-bound-authentication-1_0.html](http://openid.net/specs/openid-connect-token-bound-authentication-1_0.html) using its `OIDCTokenBindingPolicy` directive as described in https://github.com/pingidentity/mod_auth_openidc/blob/v2.3.0/auth_openidc.conf#L205.
