# mod_token_binding
Toking Binding for Apache HTTP Server 2.x

Requires:
- OpenSSL 1.1.x  
  support for Extended Master Secret
- HTTPd 2.4.x-openssl-1.1.0-compat  
  with a patch to install the Token Binding Extension handler:  
  https://github.com/zmartzone/httpd/commit/0faae87c00d94ce4392b177e83f397f2fcc4abb3
- Google's Token Bind library  
  https://github.com/zmartzone/token_bind  
