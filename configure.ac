AC_INIT([mod_token_binding],[0.1.0],[hans.zandbelt@zmartzone.eu])

AC_SUBST(NAMEVER, AC_PACKAGE_TARNAME()-AC_PACKAGE_VERSION())

# This section defines the --with-apxs2 option.
AC_ARG_WITH(
	[apxs2],
	[  --with-apxs2=PATH       Full path to the apxs2 executable.],
	[
		APXS2=${withval}
	],)


if test "x$APXS2" = "x"; then
   # The user didn't specify the --with-apxs2-option.

   # Search for apxs2 in the specified directories
   AC_PATH_PROG(APXS2, apxs2,,
		/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin)

   if test "x$APXS2" = "x"; then
      # Didn't find apxs2 in any of the specified directories.
      # Search for apxs instead.
      AC_PATH_PROG(APXS2, apxs,,
		   /usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin)
   fi

fi

# Test if $APXS2 exists and is an executable.
if test ! -x "$APXS2"; then
   # $APXS2 isn't a executable file.
   AC_MSG_ERROR([
Could not find apxs2. Please specify the path to apxs2
using the --with-apxs2=/full/path/to/apxs2 option.
The executable may also be named 'apxs'.
])
fi

# Replace any occurrences of @APXS2@ with the value of $APXS2 in the Makefile.
AC_SUBST(APXS2)

# Use environment variable APXS2_OPTS to pass params to APXS2 command
AC_ARG_VAR(APXS2_OPTS, [Additional command line options to pass to apxs2.])

# We need OpenSSL for crypto
PKG_CHECK_MODULES(OPENSSL, openssl)
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)

PKG_CHECK_MODULES(APR, [apr-1, apr-util-1])
AC_SUBST(APR_CFLAGS)
AC_SUBST(APR_LIBS)

AC_MSG_CHECKING([for Token Bind])
AC_ARG_WITH(
	[token-binding],
	[  --with-token-binding=PATH       Full path to the token binding library.],
	[
		TOKEN_BINDING=${withval}
	],)
if test ! -d "$TOKEN_BINDING"; then
   AC_MSG_RESULT([no])
   AC_MSG_ERROR([
Could not find Token Bind. Please specify the path to Token Bind
using the --with-token-binding=/full/path/to/token_bind option.
])
fi
AC_MSG_RESULT([yes])
AC_SUBST(TOKEN_BINDING)

# Create Makefile from Makefile.in
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
