PHP_ARG_ENABLE(interceptor, whether to enable interceptor support,
   [  --enable-interceptor           Enable interceptor support])

if test "$PHP_INTERCEPTOR" != "no"; then
  PHP_NEW_EXTENSION(interceptor, interceptor.c, $ext_shared)
fi
