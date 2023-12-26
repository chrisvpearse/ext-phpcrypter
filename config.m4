PHP_ARG_ENABLE(phpcrypter, whether to enable phpcrypter support,
[  --enable-phpcrypter        Enable phpcrypter support])

if test "$PHP_PHPCRYPTER" != "no"; then
    PHP_NEW_EXTENSION(phpcrypter, phpcrypter.c, $ext_shared)
fi
