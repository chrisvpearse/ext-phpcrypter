#ifndef PHP_PHPCRYPTER_H
#define PHP_PHPCRYPTER_H

extern zend_module_entry phpcrypter_module_entry;
#define phpext_phpcrypter_ptr &phpcrypter_module_entry

#define PHPCRYPTER_VERSION "0.1.0"
#define PHPCRYPTER_SIG "<?php // @phpcrypter"

#define PHPCRYPTER_CIPHER_ALGO "AES-256-CBC"
#define PHPCRYPTER_KEY_LENGTH 32

ZEND_BEGIN_MODULE_GLOBALS(phpcrypter)
    zend_bool decrypt;
ZEND_END_MODULE_GLOBALS(phpcrypter)

#define PHPCRYPTER_G(v) (phpcrypter_globals.v)

#endif
