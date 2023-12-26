#include "php.h"
#include "ext/standard/info.h"
#include "ext/standard/file.h"
#include "ext/standard/base64.h"
#include "ext/openssl/php_openssl.h"
#include "phpcrypter.h"

ZEND_DECLARE_MODULE_GLOBALS(phpcrypter)

static zend_op_array* (*old_compile_file)(zend_file_handle *file_handle, int type);
static zend_op_array* new_compile_file(zend_file_handle *file_handle, int type)
{
    if (PHP_VERSION_ID < 80200 || ! PHPCRYPTER_G(decrypt)) {
        return old_compile_file(file_handle, type);
    }

    unsigned char xor_key_58[] = {0xe8}; unsigned char xor_key_35[] = {0x20}; unsigned char key_xor_59[] = {0x65}; unsigned char key_xor_46[] = {0x8b}; unsigned char xor_key_28[] = {0x1f}; unsigned char xor_key_26[] = {0xc2}; unsigned char key_xor_19[] = {0x21}; unsigned char key_xor_56[] = {0xf0}; unsigned char key_xor_4[] = {0xad}; unsigned char key_xor_27[] = {0xf8}; unsigned char key_xor_43[] = {0xc7}; unsigned char key_xor_30[] = {0x56}; unsigned char xor_key_43[] = {0xf7}; unsigned char xor_key_54[] = {0x3b}; unsigned char xor_key_49[] = {0xfb}; unsigned char xor_key_15[] = {0x8b}; unsigned char key_xor_61[] = {0x4b}; unsigned char key_xor_63[] = {0x31}; unsigned char key_xor_39[] = {0x80}; unsigned char xor_key_25[] = {0xbd}; unsigned char key_xor_60[] = {0xae}; unsigned char xor_key_1[] = {0xbb}; unsigned char key_xor_1[] = {0xfa}; unsigned char key_xor_10[] = {0x0e}; unsigned char key_xor_32[] = {0xe4}; unsigned char key_xor_22[] = {0xe6}; unsigned char xor_key_11[] = {0x32}; unsigned char xor_key_2[] = {0x8c}; unsigned char xor_key_63[] = {0x66}; unsigned char xor_key_48[] = {0x73}; unsigned char key_xor_54[] = {0x2a}; unsigned char key_xor_23[] = {0x6c}; unsigned char xor_key_16[] = {0xa6}; unsigned char xor_key_45[] = {0x87}; unsigned char key_xor_16[] = {0x72}; unsigned char key_xor_40[] = {0xf4}; unsigned char xor_key_30[] = {0x3f}; unsigned char xor_key_41[] = {0xba}; unsigned char key_xor_35[] = {0x2a}; unsigned char xor_key_17[] = {0x28}; unsigned char xor_key_50[] = {0x61}; unsigned char xor_key_20[] = {0xd9}; unsigned char key_xor_34[] = {0x03}; unsigned char key_xor_24[] = {0x0f}; unsigned char key_xor_62[] = {0x27}; unsigned char key_xor_44[] = {0x0b}; unsigned char key_xor_52[] = {0x4a}; unsigned char key_xor_37[] = {0x78}; unsigned char key_xor_5[] = {0x69}; unsigned char xor_key_60[] = {0xc5}; unsigned char key_xor_50[] = {0x6e}; unsigned char key_xor_25[] = {0x22}; unsigned char key_xor_57[] = {0x55}; unsigned char xor_key_5[] = {0xdc}; unsigned char key_xor_3[] = {0xf3}; unsigned char key_xor_64[] = {0xe4}; unsigned char xor_key_33[] = {0xff}; unsigned char key_xor_33[] = {0xd8}; unsigned char xor_key_55[] = {0xef}; unsigned char xor_key_32[] = {0x6f}; unsigned char xor_key_59[] = {0x1a}; unsigned char xor_key_44[] = {0x9b}; unsigned char xor_key_42[] = {0x1e}; unsigned char xor_key_40[] = {0x5e}; unsigned char key_xor_26[] = {0x05}; unsigned char xor_key_37[] = {0x9e}; unsigned char xor_key_23[] = {0xd4}; unsigned char xor_key_27[] = {0x49}; unsigned char key_xor_13[] = {0xdb}; unsigned char xor_key_64[] = {0x13}; unsigned char key_xor_28[] = {0x41}; unsigned char xor_key_62[] = {0xe2}; unsigned char xor_key_24[] = {0xd3}; unsigned char key_xor_31[] = {0xcb}; unsigned char key_xor_12[] = {0x42}; unsigned char key_xor_36[] = {0x07}; unsigned char key_xor_20[] = {0x45}; unsigned char xor_key_46[] = {0x8a}; unsigned char xor_key_19[] = {0x4e}; unsigned char xor_key_53[] = {0x04}; unsigned char key_xor_21[] = {0x67}; unsigned char key_xor_9[] = {0x84}; unsigned char xor_key_7[] = {0x38}; unsigned char xor_key_14[] = {0x22}; unsigned char key_xor_48[] = {0x39}; unsigned char xor_key_36[] = {0xaf}; unsigned char key_xor_14[] = {0xa1}; unsigned char xor_key_6[] = {0x99}; unsigned char xor_key_21[] = {0xa9}; unsigned char key_xor_41[] = {0xd9}; unsigned char key_xor_38[] = {0xd6}; unsigned char key_xor_49[] = {0xca}; unsigned char key_xor_18[] = {0x10}; unsigned char key_xor_58[] = {0xf1}; unsigned char xor_key_56[] = {0x79}; unsigned char key_xor_8[] = {0x32}; unsigned char key_xor_53[] = {0x78}; unsigned char xor_key_3[] = {0xba}; unsigned char xor_key_18[] = {0xd1}; unsigned char key_xor_51[] = {0xbc}; unsigned char key_xor_29[] = {0x2d}; unsigned char key_xor_42[] = {0x00}; unsigned char xor_key_12[] = {0x17}; unsigned char xor_key_51[] = {0x24}; unsigned char xor_key_61[] = {0x45}; unsigned char key_xor_6[] = {0x5e}; unsigned char xor_key_52[] = {0x42}; unsigned char xor_key_31[] = {0xcc}; unsigned char key_xor_7[] = {0x81}; unsigned char xor_key_34[] = {0x41}; unsigned char xor_key_29[] = {0x39}; unsigned char xor_key_8[] = {0xa5}; unsigned char xor_key_57[] = {0xe9}; unsigned char xor_key_9[] = {0x2b}; unsigned char xor_key_4[] = {0x22}; unsigned char xor_key_38[] = {0xc5}; unsigned char key_xor_55[] = {0x84}; unsigned char key_xor_45[] = {0x0c}; unsigned char key_xor_17[] = {0x58}; unsigned char key_xor_15[] = {0xda}; unsigned char key_xor_2[] = {0xf1}; unsigned char xor_key_22[] = {0xc0}; unsigned char key_xor_47[] = {0xb9}; unsigned char xor_key_13[] = {0xa9}; unsigned char xor_key_39[] = {0x76}; unsigned char key_xor_11[] = {0x81}; unsigned char xor_key_47[] = {0xc8}; unsigned char xor_key_10[] = {0x75};

    do {
        FILE *fp;

        fp = fopen(ZSTR_VAL(file_handle->filename), "rb");

        if (! fp) {
            break;
        }

        char sig[] = PHPCRYPTER_SIG;
        size_t sig_length = strlen(sig);

        char *sig_buffer = (char *)emalloc(sig_length);
        fread(sig_buffer, sizeof(char), sig_length, fp);

        if (memcmp(sig_buffer, sig, sig_length) != 0) {
            fclose(fp);

            efree(sig_buffer);

            break;
        }

        efree(sig_buffer);

        fseek(fp, 0, SEEK_END);
        long file_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        char *file_contents = (char *)emalloc(file_size);
        fread(file_contents, sizeof(char), file_size, fp);

        fclose(fp);

        strtok(file_contents, "#");
        char *encoded_data = strtok(NULL, "#");

        efree(file_contents);

        if (! encoded_data) {
            break;
        }

        zend_string *tmp_encoded_data = zend_string_init(encoded_data, strlen(encoded_data), 0);
        zend_string *decoded_data = php_base64_decode_str(tmp_encoded_data);
        zend_string_release(tmp_encoded_data);

        if (! ZSTR_LEN(decoded_data)) {
            break;
        }

        char *phpcrypter_version = strtok(ZSTR_VAL(decoded_data), ",");
        char *encoded_iv = strtok(NULL, ",");
        char *encrypted_data = strtok(NULL, ",");

        zend_string_release(decoded_data);

        if (! phpcrypter_version || ! encoded_iv || ! encrypted_data) {
            break;
        }

        if (strcmp(phpcrypter_version, PHPCRYPTER_VERSION) != 0) {
            break;
        }

        zend_string *tmp_encoded_iv = zend_string_init(encoded_iv, strlen(encoded_iv), 0);
        zend_string *decoded_iv = php_base64_decode_str(tmp_encoded_iv);
        zend_string_release(tmp_encoded_iv);

        if (! ZSTR_LEN(decoded_iv)) {
            break;
        }

        char *iv = ZSTR_VAL(decoded_iv);

        size_t key_xor_length = PHPCRYPTER_KEY_LENGTH;
        size_t xor_key_length = PHPCRYPTER_KEY_LENGTH;

        char key_xor[key_xor_length];
        char xor_key[xor_key_length];

        memcpy(key_xor + 0, key_xor_1, sizeof(key_xor_1)); memcpy(key_xor + 1, key_xor_2, sizeof(key_xor_2)); memcpy(key_xor + 2, key_xor_3, sizeof(key_xor_3)); memcpy(key_xor + 3, key_xor_4, sizeof(key_xor_4)); memcpy(key_xor + 4, key_xor_5, sizeof(key_xor_5)); memcpy(key_xor + 5, key_xor_6, sizeof(key_xor_6)); memcpy(key_xor + 6, key_xor_7, sizeof(key_xor_7)); memcpy(key_xor + 7, key_xor_8, sizeof(key_xor_8)); memcpy(key_xor + 8, key_xor_9, sizeof(key_xor_9)); memcpy(key_xor + 9, key_xor_10, sizeof(key_xor_10)); memcpy(key_xor + 10, key_xor_11, sizeof(key_xor_11)); memcpy(key_xor + 11, key_xor_12, sizeof(key_xor_12)); memcpy(key_xor + 12, key_xor_13, sizeof(key_xor_13)); memcpy(key_xor + 13, key_xor_14, sizeof(key_xor_14)); memcpy(key_xor + 14, key_xor_15, sizeof(key_xor_15)); memcpy(key_xor + 15, key_xor_16, sizeof(key_xor_16)); memcpy(key_xor + 16, key_xor_17, sizeof(key_xor_17)); memcpy(key_xor + 17, key_xor_18, sizeof(key_xor_18)); memcpy(key_xor + 18, key_xor_19, sizeof(key_xor_19)); memcpy(key_xor + 19, key_xor_20, sizeof(key_xor_20)); memcpy(key_xor + 20, key_xor_21, sizeof(key_xor_21)); memcpy(key_xor + 21, key_xor_22, sizeof(key_xor_22)); memcpy(key_xor + 22, key_xor_23, sizeof(key_xor_23)); memcpy(key_xor + 23, key_xor_24, sizeof(key_xor_24)); memcpy(key_xor + 24, key_xor_25, sizeof(key_xor_25)); memcpy(key_xor + 25, key_xor_26, sizeof(key_xor_26)); memcpy(key_xor + 26, key_xor_27, sizeof(key_xor_27)); memcpy(key_xor + 27, key_xor_28, sizeof(key_xor_28)); memcpy(key_xor + 28, key_xor_29, sizeof(key_xor_29)); memcpy(key_xor + 29, key_xor_30, sizeof(key_xor_30)); memcpy(key_xor + 30, key_xor_31, sizeof(key_xor_31)); memcpy(key_xor + 31, key_xor_32, sizeof(key_xor_32)); memcpy(xor_key + 0, xor_key_1, sizeof(xor_key_1)); memcpy(xor_key + 1, xor_key_2, sizeof(xor_key_2)); memcpy(xor_key + 2, xor_key_3, sizeof(xor_key_3)); memcpy(xor_key + 3, xor_key_4, sizeof(xor_key_4)); memcpy(xor_key + 4, xor_key_5, sizeof(xor_key_5)); memcpy(xor_key + 5, xor_key_6, sizeof(xor_key_6)); memcpy(xor_key + 6, xor_key_7, sizeof(xor_key_7)); memcpy(xor_key + 7, xor_key_8, sizeof(xor_key_8)); memcpy(xor_key + 8, xor_key_9, sizeof(xor_key_9)); memcpy(xor_key + 9, xor_key_10, sizeof(xor_key_10)); memcpy(xor_key + 10, xor_key_11, sizeof(xor_key_11)); memcpy(xor_key + 11, xor_key_12, sizeof(xor_key_12)); memcpy(xor_key + 12, xor_key_13, sizeof(xor_key_13)); memcpy(xor_key + 13, xor_key_14, sizeof(xor_key_14)); memcpy(xor_key + 14, xor_key_15, sizeof(xor_key_15)); memcpy(xor_key + 15, xor_key_16, sizeof(xor_key_16)); memcpy(xor_key + 16, xor_key_17, sizeof(xor_key_17)); memcpy(xor_key + 17, xor_key_18, sizeof(xor_key_18)); memcpy(xor_key + 18, xor_key_19, sizeof(xor_key_19)); memcpy(xor_key + 19, xor_key_20, sizeof(xor_key_20)); memcpy(xor_key + 20, xor_key_21, sizeof(xor_key_21)); memcpy(xor_key + 21, xor_key_22, sizeof(xor_key_22)); memcpy(xor_key + 22, xor_key_23, sizeof(xor_key_23)); memcpy(xor_key + 23, xor_key_24, sizeof(xor_key_24)); memcpy(xor_key + 24, xor_key_25, sizeof(xor_key_25)); memcpy(xor_key + 25, xor_key_26, sizeof(xor_key_26)); memcpy(xor_key + 26, xor_key_27, sizeof(xor_key_27)); memcpy(xor_key + 27, xor_key_28, sizeof(xor_key_28)); memcpy(xor_key + 28, xor_key_29, sizeof(xor_key_29)); memcpy(xor_key + 29, xor_key_30, sizeof(xor_key_30)); memcpy(xor_key + 30, xor_key_31, sizeof(xor_key_31)); memcpy(xor_key + 31, xor_key_32, sizeof(xor_key_32));

        char key[key_xor_length];

        for (size_t i = 0; i < key_xor_length; i++) {
            key[i] = key_xor[i] ^ xor_key[i % sizeof(xor_key)];
        }

        char *cipher_algo = PHPCRYPTER_CIPHER_ALGO;

        zend_string *decrypted_data = php_openssl_decrypt(
            encrypted_data, strlen(encrypted_data),
            cipher_algo, strlen(cipher_algo),
            key, strlen(key),
            0,
            iv, strlen(iv),
            NULL, 0,
            NULL, 0
        );

        if (! ZSTR_LEN(decrypted_data)) {
            break;
        }

        size_t decrypted_data_length = ZSTR_LEN(decrypted_data);
        char *new_buffer = estrndup(ZSTR_VAL(decrypted_data), decrypted_data_length);

        zend_string_release(decrypted_data);

        char *tmp_buffer = NULL;
        size_t tmp_length = 0;

        if (zend_stream_fixup(file_handle, &tmp_buffer, &tmp_length) == FAILURE) {
            break;
        }

        if (file_handle->buf != NULL) {
            efree(file_handle->buf);
        }

        file_handle->buf = new_buffer;
        file_handle->len = decrypted_data_length;
    } while (0);

    return old_compile_file(file_handle, type);
}

static void php_phpcrypter_init_globals(zend_phpcrypter_globals *phpcrypter_globals) {
    phpcrypter_globals->decrypt = 0;
}

PHP_INI_BEGIN()
    STD_PHP_INI_BOOLEAN("phpcrypter.decrypt", "0", PHP_INI_ALL, OnUpdateBool, decrypt, zend_phpcrypter_globals, phpcrypter_globals)
PHP_INI_END()

PHP_MINIT_FUNCTION(phpcrypter)
{
    ZEND_INIT_MODULE_GLOBALS(phpcrypter, php_phpcrypter_init_globals, NULL);
    REGISTER_INI_ENTRIES();

    old_compile_file = zend_compile_file;
    zend_compile_file = new_compile_file;

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(phpcrypter)
{
    zend_compile_file = old_compile_file;

    return SUCCESS;
}

PHP_RINIT_FUNCTION(phpcrypter)
{
    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(phpcrypter)
{
    return SUCCESS;
}

PHP_MINFO_FUNCTION(phpcrypter)
{
    php_info_print_table_start();
    php_info_print_table_row(2, "phpcrypter", "enabled");
    php_info_print_table_row(2, "version", PHPCRYPTER_VERSION);
    php_info_print_table_end();
}

zend_function_entry phpcrypter_functions[] = {
    ZEND_FE_END
};

zend_module_entry phpcrypter_module_entry = {
    STANDARD_MODULE_HEADER,
    "phpcrypter",
    phpcrypter_functions,
    PHP_MINIT(phpcrypter),
    PHP_MSHUTDOWN(phpcrypter),
    PHP_RINIT(phpcrypter),
    PHP_RSHUTDOWN(phpcrypter),
    PHP_MINFO(phpcrypter),
    PHPCRYPTER_VERSION,
    STANDARD_MODULE_PROPERTIES
};

ZEND_GET_MODULE(phpcrypter)
