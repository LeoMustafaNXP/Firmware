/**
 * \file mbedtls_cfg.h
 *
 * \brief User config for mbedtls (overriding default config)
 * 
 * Custom configuration of mbedtls.
 * Set this file's include path in DMBEDTLS_USER_CONFIG_FILE!
 */

#define MBEDTLS_TEST_NULL_ENTROPY

#define MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
#define MBEDTLS_NO_PLATFORM_ENTROPY

#undef MBEDTLS_TIMING_C
