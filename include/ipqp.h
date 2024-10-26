#ifndef __LIB_IPQP_H__
#define __LIB_IPQP_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>

typedef enum ipqp_error_code
{
    IPQP_EC_SUCCESS = 0,
    IPQP_EC_FAIL = -1,
    IPQP_EC_TIMEOUT = -2,
    IPQP_EC_NULL_POINTER = -3,
    IPQP_EC_RTL_SRC_MISSING = -4,
    IPQP_EC_ALGO_MISSING = -5,
    IPQP_EC_PROV_NOT_CONFIGED = -6,
    IPQP_EC_SPI_IO = -7,
    IPQP_EC_UART_IO = -8,
    IPQP_EC_I2C_IO = -9,
    IPQP_EC_TCP_IO = -10
} IPQP_ErrorCode;

typedef enum ipqp_provider
{
    IPQP_PROV_LIBOQS = 0, // liboqs
    IPQP_PROV_SPI_ITRI,   // SPI device, with ITRI RTLs
    IPQP_PROV_UART_ITRI,  // UART device, with ITRI RTLs
    IPQP_PROV_I2C_ITRI,   // I2C device, with ITRI RTLs
    IPQP_PROV_TCP_ITRI   // TCP server, with ITRI RTLs
} IPQP_Provider;

typedef enum ipqp_algorithm
{
    // KEM
    IPQP_ALGO_KYBER_512 = 0xA1,
    IPQP_ALGO_KYBER_768 = 0xA2,
    IPQP_ALGO_KYBER_1024 = 0xA3,

    // DSA
    IPQP_ALGO_DILITHIUM_2 = 0xB1,
    IPQP_ALGO_DILITHIUM_3 = 0xB2,
    IPQP_ALGO_DILITHIUM_5 = 0xB3,
} IPQP_Algorithm;

typedef enum ipqp_data_length
{
    IPQP_KEM_kyber_512_length_public_key = 800,
    IPQP_KEM_kyber_512_length_secret_key = 1632,
    IPQP_KEM_kyber_512_length_ciphertext = 768,
    IPQP_KEM_kyber_512_length_shared_secret = 32,

    IPQP_KEM_kyber_768_length_public_key = 1184,
    IPQP_KEM_kyber_768_length_secret_key = 2400,
    IPQP_KEM_kyber_768_length_ciphertext = 1088,
    IPQP_KEM_kyber_768_length_shared_secret = 32,

    IPQP_KEM_kyber_1024_length_public_key = 1568,
    IPQP_KEM_kyber_1024_length_secret_key = 3168,
    IPQP_KEM_kyber_1024_length_ciphertext = 1568,
    IPQP_KEM_kyber_1024_length_shared_secret = 32,

    IPQP_DSA_dilithium_2_length_public_key = 1312,
    IPQP_DSA_dilithium_2_length_secret_key = 2528,
    IPQP_DSA_dilithium_2_length_signature = 2420,

    IPQP_DSA_dilithium_3_length_public_key = 1952,
    IPQP_DSA_dilithium_3_length_secret_key = 4000,
    IPQP_DSA_dilithium_3_length_signature = 3293,

    IPQP_DSA_dilithium_5_length_public_key = 2592,
    IPQP_DSA_dilithium_5_length_secret_key = 4864,
    IPQP_DSA_dilithium_5_length_signature = 4595
} IPQP_Data_Length;

IPQP_ErrorCode IPQP_config(IPQP_Provider prov, ...);

IPQP_ErrorCode IPQP_kem_keypair(IPQP_Algorithm i_kem_algo, uint8_t *o_pk, uint8_t *o_sk);
IPQP_ErrorCode IPQP_kem_encap(IPQP_Algorithm i_kem_algo, uint8_t *i_pk, uint8_t *o_ss, uint8_t *o_ct);
IPQP_ErrorCode IPQP_kem_decap(IPQP_Algorithm i_kem_algo, uint8_t *i_sk, uint8_t *i_ct, uint8_t *o_ss);

IPQP_ErrorCode IPQP_dsa_keypair(IPQP_Algorithm i_dsa_algo, uint8_t *o_pk, uint8_t *o_sk);
IPQP_ErrorCode IPQP_dsa_sign(IPQP_Algorithm i_dsa_algo, uint8_t *i_sk, uint8_t *i_msg, size_t i_msg_len, uint8_t *o_sm, size_t *o_sm_len);
IPQP_ErrorCode IPQP_dsa_verify(IPQP_Algorithm i_dsa_algo, uint8_t *i_pk, uint8_t *i_msg, size_t i_msg_len, uint8_t *i_sm, size_t i_sm_len, bool *o_verified);

#endif /* __LIB_IPQP_H__ */