#include "kat.h"

uint8_t kat_kyber_1024_pk[IPQP_KEM_kyber_1024_length_public_key];
uint8_t kat_kyber_1024_sk[IPQP_KEM_kyber_1024_length_secret_key];
uint8_t kat_kyber_1024_ct[IPQP_KEM_kyber_1024_length_ciphertext];
uint8_t kat_kyber_1024_ss[IPQP_KEM_kyber_1024_length_shared_secret];

uint8_t kat_kyber_768_pk[IPQP_KEM_kyber_768_length_public_key];
uint8_t kat_kyber_768_sk[IPQP_KEM_kyber_768_length_secret_key];
uint8_t kat_kyber_768_ct[IPQP_KEM_kyber_768_length_ciphertext];
uint8_t kat_kyber_768_ss[IPQP_KEM_kyber_768_length_shared_secret];

uint8_t kat_kyber_512_pk[IPQP_KEM_kyber_512_length_public_key];
uint8_t kat_kyber_512_sk[IPQP_KEM_kyber_512_length_secret_key];
uint8_t kat_kyber_512_ct[IPQP_KEM_kyber_512_length_ciphertext];
uint8_t kat_kyber_512_ss[IPQP_KEM_kyber_512_length_shared_secret];

uint8_t kat_dilithium2_pk[IPQP_DSA_dilithium_2_length_public_key];
uint8_t kat_dilithium2_sk[IPQP_DSA_dilithium_2_length_secret_key];
uint8_t kat_dilithium2_msg[KAT_DILITHIUM2_MLEN];
uint8_t kat_dilithium2_sm[IPQP_DSA_dilithium_2_length_signature];

uint8_t kat_dilithium3_pk[IPQP_DSA_dilithium_3_length_public_key];
uint8_t kat_dilithium3_sk[IPQP_DSA_dilithium_3_length_secret_key];
uint8_t kat_dilithium3_msg[KAT_DILITHIUM3_MLEN];
uint8_t kat_dilithium3_sm[IPQP_DSA_dilithium_3_length_signature];

uint8_t kat_dilithium5_pk[IPQP_DSA_dilithium_5_length_public_key];
uint8_t kat_dilithium5_sk[IPQP_DSA_dilithium_5_length_secret_key];
uint8_t kat_dilithium5_msg[KAT_DILITHIUM5_MLEN];
uint8_t kat_dilithium5_sm[IPQP_DSA_dilithium_5_length_signature];

void convert_hex_string_to_array(const char *hex_str, uint8_t *arr, size_t arr_len)
{
    for (int i = 0; i < arr_len; i++)
    {
        uint32_t tmp_int = 0;
        char tmp_str[5] = "0x00";
        tmp_str[2] = hex_str[2 * i];
        tmp_str[3] = hex_str[(2 * i) + 1];
        sscanf(tmp_str, "%X", &tmp_int);
        arr[i] = tmp_int & 0xFF;
    }
}
void prepare_kat_data()
{
    convert_hex_string_to_array(KAT_KYBER_512_PK, kat_kyber_512_pk, IPQP_KEM_kyber_512_length_public_key);
    convert_hex_string_to_array(KAT_KYBER_512_SK, kat_kyber_512_sk, IPQP_KEM_kyber_512_length_secret_key);
    convert_hex_string_to_array(KAT_KYBER_512_CT, kat_kyber_512_ct, IPQP_KEM_kyber_512_length_ciphertext);
    convert_hex_string_to_array(KAT_KYBER_512_SS, kat_kyber_512_ss, IPQP_KEM_kyber_512_length_shared_secret);

    convert_hex_string_to_array(KAT_KYBER_768_PK, kat_kyber_768_pk, IPQP_KEM_kyber_768_length_public_key);
    convert_hex_string_to_array(KAT_KYBER_768_SK, kat_kyber_768_sk, IPQP_KEM_kyber_768_length_secret_key);
    convert_hex_string_to_array(KAT_KYBER_768_CT, kat_kyber_768_ct, IPQP_KEM_kyber_768_length_ciphertext);
    convert_hex_string_to_array(KAT_KYBER_768_SS, kat_kyber_768_ss, IPQP_KEM_kyber_768_length_shared_secret);

    convert_hex_string_to_array(KAT_KYBER_1024_PK, kat_kyber_1024_pk, IPQP_KEM_kyber_1024_length_public_key);
    convert_hex_string_to_array(KAT_KYBER_1024_SK, kat_kyber_1024_sk, IPQP_KEM_kyber_1024_length_secret_key);
    convert_hex_string_to_array(KAT_KYBER_1024_CT, kat_kyber_1024_ct, IPQP_KEM_kyber_1024_length_ciphertext);
    convert_hex_string_to_array(KAT_KYBER_1024_SS, kat_kyber_1024_ss, IPQP_KEM_kyber_1024_length_shared_secret);

    convert_hex_string_to_array(KAT_DILITHIUM2_PK, kat_dilithium2_pk, IPQP_DSA_dilithium_2_length_public_key);
    convert_hex_string_to_array(KAT_DILITHIUM2_SK, kat_dilithium2_sk, IPQP_DSA_dilithium_2_length_secret_key);
    convert_hex_string_to_array(KAT_DILITHIUM2_MSG, kat_dilithium2_msg, KAT_DILITHIUM2_MLEN);
    convert_hex_string_to_array(KAT_DILITHIUM2_SM, kat_dilithium2_sm, KAT_DILITHIUM2_SMLEN);

    convert_hex_string_to_array(KAT_DILITHIUM3_PK, kat_dilithium3_pk, IPQP_DSA_dilithium_3_length_public_key);
    convert_hex_string_to_array(KAT_DILITHIUM3_SK, kat_dilithium3_sk, IPQP_DSA_dilithium_3_length_secret_key);
    convert_hex_string_to_array(KAT_DILITHIUM3_MSG, kat_dilithium3_msg, KAT_DILITHIUM3_MLEN);
    convert_hex_string_to_array(KAT_DILITHIUM3_SM, kat_dilithium3_sm, KAT_DILITHIUM3_SMLEN);

    convert_hex_string_to_array(KAT_DILITHIUM5_PK, kat_dilithium5_pk, IPQP_DSA_dilithium_5_length_public_key);
    convert_hex_string_to_array(KAT_DILITHIUM5_SK, kat_dilithium5_sk, IPQP_DSA_dilithium_5_length_secret_key);
    convert_hex_string_to_array(KAT_DILITHIUM5_MSG, kat_dilithium5_msg, KAT_DILITHIUM5_MLEN);
    convert_hex_string_to_array(KAT_DILITHIUM5_SM, kat_dilithium5_sm, KAT_DILITHIUM5_SMLEN);
}
