
#include "test_common.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#define BUFFER_SIZE 1024
#define MAX_PENDING_CONNECTIONS 5

int receive_apdu_command(int tcp_fd, apdu_t *rcvd_apdu, uint8_t **ret_data);

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("usage: %s [port]\r\n", argv[0]);
        return EXIT_FAILURE;
    }

    int port = atoi(argv[1]);

    int server_fd, err;
    struct sockaddr_in server, client;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        printf("Could not create socket\r\n");
        return EXIT_FAILURE;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = htonl(INADDR_ANY);

    int opt_val = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof opt_val);

    if (bind(server_fd, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        printf("Could not bind socket\n");
        return EXIT_FAILURE;
    }

    // Listen for incoming connections
    if (listen(server_fd, MAX_PENDING_CONNECTIONS) < 0)
    {
        printf("Could not listen on socket\n");
        return EXIT_FAILURE;
    }

    while (true)
    {
        printf("================================================================\r\n");
        printf("Server is listening on %d\n", port);
        printf("waiting for connection...\n");

        socklen_t client_len = sizeof(client);
        int client_fd = accept(server_fd, (struct sockaddr *)&client, &client_len);

        if (client_fd < 0)
        {
            printf("Could not establish new connection\n");
            continue;
        }

        apdu_t rcvd_apdu;
        bzero(&rcvd_apdu, sizeof(rcvd_apdu));
        rcvd_apdu.data = NULL;

        tcp_conf_t tcp_conf;
        tcp_conf.fd = client_fd;
        tcp_conf.retries_on_failure = 10000000;

        uint8_t *snd_buff = NULL;

        // receive apdu command
        if (receive_apdu_command(client_fd, &rcvd_apdu, &snd_buff) < 0)
        {
            printf("[ERROR]: receive_apdu_command()\r\n");
            close(client_fd);
            break;
        }
        PRINTF("receive_apdu_command():: Success\r\n");

        printf("apdu.cla: 0x%02X\r\n", rcvd_apdu.cla);
        printf("apdu.ins: 0x%02X\r\n", rcvd_apdu.ins);
        printf("apdu.p1: 0x%02X\r\n", rcvd_apdu.p1);
        printf("apdu.p2: 0x%02X\r\n", rcvd_apdu.p2);
        printf("apdu.lc: 0x%06X (%d)\r\n", rcvd_apdu.lc, rcvd_apdu.lc);
        printf("apdu.le: 0x%06X (%d)\r\n", rcvd_apdu.le, rcvd_apdu.le);
        if (rcvd_apdu.lc > 0)
            print_arr(rcvd_apdu.data, rcvd_apdu.lc, 32, "apdu.data");
        else
            printf("apdu.data: NULL\r\n");

        // getchar();

        if (tcp_send_ack(&tcp_conf) != IPQP_EC_SUCCESS)
        {
            printf("[ERROR]: tcp_send_ack()\r\n");
            close(client_fd);
            if (rcvd_apdu.data != NULL)
                free(rcvd_apdu.data);
            if (snd_buff != NULL)
                free(snd_buff);
            break;
        }

        if (tcp_receive_ack(&tcp_conf) != IPQP_EC_SUCCESS)
        {
            printf("[ERROR]: tcp_receive_ack()\r\n");
            close(client_fd);
            if (rcvd_apdu.data != NULL)
                free(rcvd_apdu.data);
            if (snd_buff != NULL)
                free(snd_buff);
            break;
        }
        PRINTF("tcp_receive_ack()\r\n");

        if (rcvd_apdu.le > 0)
        {
            /*
            snd_buff = (uint8_t *)malloc(sizeof(uint8_t) * rcvd_apdu.le);
            for (int i = 0; i < rcvd_apdu.le; i++)
                snd_buff[i] = i % 256;
            */

            err = send(client_fd, snd_buff, rcvd_apdu.le, 0);

            if (snd_buff != NULL)
            {
                free(snd_buff);
                snd_buff = NULL;
            }

            if (err < 0)
            {
                printf("Client write failed\n");
                close(client_fd);
                break;
            }
        }

        if (rcvd_apdu.data != NULL)
            free(rcvd_apdu.data);

        if (snd_buff != NULL)
            free(snd_buff);

        close(client_fd);
    }

    return EXIT_FAILURE;
}

#define IPQP_EC_CHECK(ipqp_ec, buff, err_log) \
    if (ipqp_ec != IPQP_EC_SUCCESS)           \
    {                                         \
        if (strlen(err_log) > 1)              \
            printf(err_log);                  \
        if (buff != NULL)                     \
        {                                     \
            free(buff);                       \
            buff = NULL;                      \
        }                                     \
        return -1;                            \
    }

int receive_apdu_command(int tcp_fd, apdu_t *rcvd_apdu, uint8_t **ret_data)
{
    // receive apdu header (cla -> lc)
    uint8_t buff[7];
    tcp_conf_t tcp_conf;
    tcp_conf.fd = tcp_fd;
    tcp_conf.retries_on_failure = 10000000;

    IPQP_ErrorCode ipqp_ec = IPQP_EC_SUCCESS;

    // read apdu header
    ipqp_ec = tcp_read_packet(&tcp_conf, buff, 7);
    IPQP_EC_CHECK(ipqp_ec, *ret_data, "[ERROR]: tcp_read_packet()::apdu_header(7)\r\n");

    rcvd_apdu->cla = buff[0];
    rcvd_apdu->ins = buff[1];
    rcvd_apdu->p1 = buff[2];
    rcvd_apdu->p2 = buff[3];
    // rcvd_apdu->lc = ((buff[5] << 8) | (buff[6]));
    uint8_t *lc = (uint8_t *)&(rcvd_apdu->lc);
    rcvd_apdu->lc = 0;
    memcpy(lc, buff + 4, 3);

    ipqp_ec = tcp_send_ack(&tcp_conf);
    IPQP_EC_CHECK(ipqp_ec, *ret_data, "[ERROR]: tcp_send_ack()\r\n");

    if (rcvd_apdu->lc > 0)
    {
        // receive apdu data
        rcvd_apdu->data = (uint8_t *)malloc(sizeof(uint8_t) * rcvd_apdu->lc);

        switch (rcvd_apdu->p1)
        {
        case APDU_CMD_P1_KEM_KEYPAIR:
        case APDU_CMD_P1_DSA_KEYPAIR:
        {
            // do nothing
            break;
        }

        case APDU_CMD_P1_KEM_ENCAP:
        {
            size_t pk_len = 0;
            switch (rcvd_apdu->ins)
            {
            case APDU_CMD_INS_ALGO_KYBER_512:
                pk_len = IPQP_KEM_kyber_512_length_public_key;
                break;
            case APDU_CMD_INS_ALGO_KYBER_768:
                pk_len = IPQP_KEM_kyber_768_length_public_key;
                break;
            case APDU_CMD_INS_ALGO_KYBER_1024:
                pk_len = IPQP_KEM_kyber_1024_length_public_key;
                break;
            default:
                IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_EC_ALGO_MISSING\r\n");
            }

            // read pk(pk_len)
            ipqp_ec = tcp_read_packet(&tcp_conf, rcvd_apdu->data, pk_len);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_read_packet()::pk(pk_len)\r\n");

            ipqp_ec = tcp_send_ack(&tcp_conf);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_send_ack()\r\n");

            break;
        }

        case APDU_CMD_P1_KEM_DECAP:
        {
            size_t sk_len = 0;
            size_t ct_len = 0;
            switch (rcvd_apdu->ins)
            {
            case APDU_CMD_INS_ALGO_KYBER_512:
                sk_len = IPQP_KEM_kyber_512_length_secret_key;
                ct_len = IPQP_KEM_kyber_512_length_ciphertext;
                break;
            case APDU_CMD_INS_ALGO_KYBER_768:
                sk_len = IPQP_KEM_kyber_768_length_secret_key;
                ct_len = IPQP_KEM_kyber_768_length_ciphertext;
                break;
            case APDU_CMD_INS_ALGO_KYBER_1024:
                sk_len = IPQP_KEM_kyber_1024_length_secret_key;
                ct_len = IPQP_KEM_kyber_1024_length_ciphertext;
                break;
            default:
                IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_EC_ALGO_MISSING\r\n");
            }

            // read ct(ct_len)
            ipqp_ec = tcp_read_packet(&tcp_conf, rcvd_apdu->data, ct_len);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_read_packet()::ct(ct_len)\r\n");

            ipqp_ec = tcp_send_ack(&tcp_conf);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_send_ack()\r\n");

            // read sk(sk_len)
            ipqp_ec = tcp_read_packet(&tcp_conf, rcvd_apdu->data + ct_len, sk_len);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_read_packet()::sk(sk_len)\r\n");

            ipqp_ec = tcp_send_ack(&tcp_conf);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_send_ack()\r\n");

            break;
        }

        case APDU_CMD_P1_DSA_SIGN:
        {
            // read msg_len_val(2)
            ipqp_ec = tcp_read_packet(&tcp_conf, rcvd_apdu->data, 2);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_read_packet()::msg_len_val(2)\r\n");

            uint16_t msg_len = *(&(rcvd_apdu->data[0]));
            printf("msg_len_val: %u\n", msg_len);

            ipqp_ec = tcp_send_ack(&tcp_conf);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_send_ack()\r\n");

            // read msg(msg_len_val)
            ipqp_ec = tcp_read_packet(&tcp_conf, rcvd_apdu->data + 2, (size_t)msg_len);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_read_packet()::msg(msg_len_val)\r\n");

            size_t sk_len = 0;
            switch (rcvd_apdu->ins)
            {
            case APDU_CMD_INS_ALGO_DILITHIUM_2:
                sk_len = IPQP_DSA_dilithium_2_length_secret_key;
                break;
            case APDU_CMD_INS_ALGO_DILITHIUM_3:
                sk_len = IPQP_DSA_dilithium_3_length_secret_key;
                break;
            case APDU_CMD_INS_ALGO_DILITHIUM_5:
                sk_len = IPQP_DSA_dilithium_5_length_secret_key;
                break;
            default:
                IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_EC_ALGO_MISSING\r\n");
            }

            ipqp_ec = tcp_send_ack(&tcp_conf);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_send_ack()\r\n");

            // read sk(sk_len)
            ipqp_ec = tcp_read_packet(&tcp_conf, rcvd_apdu->data + 2 + msg_len, sk_len);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_read_packet()::sk(sk_len)\r\n");

            ipqp_ec = tcp_send_ack(&tcp_conf);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_send_ack()\r\n");

            break;
        }

        case APDU_CMD_P1_DSA_VERIFY:
        {
            // read msg_len_val(2)
            ipqp_ec = tcp_read_packet(&tcp_conf, rcvd_apdu->data, 2);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_read_packet()::msg_len_val(2)\r\n");

            uint16_t msg_len = *((uint16_t *)rcvd_apdu->data);
            printf("msg_len_val: %u\n", msg_len);

            ipqp_ec = tcp_send_ack(&tcp_conf);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_send_ack()\r\n");

            // read msg(msg_len_val)
            ipqp_ec = tcp_read_packet(&tcp_conf, rcvd_apdu->data + 2, (size_t)msg_len);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_read_packet()::msg(msg_len_val)\r\n");

            size_t sm_len = 0;
            size_t pk_len = 0;
            switch (rcvd_apdu->ins)
            {
            case APDU_CMD_INS_ALGO_DILITHIUM_2:
                sm_len = IPQP_DSA_dilithium_2_length_signature;
                pk_len = IPQP_DSA_dilithium_2_length_public_key;
                break;
            case APDU_CMD_INS_ALGO_DILITHIUM_3:
                sm_len = IPQP_DSA_dilithium_3_length_signature;
                pk_len = IPQP_DSA_dilithium_3_length_public_key;
                break;
            case APDU_CMD_INS_ALGO_DILITHIUM_5:
                sm_len = IPQP_DSA_dilithium_5_length_signature;
                pk_len = IPQP_DSA_dilithium_5_length_public_key;
                break;
            default:
                IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_EC_ALGO_MISSING\r\n");
            }

            ipqp_ec = tcp_send_ack(&tcp_conf);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_send_ack()\r\n");

            // read sm(sm_len)
            ipqp_ec = tcp_read_packet(&tcp_conf, rcvd_apdu->data + 2 + msg_len, sm_len);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_read_packet()::sm(sm_len)\r\n");

            ipqp_ec = tcp_send_ack(&tcp_conf);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_send_ack()\r\n");

            // read pk(pk_len)
            ipqp_ec = tcp_read_packet(&tcp_conf, rcvd_apdu->data + 2 + msg_len + sm_len, pk_len);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_read_packet()::pk(pk_len)\r\n");

            ipqp_ec = tcp_send_ack(&tcp_conf);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_send_ack()\r\n");

            break;
        }

        default:
        {
            ipqp_ec = tcp_read_packet(&tcp_conf, rcvd_apdu->data, rcvd_apdu->lc);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_read_packet()\r\n");

            ipqp_ec = tcp_send_ack(&tcp_conf);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: tcp_send_ack()\r\n");
            break;
        }
        }
    }

    // read apdu footer (le)
    ipqp_ec = tcp_read_packet(&tcp_conf, buff, 3);
    IPQP_EC_CHECK(ipqp_ec, *ret_data, "[ERROR]: tcp_read_packet()::apdu_footer(3)\r\n");

    // rcvd_apdu->le = ((buff[1] << 8) | (buff[2]));
    uint8_t *le = (uint8_t *)&(rcvd_apdu->le);
    rcvd_apdu->le = 0;
    memcpy(le, buff, 3);

    if (rcvd_apdu->le > 0)
    {
        switch (rcvd_apdu->p1)
        {

        case APDU_CMD_P1_KEM_KEYPAIR:
        {
            size_t pk_len = 0;
            switch (rcvd_apdu->ins)
            {
            case APDU_CMD_INS_ALGO_KYBER_512:
                pk_len = IPQP_KEM_kyber_512_length_public_key;
                break;
            case APDU_CMD_INS_ALGO_KYBER_768:
                pk_len = IPQP_KEM_kyber_768_length_public_key;
                break;
            case APDU_CMD_INS_ALGO_KYBER_1024:
                pk_len = IPQP_KEM_kyber_1024_length_public_key;
                break;
            default:
                IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_EC_ALGO_MISSING\r\n");
            }

            (*ret_data) = (uint8_t *)malloc(sizeof(uint8_t) * rcvd_apdu->le);
            ipqp_ec = IPQP_kem_keypair(rcvd_apdu->ins, (uint8_t *)(*ret_data), (uint8_t *)((*ret_data) + pk_len));
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_kem_keypair()\r\n");

            break;
        }

        case APDU_CMD_P1_KEM_ENCAP:
        {
            uint16_t ss_len = 0;
            uint16_t ct_len = 0;
            switch (rcvd_apdu->ins)
            {
            case APDU_CMD_INS_ALGO_KYBER_512:
                ss_len = IPQP_KEM_kyber_512_length_shared_secret;
                ct_len = IPQP_KEM_kyber_512_length_ciphertext;
                break;
            case APDU_CMD_INS_ALGO_KYBER_768:
                ss_len = IPQP_KEM_kyber_768_length_shared_secret;
                ct_len = IPQP_KEM_kyber_768_length_ciphertext;
                break;
            case APDU_CMD_INS_ALGO_KYBER_1024:
                ss_len = IPQP_KEM_kyber_1024_length_shared_secret;
                ct_len = IPQP_KEM_kyber_1024_length_ciphertext;
                break;
            default:
                IPQP_EC_LOG(IPQP_EC_ALGO_MISSING, NULL);
                return IPQP_EC_ALGO_MISSING;
            }

            uint8_t *pk = rcvd_apdu->data;

            (*ret_data) = (uint8_t *)malloc(sizeof(uint8_t) * rcvd_apdu->le);
            uint8_t *ss = (*ret_data) + 2 + 2 + ct_len;
            uint8_t *ct = (*ret_data) + 2 + 2;

            ipqp_ec = IPQP_config(IPQP_PROV_LIBOQS);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_config()\r\n");

            ipqp_ec = IPQP_kem_encap(rcvd_apdu->ins, (uint8_t *)pk, (uint8_t *)ss, (uint8_t *)ct);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_kem_encap()\r\n");

            (*ret_data)[0] = ((uint8_t *)&ct_len)[0];
            (*ret_data)[1] = ((uint8_t *)&ct_len)[1];

            (*ret_data)[2] = ((uint8_t *)&ss_len)[0];
            (*ret_data)[3] = ((uint8_t *)&ss_len)[1];

            break;
        }

        case APDU_CMD_P1_KEM_DECAP:
        {
            uint16_t ss_len = 0;
            uint16_t ct_len = 0;
            switch (rcvd_apdu->ins)
            {
            case APDU_CMD_INS_ALGO_KYBER_512:
                ss_len = IPQP_KEM_kyber_512_length_shared_secret;
                ct_len = IPQP_KEM_kyber_512_length_ciphertext;
                break;
            case APDU_CMD_INS_ALGO_KYBER_768:
                ss_len = IPQP_KEM_kyber_768_length_shared_secret;
                ct_len = IPQP_KEM_kyber_768_length_ciphertext;
                break;
            case APDU_CMD_INS_ALGO_KYBER_1024:
                ss_len = IPQP_KEM_kyber_1024_length_shared_secret;
                ct_len = IPQP_KEM_kyber_1024_length_ciphertext;
                break;
            default:
                IPQP_EC_LOG(IPQP_EC_ALGO_MISSING, NULL);
                return IPQP_EC_ALGO_MISSING;
            }

            uint8_t *ct = rcvd_apdu->data;
            uint8_t *sk = rcvd_apdu->data + ct_len;

            (*ret_data) = (uint8_t *)malloc(sizeof(uint8_t) * rcvd_apdu->le);
            uint8_t *ss = (*ret_data) + 2;

            ipqp_ec = IPQP_config(IPQP_PROV_LIBOQS);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_config()\r\n");

            ipqp_ec = IPQP_kem_decap(rcvd_apdu->ins, (uint8_t *)sk, (uint8_t *)ct, (uint8_t *)ss);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_kem_decap()\r\n");

            (*ret_data)[0] = ((uint8_t *)&ss_len)[0];
            (*ret_data)[1] = ((uint8_t *)&ss_len)[1];

            break;
        }

        case APDU_CMD_P1_DSA_KEYPAIR:
        {
            size_t pk_len = 0;
            switch (rcvd_apdu->ins)
            {
            case APDU_CMD_INS_ALGO_DILITHIUM_2:
                pk_len = IPQP_DSA_dilithium_2_length_public_key;
                break;
            case APDU_CMD_INS_ALGO_DILITHIUM_3:
                pk_len = IPQP_DSA_dilithium_3_length_public_key;
                break;
            case APDU_CMD_INS_ALGO_DILITHIUM_5:
                pk_len = IPQP_DSA_dilithium_5_length_public_key;
                break;
            default:
                IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_EC_ALGO_MISSING\r\n");
            }

            (*ret_data) = (uint8_t *)malloc(sizeof(uint8_t) * rcvd_apdu->le);
            uint8_t *pk = (*ret_data);
            uint8_t *sk = (*ret_data) + pk_len;

            ipqp_ec = IPQP_config(IPQP_PROV_LIBOQS);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_config()\r\n");

            ipqp_ec = IPQP_dsa_keypair(rcvd_apdu->ins, (uint8_t *)pk, (uint8_t *)sk);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_dsa_keypair()\r\n");

            break;
        }

        case APDU_CMD_P1_DSA_SIGN:
        {
            size_t sm_len = 0;
            uint16_t msg_len = *(&(rcvd_apdu->data[0]));
            uint8_t *msg = rcvd_apdu->data + 2;
            uint8_t *sk = rcvd_apdu->data + 2 + msg_len;

            (*ret_data) = (uint8_t *)malloc(sizeof(uint8_t) * rcvd_apdu->le);
            uint8_t *sm = (*ret_data) + 2;

            ipqp_ec = IPQP_config(IPQP_PROV_LIBOQS);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_config()\r\n");

            ipqp_ec = IPQP_dsa_sign(rcvd_apdu->ins, (uint8_t *)sk, (uint8_t *)msg, (size_t)msg_len, (uint8_t *)sm, (size_t *)&sm_len);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_dsa_sign()\r\n");

            uint16_t sm_len_16 = (uint16_t)sm_len;
            (*ret_data)[0] = ((uint8_t *)&sm_len_16)[0];
            (*ret_data)[1] = ((uint8_t *)&sm_len_16)[1];

            break;
        }
        case APDU_CMD_P1_DSA_VERIFY:
        {
            size_t sm_len = 0;
            switch (rcvd_apdu->ins)
            {
            case APDU_CMD_INS_ALGO_DILITHIUM_2:
                sm_len = IPQP_DSA_dilithium_2_length_signature;
                break;
            case APDU_CMD_INS_ALGO_DILITHIUM_3:
                sm_len = IPQP_DSA_dilithium_3_length_signature;
                break;
            case APDU_CMD_INS_ALGO_DILITHIUM_5:
                sm_len = IPQP_DSA_dilithium_5_length_signature;
                break;
            default:
                IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_EC_ALGO_MISSING\r\n");
            }

            uint16_t msg_len = *(&(rcvd_apdu->data[0]));
            uint8_t *msg = rcvd_apdu->data + 2;
            uint8_t *sm = rcvd_apdu->data + 2 + msg_len;
            uint8_t *pk = rcvd_apdu->data + 2 + msg_len + sm_len;

            bool verified = false;

            ipqp_ec = IPQP_config(IPQP_PROV_LIBOQS);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_config()\r\n");

            ipqp_ec = IPQP_dsa_verify(rcvd_apdu->ins, (uint8_t *)pk, (uint8_t *)msg, (size_t)msg_len, (uint8_t *)sm, (size_t)sm_len, (bool *)&verified);
            IPQP_EC_CHECK(ipqp_ec, rcvd_apdu->data, "[ERROR]: IPQP_dsa_verify()\r\n");

            (*ret_data) = (uint8_t *)malloc(sizeof(uint8_t) * rcvd_apdu->le);
            if (verified)
            {
                memcpy((*ret_data), rcvd_apdu->data, rcvd_apdu->le);
            }
            else
            {
                for (int i = 0; i < rcvd_apdu->le; i++)
                    (*ret_data)[i] = 0xFF;
                memcpy((*ret_data), rcvd_apdu->data, 2);
            }

            break;
        }
        default:
        {

            if (rcvd_apdu->le > 0)
            {
                (*ret_data) = (uint8_t *)malloc(sizeof(uint8_t) * rcvd_apdu->le);

                for (int i = 0; i < rcvd_apdu->le; i++)
                    (*ret_data)[i] = 0xFF;

                (*ret_data)[0] = ((uint8_t *)&(rcvd_apdu->le))[0];
                (*ret_data)[1] = ((uint8_t *)&(rcvd_apdu->le))[1];
            }
            else
            {
                *ret_data = NULL;
            }
        }
        }
    }
    else
        *ret_data = NULL;

    return 0;
}
