#include "ipqp_common.h"
#include "ipqp_device.h"
#include "ipqp_apdu.h"
#include "ipqp.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

int tcp_open(tcp_conf_t *tcp_conf)
{
    tcp_conf->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_conf->fd < 0)
    {
        PRINTF("Failed to create TPC socket.\r\n");
        return tcp_conf->fd;
    }

    struct timeval tv;
    tv.tv_sec = tcp_conf->timeout_sec;
    tv.tv_usec = 0;
    setsockopt(tcp_conf->fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

    struct sockaddr_in info;
    bzero(&info, sizeof(info));

    info.sin_family = PF_INET;
    info.sin_addr.s_addr = inet_addr(tcp_conf->ip);
    info.sin_port = htons(tcp_conf->port);

    int err = connect(tcp_conf->fd, (struct sockaddr *)&info, sizeof(info));
    if (err < 0)
    {
        PRINTF("Failed to connect to %s:%d\r\n", tcp_conf->ip, tcp_conf->port);
        return err;
    }

    return 0;
}

int tcp_close(tcp_conf_t *tcp_conf)
{
    return close(tcp_conf->fd);
}

ssize_t tcp_read(tcp_conf_t *tcp_conf, uint8_t *buff, size_t max_buff_len)
{
    return recv(tcp_conf->fd, buff, max_buff_len, 0);
}

IPQP_ErrorCode tcp_read_packet(tcp_conf_t *tcp_conf, uint8_t *pkt_buff, size_t pkt_len)
{
    size_t rcv_pkt_len = 0;
    int retries = 0;
    while ((rcv_pkt_len < pkt_len) && (retries < (tcp_conf->retries_on_failure)))
    {
        int rcv_data_len = tcp_read(tcp_conf, pkt_buff + rcv_pkt_len, pkt_len - rcv_pkt_len);
        if (rcv_data_len > 0)
        {
            // print_arr(pkt_buff + rcv_pkt_len, rcv_data_len, 32, "DATA");
            rcv_pkt_len += rcv_data_len;
            retries = 0;

            usleep(10000);
        }
        else
            retries++;
    }

    if (retries >= (tcp_conf->retries_on_failure))
        return IPQP_EC_TIMEOUT;

    return IPQP_EC_SUCCESS;
}

ssize_t tcp_write(tcp_conf_t *tcp_conf, uint8_t *buff, size_t len_to_write)
{
#if false
    int flag = 1;
    setsockopt(tcp_conf->fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

    ssize_t ret = send(tcp_conf->fd, buff, len_to_write, 0);

    flag = 0;
    setsockopt(tcp_conf->fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
#else
    ssize_t ret = send(tcp_conf->fd, buff, len_to_write, 0);
#endif

    return ret;
}

#ifndef IPQP_TCP_ACK
#define IPQP_TCP_ACK

#define IPQP_TCP_ACK_DATA {'I', 'P', 'Q', 'P'}
#define IPQP_TCP_ACK_DATA_LEN 4

#endif

IPQP_ErrorCode tcp_send_ack(tcp_conf_t *tcp_conf)
{
    uint8_t ack_data[IPQP_TCP_ACK_DATA_LEN] = IPQP_TCP_ACK_DATA;
    ssize_t snd_size = tcp_write(tcp_conf, ack_data, IPQP_TCP_ACK_DATA_LEN);
    if (snd_size != IPQP_TCP_ACK_DATA_LEN)
        return IPQP_EC_TCP_IO;

    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode tcp_receive_ack(tcp_conf_t *tcp_conf)
{
    uint8_t ack_data[IPQP_TCP_ACK_DATA_LEN] = IPQP_TCP_ACK_DATA;
    uint8_t rcv_ack_data[IPQP_TCP_ACK_DATA_LEN];
    memset(rcv_ack_data, 0x00, IPQP_TCP_ACK_DATA_LEN);

    IPQP_ErrorCode ret = tcp_read_packet(tcp_conf, rcv_ack_data, IPQP_TCP_ACK_DATA_LEN);

    if (memcmp(ack_data, rcv_ack_data, IPQP_TCP_ACK_DATA_LEN) == 0)
        return IPQP_EC_SUCCESS;

    if (ret == IPQP_EC_SUCCESS)
        return IPQP_EC_FAIL;
    else
        return ret;
}