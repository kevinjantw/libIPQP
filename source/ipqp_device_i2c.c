#include "ipqp_common.h"
#include "ipqp_device.h"
#include "ipqp_apdu.h"
#include "ipqp.h"

#include <linux/i2c-dev.h>

IPQP_ErrorCode i2c_open(i2c_conf_t *i2c_conf)
{
    i2c_conf->fd = open(i2c_conf->name, i2c_conf->open_flags);
    if (i2c_conf->fd < 0)
    {
        IPQP_EC_LOG(IPQP_EC_I2C_IO, "fail to open I2C interface.");
        return IPQP_EC_I2C_IO;
    }

    if (i2c_conf->ten_bits)
    {
        if (ioctl(i2c_conf->fd, I2C_TENBIT, 1) < 0)
        {
            close(i2c_conf->fd);
            IPQP_EC_LOG(IPQP_EC_I2C_IO, "fail to config I2C interface.");
            return IPQP_EC_I2C_IO;
        }

        if (ioctl(i2c_conf->fd, I2C_SLAVE, i2c_conf->slave_addr) < 0)
        {
            close(i2c_conf->fd);
            IPQP_EC_LOG(IPQP_EC_I2C_IO, "fail to config I2C interface.");
            return IPQP_EC_I2C_IO;
        }
    }
    else
    {
        if (ioctl(i2c_conf->fd, I2C_TENBIT, 0) < 0)
        {
            close(i2c_conf->fd);
            IPQP_EC_LOG(IPQP_EC_I2C_IO, "fail to config I2C interface.");
            return IPQP_EC_I2C_IO;
        }

        if (ioctl(i2c_conf->fd, I2C_SLAVE, (i2c_conf->slave_addr) >> 1) < 0)
        {
            close(i2c_conf->fd);
            IPQP_EC_LOG(IPQP_EC_I2C_IO, "fail to config I2C interface.");
            return IPQP_EC_I2C_IO;
        }
    }

    IPQP_EC_LOG(IPQP_EC_SUCCESS, "Opened I2C interface.");
    return IPQP_EC_SUCCESS;
}

IPQP_ErrorCode i2c_close(i2c_conf_t *i2c_conf)
{
    if (close(i2c_conf->fd) != 0)
    {
        IPQP_EC_LOG(IPQP_EC_I2C_IO, "fail to close I2C interface.");
        return IPQP_EC_I2C_IO;
    }

    IPQP_EC_LOG(IPQP_EC_SUCCESS, "Closed I2C interface.");
    return IPQP_EC_SUCCESS;
}

ssize_t i2c_read(i2c_conf_t *i2c_conf, uint8_t *buff, size_t max_buff_len)
{
    return read(i2c_conf->fd, buff, max_buff_len);
}

IPQP_ErrorCode i2c_read_packet(i2c_conf_t *i2c_conf, uint8_t *pkt_buff, size_t pkt_len)
{
    // int rcv_data_idx = 0;
    int rcv_pkt_len = 0;
    int max_round_to_read = 100;
    while ((rcv_pkt_len < pkt_len) && (max_round_to_read-- > 0))
    {
        uint8_t rcv_data[1024];
        int n = 100;
        int rcv_data_len = -1;
        while ((n-- > 0) && rcv_data_len < 0)
        {
            rcv_data_len = i2c_read(i2c_conf, rcv_data, 1024);
            usleep(5000);
        }

        if (rcv_data_len > 0)
        {
            memcpy(pkt_buff + rcv_pkt_len, rcv_data, rcv_data_len);
            rcv_pkt_len += rcv_data_len;
        }
    }

    if (max_round_to_read <= 0)
    {
        IPQP_EC_LOG(IPQP_EC_TIMEOUT, NULL);
        return IPQP_EC_TIMEOUT;
    }

    return IPQP_EC_SUCCESS;
}

ssize_t i2c_write(i2c_conf_t *i2c_conf, uint8_t *buff, size_t len_to_write)
{
    return write(i2c_conf->fd, buff, len_to_write);
}

IPQP_ErrorCode i2c_wait_for_ready(i2c_conf_t *i2c_conf)
{
    int max_retries = 500;
    uint8_t status[2] = {0x00, 0x00};
    bool to_stop = false;
    do
    {
        status[0] = 0x00;
        status[1] = 0x00;
        if (apdu_i2c_status_check(i2c_conf, status) < 0)
            return IPQP_EC_I2C_IO; // failed to check status

        if ((status[0] == 0x90) && (status[1] == 0x00))
            to_stop = true;
        else
            usleep(100000);

        if (max_retries <= 0)
        {
            IPQP_EC_LOG(IPQP_EC_TIMEOUT, NULL);
            return IPQP_EC_TIMEOUT;
        }

        max_retries--;
    } while (!to_stop);
    return IPQP_EC_SUCCESS;
}
