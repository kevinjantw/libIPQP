#include "ipqp_common.h"
#include "ipqp_device.h"
#include "ipqp_apdu.h"
#include "ipqp.h"

#include <linux/spi/spidev.h>

int spi_open(spi_conf_t *spi_conf)
{
    if (spi_conf->fd >= 0)
        return -1;

    spi_conf->fd = open(spi_conf->name, O_RDWR);
    if (spi_conf->fd < 0)
    {
        PRINTF("can't open %s\n", spi_conf->name);
        return -1;
    }

    if (ioctl(spi_conf->fd, SPI_IOC_WR_MODE, &(spi_conf->mode)) < 0)
    {
        PRINTF("can't set spi mode\n");
        close(spi_conf->fd);
        return -1;
    }

    if (ioctl(spi_conf->fd, SPI_IOC_RD_MODE, &(spi_conf->mode)) < 0)
    {
        PRINTF("can't get spi mode\n");
        close(spi_conf->fd);
        return -1;
    }

    if (ioctl(spi_conf->fd, SPI_IOC_WR_BITS_PER_WORD, &(spi_conf->bits_per_word)) < 0)
    {
        PRINTF("can't set bits per word\n");
        close(spi_conf->fd);
        return -1;
    }

    if (ioctl(spi_conf->fd, SPI_IOC_RD_BITS_PER_WORD, &(spi_conf->bits_per_word)) < 0)
    {
        PRINTF("can't get bits per word\n");
        close(spi_conf->fd);
        return -1;
    }

    if (ioctl(spi_conf->fd, SPI_IOC_WR_MAX_SPEED_HZ, &(spi_conf->speed)) < 0)
    {
        PRINTF("can't set max speed hz\n");
        close(spi_conf->fd);
        return -1;
    }

    if (ioctl(spi_conf->fd, SPI_IOC_RD_MAX_SPEED_HZ, &(spi_conf->speed)) < 0)
    {
        PRINTF("can't get max speed hz\n");
        close(spi_conf->fd);
        return -1;
    }

    if (ioctl(spi_conf->fd, SPI_IOC_RD_LSB_FIRST, &(spi_conf->lsb)) < 0)
    {
        PRINTF("mspi get lsb first failed!\n");
        close(spi_conf->fd);
        return -1;
    }

    PRINTF("spi iface %s opened\r\n", spi_conf->name);
    PRINTF("mspi mode: %d\n", spi_conf->mode);
    PRINTF("mspi bits per word: %d\n", spi_conf->bits_per_word);
    PRINTF("mspi speed: %d Hz\n", spi_conf->speed);
    PRINTF("mspi transmit is lsb first: %d\n", spi_conf->lsb);

    return 0;
}

int spi_close(spi_conf_t *spi_conf)
{
    if (spi_conf->fd < 0)
    {
        PRINTF("interface not opened.\r\n");
        return -1;
    }

    close(spi_conf->fd);
    spi_conf->fd = -1;

    PRINTF("closed spi iface %s\n", spi_conf->name);

    return 0;
}

int spi_data_snd_rcv(spi_conf_t *spi_conf, uint8_t *tx, uint8_t *rx, size_t len)
{
    struct spi_ioc_transfer tr = {
        .tx_buf = (unsigned long)tx,
        .rx_buf = (unsigned long)rx,
        .len = len,
        .delay_usecs = 0,
        .speed_hz = spi_conf->speed,
        .bits_per_word = spi_conf->bits_per_word,
    };

    if (spi_conf->mode & SPI_TX_QUAD)
        tr.tx_nbits = 4;
    else if (spi_conf->mode & SPI_TX_DUAL)
        tr.tx_nbits = 2;
    if (spi_conf->mode & SPI_RX_QUAD)
        tr.rx_nbits = 4;
    else if (spi_conf->mode & SPI_RX_DUAL)
        tr.rx_nbits = 2;
    if (!(spi_conf->mode & SPI_LOOP))
    {
        if (spi_conf->mode & (SPI_TX_QUAD | SPI_TX_DUAL))
            tr.rx_buf = 0;
        else if (spi_conf->mode & (SPI_RX_QUAD | SPI_RX_DUAL))
            tr.tx_buf = 0;
    }

    return ioctl(spi_conf->fd, SPI_IOC_MESSAGE(1), &tr);
}

int spi_wait_for_ready(spi_conf_t *spi_conf)
{
    if (spi_conf == NULL)
        return IPQP_EC_NULL_POINTER;

    int max_retries = 500;
    uint8_t status[2] = {0x00, 0x00};
    bool to_stop = false;
    do
    {
        status[0] = 0x00;
        status[1] = 0x00;
        if (apdu_spi_status_check(spi_conf, status) < 0)
            return IPQP_EC_SPI_IO; // failed to check status

        if ((status[0] == 0x90) && (status[1] == 0x00))
            to_stop = true;
        else
            usleep(100000);

        if (max_retries <= 0)
            return IPQP_EC_TIMEOUT;
        max_retries--;
    } while (!to_stop);
    return IPQP_EC_SUCCESS; // spi ready
}
