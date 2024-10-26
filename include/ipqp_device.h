#ifndef __IPQP_DEVICE_H__
#define __IPQP_DEVICE_H__

#include "ipqp_common.h"
#include "ipqp.h"

// include ipqp_dev_conf.h if the file exists
#if __has_include("ipqp_dev_conf.h")
#include "ipqp_dev_conf.h"
#endif

/**
 * @brief Checks if the received data buffer contains a valid packet.
 *
 * This function analyzes the received data buffer to determine if it contains a valid packet.
 * The specific validation logic is not provided in the given code snippet, so this function assumes
 * a basic validation based on the existence of a valid packet header.
 *
 * @param rcv_buff A pointer to the buffer containing the received data.
 *
 * @return A boolean value indicating the validity of the received packet.
 * - true: The received data buffer contains a valid packet.
 * - false: The received data buffer does not contain a valid packet.
 */
bool received_valid_packet(uint8_t *rcv_buff);

//----------------------------------------------------------------
/* SPI */
#ifndef SPI_LSB_FIRST
#define SPI_LSB_FIRST 0
#endif

#ifndef IPQP_DEVICE_CONFIGURATION
#define SPI_DEV_ENABLED true
#define SPI_DEV_NAME "/dev/spidev0.1"
#define SPI_MODE 0
#define SPI_BITS_PER_WORD 8
#define SPI_MAX_SPEED_HZ 1000000
#define SPI_BUFFER_SIZE 2048
#define SPI_PACKET_DATA_SIZE 1024
#endif

typedef struct
{
	int fd;
	uint8_t mode;
	uint8_t bits_per_word;
	uint32_t speed;
	uint8_t lsb;
	char *name;
} spi_conf_t;

/**
 * @brief Opens a SPI device and initializes its configuration.
 *
 * This function opens a SPI device specified by the provided configuration structure.
 * It sets the device's mode, bits per word, speed, and other parameters.
 *
 * @param spi_conf A pointer to the SPI configuration structure.
 * The structure should contain the following fields:
 * - mode: The SPI mode (0, 1, 2, or 3).
 * - bits_per_word: The number of bits per word (e.g., 8).
 * - speed: The maximum speed in Hz (e.g., 1000000).
 * - lsb: A flag indicating whether to use LSB first (SPI_LSB_FIRST).
 * - name: The name of the SPI device (e.g., "/dev/spidev0.1").
 *
 * @return An integer representing the result of the operation.
 * - 0: The SPI device was successfully opened.
 * - -1: An error occurred while opening the SPI device.
 */
int spi_open(spi_conf_t *spi_conf);

/**
 * @brief Closes the SPI device and releases any associated resources.
 *
 * This function closes the SPI device specified by the provided configuration structure.
 * It also flushes any pending input and output data, and releases the file descriptor.
 *
 * @param spi_conf A pointer to the SPI configuration structure.
 * The structure should contain the following fields:
 * - fd: The file descriptor of the SPI device.
 * - mode: The SPI mode (0, 1, 2, or 3).
 * - bits_per_word: The number of bits per word (e.g., 8).
 * - speed: The maximum speed in Hz (e.g., 1000000).
 * - lsb: A flag indicating whether to use LSB first (SPI_LSB_FIRST).
 * - name: The name of the SPI device (e.g., "/dev/spidev0.1").
 *
 * @return An integer representing the result of the operation.
 * - 0: The SPI device was successfully closed.
 * - -1: An error occurred while closing the SPI device.
 */
int spi_close(spi_conf_t *spi_conf);

/**
 * @brief Transmits and receives data over the SPI interface.
 *
 * This function sends the specified number of bytes from the 'tx' buffer to the SPI device,
 * and simultaneously reads the same number of bytes into the 'rx' buffer.
 *
 * @param spi_conf A pointer to the SPI configuration structure.
 * The structure should contain the following fields:
 * - fd: The file descriptor of the SPI device.
 * - mode: The SPI mode (0, 1, 2, or 3).
 * - bits_per_word: The number of bits per word (e.g., 8).
 * - speed: The maximum speed in Hz (e.g., 1000000).
 * - lsb: A flag indicating whether to use LSB first (SPI_LSB_FIRST).
 * - name: The name of the SPI device (e.g., "/dev/spidev0.1").
 *
 * @param tx A pointer to the buffer containing the data to be transmitted.
 * @param rx A pointer to the buffer where the received data will be stored.
 * @param len The number of bytes to transmit and receive.
 *
 * @return An integer representing the result of the operation.
 * - 0: The data was successfully transmitted and received.
 * - -1: An error occurred while transmitting or receiving data.
 */
int spi_data_snd_rcv(spi_conf_t *spi_conf, uint8_t *tx, uint8_t *rx, size_t len);

/**
 * @brief Waits for the SPI device to become ready for communication.
 *
 * This function continuously sends a checking command to the SPI device and checks the response.
 * It waits until the device is ready to accept new data.
 *
 * @param spi_conf A pointer to the SPI configuration structure.
 * The structure should contain the following fields:
 * - fd: The file descriptor of the SPI device.
 * - mode: The SPI mode (0, 1, 2, or 3).
 * - bits_per_word: The number of bits per word (e.g., 8).
 * - speed: The maximum speed in Hz (e.g., 1000000).
 * - lsb: A flag indicating whether to use LSB first (SPI_LSB_FIRST).
 * - name: The name of the SPI device (e.g., "/dev/spidev0.1").
 *
 * @return An integer representing the result of the operation.
 * - 0: The SPI device is ready for communication.
 * - -1: An error occurred while waiting for the device to become ready.
 */
int spi_wait_for_ready(spi_conf_t *spi_conf);

//----------------------------------------------------------------
/* UART */
#ifndef DEFAULT_UART_CONFIG
#define DEFAULT_UART_CONFIG 0x00000000
#endif

#ifndef IPQP_DEVICE_CONFIGURATION
#define UART_DEV_ENABLED true
#define UART_DEV_NAME "/dev/ttyAMA0"
#define UART_OPEN_FLAGS (O_RDWR | O_NDELAY | O_NOCTTY)
#define UART_INPUT_MODE_FLAGS (IGNPAR)
#define UART_OUTPUT_MODE_FLAGS DEFAULT_UART_CONFIG
#define UART_CONTROL_MODE_FLAGS (B115200 | CS8 | CLOCAL | CREAD)
#define UART_LOCAL_MODE_FLAGS DEFAULT_UART_CONFIG
#define UART_BUFFER_SIZE 2048
#define UART_PACKET_DATA_SIZE 1024
#endif

typedef struct
{
	int fd;						 // file handle for uart iface
	char *name;					 // uart interface name
	int open_flags;				 // open flags
	tcflag_t input_mode_flags;	 // input modes
	tcflag_t output_mode_flags;	 // output modes
	tcflag_t control_mode_flags; // control modes
	tcflag_t local_mode_flags;	 // local modes
} uart_conf_t;

/**
 * @brief Opens a UART device and initializes its configuration.
 *
 * This function opens a UART device specified by the provided configuration structure.
 * It sets the device's open flags, input modes, output modes, control modes, and local modes.
 *
 * @param uart_conf A pointer to the UART configuration structure.
 *
 * @return An integer representing the result of the operation.
 * - 0: The UART device was successfully opened.
 * - -1: An error occurred while opening the UART device.
 */
int uart_open(uart_conf_t *uart_conf);

/**
 * @brief Closes the UART device and releases any associated resources.
 *
 * This function closes the UART device specified by the provided configuration structure.
 * It also flushes any pending input and output data, and releases the file descriptor.
 *
 * @param uart_conf A pointer to the UART configuration structure.
 *
 * @return An integer representing the result of the operation.
 * - 0: The UART device was successfully closed.
 * - -1: An error occurred while closing the UART device.
 */
int uart_close(uart_conf_t *uart_conf);

/**
 * @brief Writes data to the UART device.
 *
 * This function writes the specified number of bytes from the provided buffer to the UART device.
 * It uses the file descriptor obtained from the UART configuration structure to perform the write operation.
 *
 * @param uart_conf A pointer to the UART configuration structure.
 * @param buff A pointer to the buffer containing the data to be written.
 * @param len_to_write The number of bytes to write from the buffer.
 *
 * @return The number of bytes actually written to the UART device.
 * - On success, the function returns the number of bytes written.
 * - On error, it returns -1 and sets the appropriate errno value.
 *   - EBADF: The file descriptor is not a valid file descriptor.
 *   - EFAULT: The buffer pointer points to an invalid memory area.
 *   - EINTR: The function was interrupted by a signal.
 *   - EIO: An I/O error occurred while writing to the device.
 *   - ENOSPC: The device's write queue is full.
 */
ssize_t uart_write(uart_conf_t *uart_conf, uint8_t *buff, size_t len_to_write);

/**
 * @brief Reads data from the UART device.
 *
 * This function reads up to the specified number of bytes from the UART device into the provided buffer.
 * It uses the file descriptor obtained from the UART configuration structure to perform the read operation.
 *
 * @param uart_conf A pointer to the UART configuration structure.
 * @param buff A pointer to the buffer where the read data will be stored.
 * @param max_buff_len The maximum number of bytes to read into the buffer.
 *
 * @return The number of bytes actually read from the UART device.
 * - On success, the function returns the number of bytes read.
 * - On error, it returns -1 and sets the appropriate errno value.
 *   - EBADF: The file descriptor is not a valid file descriptor.
 *   - EFAULT: The buffer pointer points to an invalid memory area.
 *   - EINTR: The function was interrupted by a signal.
 *   - EIO: An I/O error occurred while reading from the device.
 *   - ENOSPC: The device's read queue is empty.
 */
ssize_t uart_read(uart_conf_t *uart_conf, uint8_t *buff, size_t max_buff_len);

/**
 * @brief Reads a complete packet of data from the UART device.
 *
 * This function reads a specified number of bytes from the UART device into the provided buffer.
 * It continuously reads data until a complete packet is received or an error occurs.
 *
 * @param uart_conf A pointer to the UART configuration structure.
 * @param pkt_buff A pointer to the buffer where the read data will be stored.
 * @param pkt_len The number of bytes to read into the buffer to form a complete packet.
 *
 * @return An IPQP_ErrorCode representing the result of the operation.
 * - IPQP_EC_SUCCESS: The complete packet was successfully read.
 * - IPQP_EC_UART_IO: An I/O error occurred while reading from the device.
 * - IPQP_EC_TIMEOUT: The complete packet was not received within the specified timeout.
 * - IPQP_EC_NULL_POINTER: The provided parameters are invalid.
 */
IPQP_ErrorCode uart_read_packet(uart_conf_t *uart_conf, uint8_t *pkt_buff, size_t pkt_len);

/**
 * @brief Waits for the UART device to become ready for communication.
 *
 * This function continuously sends a checking command to the UART device and checks the response.
 * It waits until the device is ready to accept new data.
 *
 * @param uart_conf A pointer to the UART configuration structure.
 * The structure should contain the following fields:
 * - fd: The file descriptor of the UART device.
 * - name: The UART device name.
 * - open_flags: Open flags for the UART device.
 * - input_mode_flags: Input modes for the UART device.
 * - output_mode_flags: Output modes for the UART device.
 * - control_mode_flags: Control modes for the UART device.
 * - local_mode_flags: Local modes for the UART device.
 *
 * @return An IPQP_ErrorCode representing the result of the operation.
 * - IPQP_EC_SUCCESS: The UART device is ready for communication.
 * - IPQP_EC_UART_IO: An I/O error occurred while waiting for the device to become ready.
 * - IPQP_EC_TIMEOUT: The device did not become ready within the specified timeout.
 * - IPQP_EC_NULL_POINTER: The provided parameters are invalid.
 */
IPQP_ErrorCode uart_wait_for_ready(uart_conf_t *uart_conf);

/**
 * @brief Clears the receive buffer of the UART device.
 *
 * This function reads and discards all the data currently present in the receive buffer of the UART device.
 * It is useful when the receive buffer contains stale or unexpected data, and it is necessary to clear it before
 * starting a new communication session.
 *
 * @param uart_conf A pointer to the UART configuration structure.
 * The structure should contain the following fields:
 * - fd: The file descriptor of the UART device.
 * - name: The UART device name.
 * - open_flags: Open flags for the UART device.
 * - input_mode_flags: Input modes for the UART device.
 * - output_mode_flags: Output modes for the UART device.
 * - control_mode_flags: Control modes for the UART device.
 * - local_mode_flags: Local modes for the UART device.
 *
 * @return void
 * This function does not return any value.
 */
void uart_clear_rcv_buffer(uart_conf_t *uart_conf);

//----------------------------------------------------------------
/* I2C */
#ifndef IPQP_DEVICE_CONFIGURATION
#define I2C_DEV_ENABLED true
#define I2C_DEV_NAME "/dev/i2c-0"
#define I2C_OPEN_FLAGS (O_RDWR)
#define I2C_SLAVE_ADDRESS 0x56
#define I2C_TENBITS_ADDR false
#define I2C_BUFFER_SIZE 1536
#define I2C_PACKET_DATA_SIZE 512
#endif

typedef struct
{
	int fd;				 // file handle for i2c iface
	char *name;			 // uart interface name
	int open_flags;		 // open flags
	bool ten_bits;		 // use 10-bits address
	uint16_t slave_addr; // i2c slave address
} i2c_conf_t;

IPQP_ErrorCode i2c_open(i2c_conf_t *i2c_conf);
IPQP_ErrorCode i2c_close(i2c_conf_t *i2c_conf);
ssize_t i2c_write(i2c_conf_t *i2c_conf, uint8_t *buff, size_t len_to_write);
ssize_t i2c_read(i2c_conf_t *i2c_conf, uint8_t *buff, size_t max_buff_len);
IPQP_ErrorCode i2c_read_packet(i2c_conf_t *i2c_conf, uint8_t *pkt_buff, size_t pkt_len);
IPQP_ErrorCode i2c_wait_for_ready(i2c_conf_t *i2c_conf);

//----------------------------------------------------------------
/* TCP */
#ifndef IPQP_DEVICE_CONFIGURATION
#define TCP_DEV_ENABLED true
#define TCP_DEV_IP "127.0.0.1"
#define TCP_DEV_PORT 5566
#define TCP_TIMEOUT_SEC 10
#define TCP_RETRIES_ON_FAILURE 100
#define TCP_BUFFER_SIZE 10240
#endif

typedef struct
{
	int fd;						 // file handle for i2c iface
	char *ip;					 // tcp server ip
	uint16_t port;				 // tcp server port
	uint32_t timeout_sec;		 // timeout in second
	uint32_t retries_on_failure; // timeout in second
} tcp_conf_t;

int tcp_open(tcp_conf_t *tcp_conf);
int tcp_close(tcp_conf_t *tcp_conf);
ssize_t tcp_read(tcp_conf_t *tcp_conf, uint8_t *buff, size_t max_buff_len);
IPQP_ErrorCode tcp_read_packet(tcp_conf_t *tcp_conf, uint8_t *pkt_buff, size_t pkt_len);
ssize_t tcp_write(tcp_conf_t *tcp_conf, uint8_t *buff, size_t len_to_write);
IPQP_ErrorCode tcp_send_ack(tcp_conf_t *tcp_conf);
IPQP_ErrorCode tcp_receive_ack(tcp_conf_t *tcp_conf);
#endif /* __IPQP_DEVICE_H__ */
